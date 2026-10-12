"""T1 command: authenticate release assets, run owned foreground journey, retain fixed receipt."""

import argparse
import hashlib
import io
import json
import math
import os
import platform
import re
import sys
import tarfile
import time
from pathlib import Path
from typing import Any, BinaryIO

from guard_harness.release_state import validate_build
from guard_harness.runner import run
from guard_harness.staged_subjects import _private
from guard_harness.testnet_process import ENTRY_REMAINING, Foreground, ProcessError
from guard_harness.testnet_scan import SCAN_TIMEOUT, TestnetReads

ROOT = Path(__file__).resolve().parents[3]
REPOSITORY = "zunderlabs/zunder-guard"


def _read(path: Path, limit: int) -> bytes:
    _private(path)
    if not 0 < path.stat().st_size <= limit:
        raise ProcessError("release metadata size refused")
    with path.open("rb") as stream:
        captured = stream.read(limit + 1)
    if not 0 < len(captured) <= limit:
        raise ProcessError("release metadata size refused")
    return captured


def _receipt(work: Path, receipt: dict[str, object]) -> None:
    pending = work / "receipt.pending"
    with pending.open("w") as stream:
        pending.chmod(0o600)
        stream.write(json.dumps(receipt, indent=2) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    pending.replace(work / "receipt.json")


def verified_asset(assets: Path, name: str, *, tag: str, commit: str) -> tuple[bytes, str]:
    """Called only after the real asset verifier succeeds in this invocation's fresh directory."""
    marker = json.loads(_read(assets / ".verified-release-source.json", 256))
    if marker != {"tag": tag, "source": commit}:
        raise ProcessError("authenticated release source differs")
    entries: dict[str, str] = {}
    for line in _read(assets / "SHA256SUMS", 65536).decode().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64}) [ *]([A-Za-z0-9][A-Za-z0-9._-]*)", line)
        if match is None or ".." in match[2] or match[2] in entries:
            raise ProcessError("signed checksum inventory refused")
        entries[match[2]] = match[1]
    captured = _read(assets / "release-manifest.json", 65536)
    build = json.loads(captured)
    validate_build(build, ROOT / "release/manifest.schema.json", expected_commit=commit)
    if (
        build["tag"] != tag
        or entries.get("release-manifest.json") != hashlib.sha256(captured).hexdigest()
        or name not in entries
        or build["assets"].get(name, {}).get("sha256") != entries[name]
    ):
        raise ProcessError("C2 build/checksum/archive binding differs")
    subject = assets / name
    captured_subject = _read(subject, 128 * 1024 * 1024)
    if hashlib.sha256(captured_subject).hexdigest() != entries[name]:
        raise ProcessError("release subject changed after verification")
    return captured_subject, hashlib.sha256(captured).hexdigest()


def signed_binary(assets: Path, output: Path, *, tag: str, commit: str) -> tuple[str, str]:
    machine = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    if platform.system() != "Linux" or machine is None:
        raise ProcessError("T1 requires a Linux release archive")
    captured_archive, manifest_digest = verified_asset(
        assets, f"zunder-guard-{tag}-linux-{machine}.tar.gz", tag=tag, commit=commit
    )
    allowed = {
        "zunder-guard",
        "README.md",
        "LICENSE",
        "NOTICE",
        "THIRD_PARTY_LICENSES.md",
        "zunder-guard.service",
    }
    seen: set[str] = set()
    binary = b""
    total = 0
    with tarfile.open(fileobj=io.BytesIO(captured_archive), mode="r:gz") as source:
        for member in source:
            total += member.size
            if (
                member.name not in allowed
                or member.name in seen
                or not member.isfile()
                or not 0 <= member.size <= 128 * 1024 * 1024
                or total > 256 * 1024 * 1024
            ):
                raise ProcessError("release archive member refused")
            seen.add(member.name)
            if member.name == "zunder-guard":
                stream = source.extractfile(member)
                if stream is None or member.size == 0:
                    raise ProcessError("release archive binary missing")
                with stream:
                    binary = stream.read(128 * 1024 * 1024 + 1)
                if len(binary) != member.size:
                    raise ProcessError("release archive binary truncated")
    if not binary:
        raise ProcessError("release archive binary missing")
    with output.open("xb") as stream:
        output.chmod(0o600)
        stream.write(binary)
    return hashlib.sha256(binary).hexdigest(), manifest_digest


def execute_release(
    *,
    tag: str,
    commit: str,
    account: str,
    api_wallet: str,
    work: Path,
    port: int,
    deadline: float,
    key_stdin: BinaryIO,
    service_marker: str | None = None,
    builder_approval: Path | None = None,
) -> int:
    """Calling reusable workflow owns global C6 serialization and the actual job deadline."""
    if (
        not re.fullmatch(r"v\d+\.\d+\.\d+(?:-rc\.[1-9]\d*)?", tag)
        or not re.fullmatch(r"[0-9a-f]{40}", commit)
        or not re.fullmatch(r"0x[0-9a-fA-F]{40}", account)
        or not re.fullmatch(r"0x[0-9a-fA-F]{40}", api_wallet)
        or not 1024 <= port <= 65535
        or not math.isfinite(deadline)
        or deadline - time.monotonic() < SCAN_TIMEOUT + ENTRY_REMAINING
    ):
        raise ProcessError("explicit release and testnet identity required")
    _private(work.parent, directory=True)
    if work.exists() or work.is_symlink() or not work.is_absolute():
        raise ProcessError("fresh private journey workspace required")
    work.mkdir(mode=0o700)
    row = "T2" if service_marker is not None else "T1"
    receipt: dict[str, object] = {
        "journey": row,
        "tag": tag,
        "commit": commit,
        "account_sha256": hashlib.sha256(account.lower().encode()).hexdigest(),
        "result": "failed",
        "release_ready": False,
        "stage": "authenticate",
    }
    old_mask = os.umask(0o077)
    try:
        _receipt(work, receipt)
        env = {
            name: os.environ[name]
            for name in ("PATH", "HOME", "GH_TOKEN", "GITHUB_TOKEN")
            if name in os.environ
        }
        env["GITHUB_REPOSITORY"] = REPOSITORY
        # A saved marker or caller assertion never bypasses signature/provenance/source CI.
        run(
            ["bash", str(ROOT / "github/verify-release-assets.sh"), tag, str(work / "assets")],
            env=env,
            log=work / "assets.log",
            timeout=600,
            secrets=[env.get("GH_TOKEN", ""), env.get("GITHUB_TOKEN", "")],
            stdin=b"",
        )
        digest, manifest_digest = signed_binary(
            work / "assets", work / "subject", tag=tag, commit=commit
        )
        if deadline - time.monotonic() < SCAN_TIMEOUT + ENTRY_REMAINING:
            raise ProcessError("complete scan and cleanup budget expired before custody")
        receipt.update(binary_sha256=digest, manifest_sha256=manifest_digest, stage="foreground")
        _receipt(work, receipt)
        if service_marker is None:
            owner = Foreground(
                work / "subject",
                sha256=digest,
                work=work / "runtime",
                account=account,
                api_wallet=api_wallet,
                port=port,
                key_stdin=key_stdin,
            )
        else:
            from guard_harness.testnet_service_owner import ServiceOwner

            owner = ServiceOwner(
                work / "subject",
                sha256=digest,
                work=work / "runtime",
                account=account,
                api_wallet=api_wallet,
                port=port,
                key_stdin=key_stdin,
                assets=work / "assets",
                tag=tag,
                commit=commit,
                marker=service_marker,
            )
        receipt["stage"] = "journey"
        _receipt(work, receipt)
        reads = TestnetReads()
        captured: dict[str, Any] = {}

        def capture_entry(observed: object, begun: int, ended: int) -> None:
            if builder_approval is None:
                return
            from guard_harness.testnet_process import OwnedLocalGuard
            from guard_harness.testnet_protection import _orders

            captured.update(
                events=_orders(OwnedLocalGuard(owner).request("/guard/events?since=0")),
                fills=_orders(
                    reads({"type": "userFillsByTime", "user": account, "startTime": begun})
                ),
                started_ms=begun,
                ended_ms=ended,
            )

        # Raw account events/fills stay in memory and never enter artifact uploads.
        if builder_approval is None:
            result = owner.journey(reads, version=tag[1:], deadline=deadline)
        else:
            result = owner.journey(
                reads, version=tag[1:], deadline=deadline, capture_entry=capture_entry
            )
        receipt.update(
            result="passed" if result.passed else "failed",
            failure=result.failure,
            guard_stopped=result.guard_stopped,
            cleanup_complete=result.cleaned is not None,
        )
        if result.protected_entry is not None:
            observed = result.protected_entry
            receipt["protected_entry"] = {
                "entry_oid": observed.entry_oid,
                "stop_oid": observed.stop_oid,
                "filled": str(observed.filled),
                "remaining": str(observed.remaining),
                "resting_entry": observed.resting_entry,
            }
        if result.cleaned is not None:
            receipt["cleanup"] = {
                "actions": result.cleaned.actions,
                "scan": result.cleaned.flat_scan,
            }
        if result.passed:
            if builder_approval is not None:
                from guard_harness.builder_journey import correlate_fee, produce_descriptor

                descriptor = produce_descriptor(
                    work / "assets",
                    work / "builder-subject",
                    account=account,
                    tag=tag,
                    commit=commit,
                )
                proof = correlate_fee(
                    json.loads(descriptor.read_bytes()),
                    json.loads(_read(builder_approval, 65536)),
                    receipt,
                    client=owner.pair.address.lower(),
                    **captured,
                )
                with (work / "P8.fee-proof.json").open("x") as stream:
                    stream.write(json.dumps(proof) + "\n")
                with (work / "P8.predicate.json").open("x") as stream:
                    stream.write(
                        json.dumps(
                            {
                                "schema": 1,
                                "journey": "P8",
                                "commit": commit,
                                "manifest_sha256": manifest_digest,
                                "result": "passed",
                                "tier": "e2e",
                                "coverage": [
                                    "signed-release",
                                    "protected-entry",
                                    "staging-approve",
                                    "testnet-owner-approval",
                                    "guard-builder-wire",
                                    "actual-builder-fee",
                                    "owned-cleanup",
                                    "all-dex-flat",
                                ],
                            }
                        )
                        + "\n"
                    )
            predicate = {
                "schema": 1,
                "journey": row,
                "commit": commit,
                "manifest_sha256": manifest_digest,
                "result": "passed",
                "tier": "e2e",
                "coverage": ["signed-release", "protected-entry", "owned-cleanup", "all-dex-flat"],
            }
            with (work / f"{row}.predicate.json").open("x") as stream:
                stream.write(json.dumps(predicate) + "\n")
        return 0 if result.passed else 1
    except (Exception, KeyboardInterrupt):
        receipt["result"] = "failed"
        receipt["failure"] = "journey_incomplete_keep_protection"
        return 1
    finally:
        # Never include exceptions, command bodies, pairing/client keys or wallet input.
        try:
            _receipt(work, receipt)
        finally:
            os.umask(old_mask)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("tag", "commit", "account", "api-wallet"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--port", type=int, default=18547)
    parser.add_argument("--service-marker")
    parser.add_argument("--builder-approval", type=Path)
    parser.add_argument(
        "--deadline",
        type=float,
        required=True,
        help="monotonic deadline from the calling job's actual start and timeout",
    )
    args = parser.parse_args()
    try:
        return execute_release(**vars(args), key_stdin=sys.stdin.buffer)
    except (Exception, KeyboardInterrupt):
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
