"""Fresh canonical D1–D4 installs and real signed paper decisions; never a venue key."""

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
from pathlib import Path

from guard_harness.attestation import AttestationError
from guard_harness.canonical_readback import check
from guard_harness.cli import GuardCLI
from guard_harness.docker_paper import lifecycle
from guard_harness.gate_state import bundles
from guard_harness.journey_evidence import authenticate_gate
from guard_harness.native_paper import healthy
from guard_harness.native_release import Release
from guard_harness.paper_bot import LocalGuard
from guard_harness.paper_roundtrip import round_trip
from guard_harness.promotion_channels import IMAGE, image_digest, public_get
from guard_harness.promotion_state import gate, stable
from guard_harness.publication import Publication
from guard_harness.release_state import canonical_bytes, predicate_digest
from guard_harness.runner import run
from guard_harness.testnet_run import ROOT


def admitted(release: Release, evidence: Path, *, run_id: str, attempt: str, work: Path) -> str:
    previous = gate(release, evidence, run_id=run_id, attempt=attempt, logs=work / "logs/gate")
    state = public_get("https://zunderlabs.com/guard/release.json")
    bundle = public_get("https://zunderlabs.com/guard/release.json.sigstore")
    if state is None or bundle is None:
        raise AttestationError("canonical promoted capsule missing")
    (work / "promoted.predicate.json").write_bytes(state[0])
    (work / "promoted.sigstore.json").write_bytes(bundle[0])
    verified = authenticate_gate(
        release.assets / "release-manifest.json",
        work / "promoted.predicate.json",
        work / "promoted.sigstore.json",
        bundles(evidence, run_id=run_id, attempt=attempt),
        manifest_schema=ROOT / "release/manifest.schema.json",
        state_schema=ROOT / "release/state.schema.json",
        commit=release.commit,
        tag=release.tag,
        workflow="promote.yml",
        previous=previous,
        logs=work / "logs/promotion",
    )
    digest = predicate_digest(verified.predicate)
    if verified.predicate["stage"] != "promoted" or any(
        response[1].get("x-zunder-state-sha256") != digest for response in (state, bundle)
    ):
        raise AttestationError("canonical capsule raced or is not promoted")
    capsule = {
        "channel": "canonical",
        "expected": None,
        "predicate": state[0].decode(),
        "bundle": bundle[0].decode(),
        "unix": release.asset("i").decode(),
        "windows": release.asset("i.ps1").decode(),
    }
    check(Publication(canonical_bytes(capsule), digest))
    return digest


def native(release: Release, *, channel: str, work: Path, account: str, shell: str) -> None:
    system = platform.system()
    windows = system == "Windows"
    target = (
        "windows-amd64"
        if windows
        else ("darwin-" if system == "Darwin" else "linux-")
        + ("arm64" if platform.machine().lower() in {"arm64", "aarch64"} else "amd64")
    )
    binary = work / ("bin/zunder-guard.exe" if windows else "bin/zunder-guard")
    env = {key: value for key, value in os.environ.items() if not key.startswith("ZUNDER_")}
    env["HOMEBREW_NO_AUTO_UPDATE"] = "1"
    if channel == "D3":
        if system != "Darwin":
            raise AttestationError("canonical Homebrew smoke requires macOS")
        run(["brew", "tap", "zunderlabs/tap"], env=env, log=work / "brew-tap.log", timeout=180)
        repo = run(
            ["brew", "--repo", "zunderlabs/tap"], env=env, log=work / "brew-repo.log", timeout=30
        ).output.strip()
        formula = Path(repo) / "Formula/zunder-guard.rb"
        if formula.read_bytes() != release.asset("zunder-guard.rb"):
            raise AttestationError("canonical Homebrew formula differs from signed release")
        run(
            ["brew", "install", "zunderlabs/tap/zunder-guard"],
            env=env,
            log=work / "brew-install.log",
            timeout=600,
        )
        prefix = run(
            ["brew", "--prefix", "zunder-guard"], env=env, log=work / "brew-prefix.log", timeout=30
        ).output.strip()
        binary = Path(prefix) / "bin/zunder-guard"
    else:
        if (channel == "D2") != windows:
            raise AttestationError("canonical loader smoke platform differs")
        loader = work / ("i.ps1" if windows else "i")
        path = "/i.ps1" if windows else "/i"
        response = public_get("https://zunderlabs.com" + path)
        if response is None or response[0] != release.asset(loader.name):
            raise AttestationError("canonical loader differs from authenticated signed release")
        loader.write_bytes(response[0])
        command = (
            [
                shell,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(loader),
                "-InstallOnly",
                "-InstallDir",
                str(binary.parent),
            ]
            if windows
            else ["sh", str(loader), "--install-only", "--prefix", str(binary.parent)]
        )
        run(command, env=env, log=work / "canonical-install.log", timeout=600)
    if (
        hashlib.sha256(binary.read_bytes()).digest()
        != hashlib.sha256(release.binary(target)).digest()
    ):
        raise AttestationError("canonical installed binary differs from signed release archive")
    paper(binary, work=work, account=account, env=env, version=release.tag.removeprefix("v"))


def paper(binary: Path, *, work: Path, account: str, env: dict[str, str], version: str) -> None:
    home = work / "home"
    home.mkdir(mode=0o700)
    rules = json.loads((ROOT / "rules/vectors.json").read_bytes())["valid"][0]["canonical"]
    run(
        [
            str(binary),
            "--home",
            str(home),
            "init",
            "--non-interactive",
            "--network",
            "paper",
            "--account-network",
            "testnet",
            "--no-key",
            "--account",
            account,
            "--rules",
            rules,
        ],
        env=env,
        log=work / "paper-init.log",
        timeout=180,
        sensitive_stdout=True,
    )
    pair = GuardCLI(binary, work, home).pair()
    process = None
    with (work / "paper-runtime.log").open("wb") as output:
        try:
            process = subprocess.Popen(
                [str(binary), "--home", str(home), "run", "--network", "paper"],
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=output,
            )
            guard = LocalGuard("http://127.0.0.1:8547")
            healthy(guard, version=version)
            decisions = round_trip(guard, pair)
            (work / "paper-decisions.json").write_bytes(
                canonical_bytes(
                    {
                        "verdicts": [decision.verdict for decision in decisions],
                        "sequences": [decision.seq for decision in decisions],
                        "mode": "paper",
                    }
                )
            )
        finally:
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)


def transferred(tag: str, commit: str, assets: Path, expected_manifest: str) -> Release:
    """Validate portable bytes received only from the Ubuntu same-run admission job."""
    release = Release(tag, commit, assets)
    if hashlib.sha256(release.asset("release-manifest.json")).hexdigest() != expected_manifest:
        raise AttestationError("same-run authenticated subject manifest differs")
    for name in json.loads(release.asset("release-manifest.json"))["assets"]:
        release.asset(name)
    return release


def exercise(args: argparse.Namespace) -> None:
    stable(args.tag, args.commit)
    if not re.fullmatch(r"0x[0-9a-fA-F]{40}", args.account):
        raise AttestationError("dedicated public paper-read account required")
    args.work.mkdir(mode=0o700)
    release = transferred(args.tag, args.commit, args.assets, args.manifest_sha256)
    digest = admitted(
        release, args.evidence, run_id=args.run_id, attempt=args.attempt, work=args.work
    )
    if args.channel == "D4":
        build = json.loads(release.asset("release-manifest.json"))
        expected = build["distribution"]["docker"]["digest"]
        if image_digest("latest") != expected:
            raise AttestationError("canonical OCI tag differs from signed released digest")
        run(["docker", "pull", IMAGE + ":latest"], log=args.work / "docker-pull.log", timeout=300)
        inspected = run(
            ["docker", "image", "inspect", IMAGE + ":latest", "--format", "{{json .RepoDigests}}"],
            log=args.work / "docker-inspect.log",
            timeout=30,
        )
        if IMAGE + "@" + expected not in json.loads(inspected.output):
            raise AttestationError("pulled canonical OCI bytes differ from signed released digest")
        lifecycle(IMAGE + "@" + expected, args.account, work=args.work / "docker-paper")
    else:
        native(
            release, channel=args.channel, work=args.work, account=args.account, shell=args.shell
        )
    (args.work / "canonical-smoke.json").write_bytes(
        canonical_bytes(
            {
                "result": "passed",
                "channel": args.channel,
                "commit": args.commit,
                "tag": args.tag,
                "manifest_sha256": hashlib.sha256(
                    release.asset("release-manifest.json")
                ).hexdigest(),
                "promoted_state_sha256": digest,
                "paper": True,
            }
        )
    )


def safe_artifacts(work: Path, *, account: str) -> None:
    """Allowlist receipts/decisions and redact bounded diagnostics; never export homes."""
    public = work / "public"
    public.mkdir(parents=True, mode=0o700, exist_ok=True)
    allowed = {
        "canonical-smoke.json": {
            "result",
            "channel",
            "commit",
            "tag",
            "manifest_sha256",
            "promoted_state_sha256",
            "paper",
        },
        "paper-decisions.json": {"verdicts", "sequences", "mode"},
    }
    for name, fields in allowed.items():
        source = work / name
        if source.is_file() and not source.is_symlink() and source.stat().st_size <= 65536:
            value = json.loads(source.read_bytes())
            if isinstance(value, dict) and set(value) == fields:
                if name == "paper-decisions.json":
                    verdicts = value.get("verdicts")
                    sequences = value.get("sequences")
                    if (
                        not isinstance(verdicts, list)
                        or not verdicts
                        or set(verdicts) - {"allow", "resize", "veto"}
                        or not isinstance(sequences, list)
                        or len(sequences) != len(verdicts)
                        or any(type(seq) is not int or seq < 0 for seq in sequences)
                        or value.get("mode") != "paper"
                    ):
                        continue
                else:
                    if (
                        value.get("result") != "passed"
                        or value.get("paper") is not True
                        or value.get("channel") not in {"D1", "D2", "D3", "D4"}
                        or re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", str(value.get("tag"))) is None
                        or any(
                            re.fullmatch(r"[0-9a-f]{64}", str(value.get(key))) is None
                            for key in ("manifest_sha256", "promoted_state_sha256")
                        )
                        or re.fullmatch(r"[0-9a-f]{40}", str(value.get("commit"))) is None
                    ):
                        continue
                body = canonical_bytes(value)
                if account.encode() not in body:
                    (public / name).write_bytes(body)
    for directory in (work, work / "docker-paper"):
        for source in directory.glob("*.log"):
            if (
                source.is_symlink()
                or not source.is_file()
                or source.stat().st_size > 4 * 1024 * 1024
            ):
                continue
            text = source.read_bytes()[-65536:].decode(errors="replace")
            text = re.sub(re.escape(account), "[ACCOUNT]", text, flags=re.IGNORECASE)
            # Pair's only supported secret representation is a 0x-prefixed 64-hex key.
            # Also hide unprefixed key material and addresses from any runtime diagnostics.
            text = re.sub(
                r"(?<![0-9a-fA-F])(?:0x)?[0-9a-fA-F]{32,}(?![0-9a-fA-F])", "[REDACTED]", text
            )
            target = public / (directory.name + "-" + source.name)
            target.write_text(text)


def execute(args: argparse.Namespace) -> None:
    try:
        exercise(args)
    finally:
        if args.work.is_dir() and re.fullmatch(r"0x[0-9a-fA-F]{40}", args.account):
            safe_artifacts(args.work, account=args.account)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("tag", "commit", "run-id", "attempt"):
        parser.add_argument("--" + name, required=True)
    for name in ("work", "evidence", "assets"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--channel", choices=("D1", "D2", "D3", "D4"), required=True)
    parser.add_argument("--account", default=os.environ.get("E2E_PAPER_ACCOUNT", ""))
    parser.add_argument("--shell", default="powershell.exe")
    execute(parser.parse_args())


if __name__ == "__main__":
    main()
