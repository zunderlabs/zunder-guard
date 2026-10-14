"""Hosted Linux only: measure released /opt refusal before normalizing that directory."""

import hashlib
import json
import os
import platform
import re
import stat
import subprocess
from pathlib import Path
from typing import Any

from guard_harness.linux_lifecycle import (
    ROOT_PATH,
    Inputs,
    LifecycleError,
    authenticated_file,
    require,
)
from guard_harness.linux_testnet_service import native_install_failure_category, opt_metadata
from guard_harness.native_release import Release

REFUSAL = "install.sh: managed software directory has unsafe permissions"
REFUSAL_TOKEN = "linux-opt-refusal"
NORMALIZED_TOKEN = "linux-opt-normalized"
NORMALIZED_NOTE = "runner /opt normalised by harness"
RECEIPTS = ("linux-opt-refusal.receipt.json", "linux-opt-normalized.receipt.json")
SCOPE = "root GitHub-hosted Linux runner; /opt only"


def hosted() -> bool:
    return (
        platform.system() == "Linux"
        and os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
    )


def metadata_valid(value: object, *, normalized: bool = False) -> bool:
    if not isinstance(value, dict) or set(value) != {"uid", "gid", "mode", "directory", "symlink"}:
        return False
    return (
        type(value["uid"]) is int
        and value["uid"] == 0
        and type(value["gid"]) is int
        and value["gid"] >= 0
        and (not normalized or value["gid"] == 0)
        and value["mode"] in ({"0755"} if normalized else {"0777", "0775"})
        and value["directory"] is True
        and value["symlink"] is False
    )


def eligible() -> bool:
    return hosted() and metadata_valid(opt_metadata())


def normalize(before: dict[str, object]) -> None:
    """A no-follow descriptor pins the only directory we may change."""
    require(hosted() and os.geteuid() == 0, "normalization requires a root hosted Linux runner")
    descriptor = os.open("/opt", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        current = Path("/opt").lstat()
        require(
            stat.S_ISDIR(info.st_mode)
            and info.st_uid == 0
            and stat.S_IMODE(info.st_mode) in {0o777, 0o775}
            and (info.st_dev, info.st_ino) == (current.st_dev, current.st_ino)
            and opt_metadata() == before,
            "runner /opt changed before normalization",
        )
        os.fchown(descriptor, 0, 0)
        os.fchmod(descriptor, 0o755)
        require(
            (info.st_dev, info.st_ino)
            == (Path("/opt").lstat().st_dev, Path("/opt").lstat().st_ino),
            "runner /opt replaced during normalization",
        )
    finally:
        os.close(descriptor)


def write(path: Path, value: dict[str, Any]) -> None:
    # Exclusive and durable: a failed probe never authorizes a normalization.
    with path.open("x") as stream:
        json.dump(value, stream)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def prepare(
    inputs: Inputs, installer: Path | None, digest: str, binary_sha256: str
) -> dict[str, object]:
    return measure(
        installer,
        digest,
        binary_sha256,
        output=inputs.output,
        account=inputs.account,
        rules=inputs.rules,
        version=inputs.version,
        commit=inputs.release_commit,
        manifest_sha256=inputs.manifest_sha256,
        scenario=inputs.scenario,
    )


def measure(
    installer: Path | None,
    digest: str,
    binary_sha256: str,
    *,
    output: Path,
    account: str,
    rules: str,
    version: str,
    commit: str,
    manifest_sha256: str,
    scenario: str,
) -> dict[str, object]:
    """The decisions.md 14 Oct step for any root service row (I1, I2, I6, T2)."""
    if not hosted():
        return {}
    before = opt_metadata()
    if not metadata_valid(before):
        return {}
    require(os.geteuid() == 0, "normalization requires a root hosted Linux runner")
    require(installer is not None, "released install.sh required for /opt refusal")
    assert installer is not None
    authenticated_file(installer, digest)
    require(
        re.fullmatch(r"[0-9a-f]{40}", commit) is not None
        and re.fullmatch(r"[0-9a-f]{64}", manifest_sha256) is not None,
        "authenticated released /opt policy identity required",
    )
    identity = dict(
        schema=1,
        result="passed",
        tag=version,
        commit=commit,
        manifest_sha256=manifest_sha256,
        installer_sha256=digest,
        binary_sha256=binary_sha256,
        scenario=scenario,
        scope=SCOPE,
    )
    try:
        result = subprocess.run(
            [
                "sh",
                str(installer),
                "--non-interactive",
                "--network",
                "testnet",
                "--account",
                account,
                "--key-stdin",
                "--rules",
                rules,
                "--equity-cap",
                "40",
                "--ip-share",
                "1",
                "--listen",
                "127.0.0.1:18548",
                "--service-instance",
                "testnet",
            ],
            input=b"",
            env={"PATH": ROOT_PATH, "HOME": "/root"},
            capture_output=True,
            timeout=600,
            check=False,
        )
    except (subprocess.SubprocessError, OSError):
        raise LifecycleError("released /opt refusal probe did not complete") from None
    # Never retain unexpected output. The probe receives no wallet key.
    require(
        result.returncode == 1
        and result.stderr == REFUSAL.encode() + b"\n"
        and native_install_failure_category(result.stderr.decode())
        == "native-software-permissions",
        "released installer did not emit the exact native-software-permissions refusal",
    )
    require(opt_metadata() == before, "runner /opt changed during refusal probe")
    refusal_path, normalized_path = (output / name for name in RECEIPTS)
    write(
        refusal_path,
        dict(
            **identity,
            exit_status=1,
            stderr=REFUSAL,
            private_stdin_supplied=False,
            failure_category="native-software-permissions",
            before=before,
            coverage=[REFUSAL_TOKEN],
        ),
    )
    normalize(before)
    after = opt_metadata()
    require(metadata_valid(after, normalized=True), "runner /opt normalization not confirmed")
    write(
        normalized_path,
        dict(
            **identity,
            opt_policy=NORMALIZED_NOTE,
            before=before,
            after=after,
            refusal_sha256=hashlib.sha256(refusal_path.read_bytes()).hexdigest(),
            coverage=[NORMALIZED_TOKEN],
        ),
    )
    return dict(
        opt_policy=NORMALIZED_NOTE,
        linux_opt_receipt_sha256=hashlib.sha256(normalized_path.read_bytes()).hexdigest(),
    )


def admit(release: Release, target: str, work: Path, lifecycle: dict[str, Any]) -> None:
    """Separate measurements do not supply positive lifecycle coverage."""
    paths = [work / name for name in RECEIPTS]
    require(
        all(
            not path.is_symlink() and path.is_file() and path.stat().st_size <= 16384
            for path in paths
        ),
        "bounded Linux /opt policy receipts required",
    )
    refusal, normalized = [json.loads(path.read_bytes()) for path in paths]
    require(
        isinstance(refusal, dict) and isinstance(normalized, dict), "/opt receipt objects required"
    )
    expected = dict(
        schema=1,
        result="passed",
        tag=release.tag,
        commit=release.commit,
        manifest_sha256=hashlib.sha256(release.asset("release-manifest.json")).hexdigest(),
        installer_sha256=hashlib.sha256(release.asset("install.sh")).hexdigest(),
        binary_sha256=hashlib.sha256(release.binary(target)).hexdigest(),
        scenario=lifecycle.get("scenario"),
        scope=SCOPE,
    )
    require(
        lifecycle.get("scenario") in {"fresh", "upgrade"}
        and all(type(value.get("schema")) is int for value in (refusal, normalized))
        and all(
            all(value.get(k) == v for k, v in expected.items()) for value in (refusal, normalized)
        )
        and type(refusal.get("exit_status")) is int
        and refusal.get("exit_status") == 1
        and refusal.get("stderr") == REFUSAL
        and refusal.get("private_stdin_supplied") is False
        and refusal.get("failure_category") == "native-software-permissions"
        and refusal.get("coverage") == [REFUSAL_TOKEN]
        and metadata_valid(refusal.get("before"))
        and normalized.get("before") == refusal.get("before")
        and metadata_valid(normalized.get("after"), normalized=True)
        and normalized.get("coverage") == [NORMALIZED_TOKEN]
        and normalized.get("opt_policy") == NORMALIZED_NOTE
        and normalized.get("refusal_sha256") == hashlib.sha256(paths[0].read_bytes()).hexdigest()
        and lifecycle.get("opt_policy") == NORMALIZED_NOTE
        and lifecycle.get("linux_opt_receipt_sha256")
        == hashlib.sha256(paths[1].read_bytes()).hexdigest(),
        "Linux /opt refusal/normalization measurements differ",
    )
