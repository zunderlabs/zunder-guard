import hashlib
import io
import json
import os
import platform
import subprocess
import sys
import tarfile
import time
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

import guard_harness.testnet_run as command
from guard_harness.testnet_cleanup import Cleaned
from guard_harness.testnet_journey import Journey
from guard_harness.testnet_ownership import Ownership
from guard_harness.testnet_process import ProcessError

TAG = "v1.0.0"
COMMIT = "b" * 40
NAME = f"zunder-guard-{TAG}-linux-amd64.tar.gz"
ACCOUNT = "0x" + "a" * 40
WALLET = "0x" + "b" * 40


def assets(path: Path, *, member: str = "zunder-guard", kind: bytes = tarfile.REGTYPE) -> None:
    path.mkdir(mode=0o700)
    archive = path / NAME
    with tarfile.open(archive, "w:gz") as stream:
        entry = tarfile.TarInfo(member)
        entry.type = kind
        entry.linkname = "outside"
        entry.size = 7 if kind == tarfile.REGTYPE else 0
        stream.addfile(entry, io.BytesIO(b"fixture") if entry.size else None)
    build = json.loads((command.ROOT / "release/examples/build-v2.json").read_text())
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    build["assets"] = {
        NAME: {
            "sha256": digest,
            "url": f"https://github.com/zunderlabs/zunder-guard/releases/download/{TAG}/{NAME}",
        }
    }
    manifest = path / "release-manifest.json"
    manifest.write_text(json.dumps(build))
    (path / "SHA256SUMS").write_text(
        f"{digest}  {NAME}\n"
        f"{hashlib.sha256(manifest.read_bytes()).hexdigest()}  release-manifest.json\n"
    )
    (path / ".verified-release-source.json").write_text(json.dumps(dict(tag=TAG, source=COMMIT)))
    for file in path.iterdir():
        file.chmod(0o600)


@pytest.fixture(autouse=True)
def linux(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(platform, "machine", lambda: "x86_64")


def test_exact_signed_inventory_binary(tmp_path: Path) -> None:
    source = tmp_path / "assets"
    assets(source)
    output = tmp_path / "subject"
    digest, manifest = command.signed_binary(source, output, tag=TAG, commit=COMMIT)
    assert output.read_bytes() == b"fixture"
    assert digest == hashlib.sha256(b"fixture").hexdigest()
    assert manifest == hashlib.sha256((source / "release-manifest.json").read_bytes()).hexdigest()
    assert output.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "member,kind",
    [
        ("../zunder-guard", tarfile.REGTYPE),
        ("zunder-guard", tarfile.SYMTYPE),
        ("zunder-guard", tarfile.LNKTYPE),
        ("README.md", tarfile.REGTYPE),
        ("zunder-guard/private", tarfile.REGTYPE),
    ],
)
def test_archive_refusal(tmp_path: Path, member: str, kind: bytes) -> None:
    source = tmp_path / "assets"
    assets(source, member=member, kind=kind)
    with pytest.raises(ProcessError):
        command.signed_binary(source, tmp_path / "subject", tag=TAG, commit=COMMIT)
    assert not (tmp_path / "subject").exists()


@pytest.mark.parametrize("changed", ["source", "archive", "manifest", "duplicate", "oversize"])
def test_changed_or_ambiguous_authenticated_subject(tmp_path: Path, changed: str) -> None:
    source = tmp_path / "assets"
    assets(source)
    if changed == "source":
        (source / ".verified-release-source.json").write_text(
            json.dumps(dict(tag=TAG, source="c" * 40))
        )
    elif changed == "archive":
        (source / NAME).write_bytes(b"changed")
    elif changed == "manifest":
        with (source / "release-manifest.json").open("a") as stream:
            stream.write(" ")
    elif changed == "duplicate":
        with (source / "SHA256SUMS").open("a") as stream:
            stream.write((source / "SHA256SUMS").read_text().splitlines()[0] + "\n")
    else:
        (source / ".verified-release-source.json").write_bytes(b" " * 257)
    with pytest.raises(ProcessError):
        command.signed_binary(source, tmp_path / "subject", tag=TAG, commit=COMMIT)
    assert not (tmp_path / "subject").exists()


def args(tmp_path: Path, key: io.BytesIO) -> dict[str, Any]:
    return dict(
        tag=TAG,
        commit=COMMIT,
        account=ACCOUNT,
        api_wallet=WALLET,
        work=tmp_path / "run",
        port=18547,
        deadline=time.monotonic() + 2400,
        key_stdin=key,
    )


@pytest.mark.parametrize("success", [True, False])
def test_verification_before_custody_and_sanitized_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, success: bool
) -> None:
    key = io.BytesIO(b"FIXTURE-PRIVATE-INPUT")
    calls: list[str] = []
    monkeypatch.setenv("E2E_TESTNET_API_KEY", "FIXTURE-PRIVATE-INPUT")
    monkeypatch.setenv("GH_TOKEN", "FIXTURE-GH-TOKEN")

    def verify(argv: list[str], **kwargs: Any) -> None:
        calls.append("verified")
        assert argv == [
            "bash",
            str(command.ROOT / "github/verify-release-assets.sh"),
            TAG,
            str(tmp_path / "run/assets"),
        ]
        assert kwargs["stdin"] == b"" and kwargs["timeout"] == 600
        assert kwargs["env"]["GITHUB_REPOSITORY"] == command.REPOSITORY
        assert "E2E_TESTNET_API_KEY" not in kwargs["env"]
        assert "FIXTURE-GH-TOKEN" in kwargs["secrets"]
        assert key.tell() == 0
        assets(Path(argv[-1]))

    class Owner:
        def __init__(self, subject: Path, **kwargs: Any) -> None:
            assert calls == ["verified"] and subject.read_bytes() == b"fixture"
            assert kwargs["key_stdin"] is key and key.tell() == 0
            assert kwargs["api_wallet"] == WALLET
            calls.append("foreground")

        def journey(self, read: Any, **kwargs: Any) -> Journey:
            assert kwargs["version"] == "1.0.0"
            calls.append("journey")
            if not success:
                raise RuntimeError("FIXTURE-PRIVATE-INPUT")
            return Journey(
                Ownership(1, 2, Decimal(".0001"), Decimal(".0001"), False),
                Cleaned(("close",), {"flat": True}),
                None,
                True,
            )

    monkeypatch.setattr(command, "run", verify)
    monkeypatch.setattr(command, "Foreground", Owner)
    assert command.execute_release(**args(tmp_path, key)) == (0 if success else 1)
    receipt = (tmp_path / "run/receipt.json").read_text()
    parsed = json.loads(receipt)
    assert parsed["result"] == ("passed" if success else "failed")
    assert parsed["release_ready"] is False
    assert "FIXTURE" not in receipt and ACCOUNT not in receipt and WALLET not in receipt
    assert (tmp_path / "run/receipt.json").stat().st_mode & 0o777 == 0o600
    assert key.tell() == 0 and calls == ["verified", "foreground", "journey"]
    if success:
        predicate = json.loads((tmp_path / "run/T1.predicate.json").read_text())
        assert predicate["commit"] == COMMIT and predicate["journey"] == "T1"
        assert predicate["manifest_sha256"] == parsed["manifest_sha256"]
        assert predicate["result"] == "passed" and predicate["tier"] == "e2e"
        assert parsed["protected_entry"]["stop_oid"] == 2
        assert parsed["cleanup"]["scan"] == {"flat": True}
    else:
        assert not (tmp_path / "run/T1.predicate.json").exists()
        assert parsed["failure"] == "journey_incomplete_keep_protection"


def test_authentication_failure_never_launches_or_reads_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = io.BytesIO(b"FIXTURE-PRIVATE-INPUT")

    def refuse(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("FIXTURE-PRIVATE-INPUT")

    monkeypatch.setattr(command, "run", refuse)
    monkeypatch.setattr(command, "Foreground", lambda *a, **k: pytest.fail("must not launch"))
    assert command.execute_release(**args(tmp_path, key)) == 1
    receipt = (tmp_path / "run/receipt.json").read_text()
    assert json.loads(receipt)["stage"] == "authenticate"
    assert "FIXTURE" not in receipt and key.tell() == 0


@pytest.mark.parametrize("deadline", [float("nan"), float("inf"), 0.0])
def test_invalid_deadline_refuses_before_custody(tmp_path: Path, deadline: float) -> None:
    values = args(tmp_path, io.BytesIO())
    values["deadline"] = deadline
    with pytest.raises(ProcessError):
        command.execute_release(**values)
    assert not (tmp_path / "run").exists()


def test_receipt_failure_restores_umask(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: Any, **kwargs: Any) -> None:
        raise OSError("fixture")

    monkeypatch.setattr(command, "_receipt", refuse)
    original = os.umask(0o027)
    try:
        with pytest.raises(OSError):
            command.execute_release(**args(tmp_path, io.BytesIO()))
        observed = os.umask(0o027)
        assert observed == 0o027
    finally:
        os.umask(original)


def test_archive_replacement_cannot_change_verified_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "assets"
    assets(source)
    original = tarfile.open
    calls = 0

    def replace_then_parse(*args: Any, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        with original(source / NAME, "w:gz") as stream:
            entry = tarfile.TarInfo("zunder-guard")
            entry.size = 7
            stream.addfile(entry, io.BytesIO(b"changed"))
        return original(*args, **kwargs)

    monkeypatch.setattr(tarfile, "open", replace_then_parse)
    output = tmp_path / "subject"
    digest, _ = command.signed_binary(source, output, tag=TAG, commit=COMMIT)
    assert calls == 1 and output.read_bytes() == b"fixture"
    assert digest == hashlib.sha256(b"fixture").hexdigest()


def test_installed_entrypoint_resolves_release_resources(tmp_path: Path) -> None:
    # CI and journey install editable. Isolated Python ignores pytest's source-path shortcut.
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            "from guard_harness.testnet_run import ROOT; import json; "
            "assert (ROOT / 'github/verify-release-assets.sh').is_file(); "
            "assert json.loads((ROOT / 'release/manifest.schema.json').read_text())"
            "['properties']['schema']['const'] == 2",
        ],
        cwd=tmp_path,
        capture_output=True,
        check=True,
        timeout=10,
    )
    assert result.returncode == 0
