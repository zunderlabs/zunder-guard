import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from guard_harness import linux_guest, native_testnet
from guard_harness.linux_lifecycle import LifecycleError
from guard_harness.native_release import Release
from guard_harness.source_installer import Candidate, component_metadata
from guard_harness.testnet_process import ProcessError


class CapturedInput(Exception):
    pass


@pytest.mark.parametrize(
    "mutation", ["none", "hash", "symlink", "formal", "paper", "upgrade", "sha"]
)
def test_guest_verifies_source_component_before_private_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    candidate = tmp_path / "candidate"
    candidate.write_bytes(b"fixed public source candidate")
    digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
    if mutation == "hash":
        candidate.write_bytes(b"changed")
    elif mutation == "symlink":
        target = tmp_path / "target"
        candidate.rename(target)
        candidate.symlink_to(target)
    words = [
        "guest",
        "--candidate",
        str(candidate),
        "--previous",
        str(candidate),
        "--version",
        "v1.0.0-rc.14",
        "--previous-version",
        "v1.0.0-rc.13",
        "--rules",
        "fixture",
        "--account",
        "fixture",
        "--output",
        str(tmp_path / "result"),
        "--account-network",
        "testnet",
        "--scenario",
        "upgrade" if mutation == "upgrade" else "fresh",
        "--source-installer-sha256",
        digest,
        "--installer-harness-commit",
        "bad" if mutation == "sha" else "a" * 40,
        "--binary-sha256",
        "b" * 64,
        "--previous-binary-sha256",
        "c" * 64,
    ]
    if mutation != "formal":
        words.append("--diagnostic")
    if mutation != "paper":
        words.append("--testnet-lifecycle")
    monkeypatch.setattr(sys, "argv", words)

    class Input:
        @property
        def buffer(self) -> "Input":
            return self

        def read(self, length: int) -> bytes:
            assert length == 66
            raise CapturedInput

    monkeypatch.setattr(sys, "stdin", Input())
    with pytest.raises(CapturedInput if mutation == "none" else (ProcessError, LifecycleError)):
        linux_guest.main()


def test_mac_source_is_current_only_and_rechecked_immediately_before_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("guard_harness.native_testnet.platform.system", lambda: "Darwin")
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    current = Release("v1.0.0-rc.14", "a" * 40, tmp_path / "current")
    previous = Release("v1.0.0-rc.13", "b" * 40, tmp_path / "previous")
    source = Candidate(b"fixed public source", "c" * 40, "d" * 64, current.tag, current.commit)
    path = source.stage(work)
    native = native_testnet.NativeTestnet(
        current, previous, work, "0x" + "1" * 40, "sh", "fresh", source, path
    )
    calls: list[list[str]] = []
    monkeypatch.setattr(
        native_testnet,
        "staged_loader",
        lambda release, **kwargs: kwargs["output"].write_bytes(b"signed loader"),
    )
    monkeypatch.setattr(Release, "asset", lambda self, name: b"signed previous loader")
    monkeypatch.setattr(native, "identity", lambda release: None)
    monkeypatch.setattr(native, "installed", lambda: tmp_path / "binary")

    def command(words: list[str], **kwargs: Any) -> str:
        calls.append(words)
        return json.dumps({"ok": True, "mode": "testnet", "account": native.account})

    monkeypatch.setattr(native, "command", command)
    native.install(current, fresh=True)
    assert str(path) in calls[0]
    calls.clear()
    native.install(previous)
    assert str(path) not in calls[0]
    calls.clear()
    path.write_bytes(b"changed after source admission")
    with pytest.raises(ProcessError):
        native.install(current)
    assert calls == []


@pytest.mark.parametrize("mutation", ["flag", "sha", "digest", "scenario", "actual"])
def test_partial_or_formal_inner_source_metadata_is_refused(mutation: str) -> None:
    with pytest.raises(ProcessError):
        component_metadata(
            mutation != "flag",
            "bad" if mutation == "sha" else "a" * 40,
            "bad" if mutation == "digest" else "b" * 64,
            scenario="upgrade" if mutation == "scenario" else "fresh",
            actual_digest="c" * 64 if mutation == "actual" else "b" * 64,
        )


def test_original_inner_receipts_are_nongate_at_write(tmp_path: Path) -> None:
    from guard_harness.linux_testnet_lifecycle import TestnetLifecycle, failure_evidence

    source = component_metadata(True, "a" * 40, "b" * 64, scenario="fresh", actual_digest="b" * 64)
    # Receipt writer only: no guest/service/credential or venue operation occurs.
    lifecycle = TestnetLifecycle.__new__(TestnetLifecycle)
    lifecycle.source_metadata = source
    lifecycle.record_path = tmp_path / "testnet-lifecycle.json"
    lifecycle.write({"stage": "awaiting-reboot", "gate_eligible": True})
    tmp_path.chmod(0o700)
    failure_evidence(tmp_path, "before-reboot", "install", "command", source=source)
    for path in tmp_path.glob("*.json"):
        record = json.loads(path.read_bytes())
        assert record["source_component"] is True and record["diagnostic"] is True
        assert record["gate_eligible"] is False


@pytest.mark.parametrize("tampered", [False, True])
def test_inner_guest_source_hash_is_verified_before_key_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tampered: bool
) -> None:
    from guard_harness import linux_testnet_lifecycle as driver

    candidate = tmp_path / "candidate"
    candidate.write_bytes(b"fixed public source")
    digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
    if tampered:
        candidate.write_bytes(b"changed")
    words = ["inner", "--source-component"]
    for name, value in {
        "installer": str(candidate),
        "previous-installer": str(candidate),
        "output": str(tmp_path / "output"),
        "installer-sha256": digest,
        "previous-installer-sha256": "b" * 64,
        "version": "v1.0.0-rc.14",
        "previous-version": "v1.0.0-rc.13",
        "rules": "fixture",
        "account": "0x" + "1" * 40,
        "marker": "c" * 32,
        "binary-sha256": "d" * 64,
        "previous-binary-sha256": "e" * 64,
        "route": "native",
        "phase": "before-reboot",
        "scenario": "fresh",
        "installer-harness-commit": "a" * 40,
        "source-installer-sha256": digest,
    }.items():
        words.extend(["--" + name, value])

    class Input:
        @property
        def buffer(self) -> "Input":
            return self

        def read(self, length: int) -> bytes:
            raise CapturedInput

    monkeypatch.setattr(sys, "argv", words)
    monkeypatch.setattr(sys, "stdin", Input())
    with pytest.raises(ProcessError if tampered else CapturedInput):
        driver.main()
