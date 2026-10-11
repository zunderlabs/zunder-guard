"""Testnet lifecycle evidence refuses mutation, uncertain cleanup and false audit credit."""

import hashlib
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from guard_harness import linux_guest, linux_testnet_lifecycle, linux_testnet_service
from guard_harness.linux_guest import Guest
from guard_harness.linux_lifecycle import LifecycleError
from guard_harness.linux_testnet_lifecycle import (
    TestnetLifecycle as ProtectedLifecycle,
)
from guard_harness.linux_testnet_lifecycle import (
    no_exchange,
    preserved,
    retained,
)
from guard_harness.runner import RunResult
from guard_harness.testnet_scan import ScanError


def journal(home: Path, events: list[dict[str, Any]]) -> None:
    previous = ""
    lines = []
    for sequence, body in enumerate(events, 1):
        event = dict(body, seq=sequence, at_ms=sequence)
        text = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        check = hashlib.sha3_256((previous + text).encode()).hexdigest()
        lines.append(json.dumps({"prev": previous, "check": check, "event": event}))
        previous = check
    (home / "decisions.jsonl").write_text("\n".join(lines) + "\n")


def test_complete_startup_journal_counts_no_exchange_including_boot(tmp_path: Path) -> None:
    journal(
        tmp_path,
        [
            {"kind": "started", "mode": "testnet"},
            {"kind": "risk", "open_positions": 0, "discrepancies": 0, "journal_error": None},
            {"kind": "stopped"},
            {"kind": "started", "mode": "testnet"},
        ],
    )
    with (tmp_path / "decisions.jsonl").open("ab") as output:
        output.write(b"\x00" * 4096)
    assert no_exchange(tmp_path) == 4


@pytest.mark.parametrize(
    "kind",
    ["decision", "intent", "sent", "protect", "flatten", "recovered", "unknown", "error", "kill"],
)
def test_action_or_unknown_event_cannot_earn_no_exchange_credit(tmp_path: Path, kind: str) -> None:
    journal(tmp_path, [{"kind": "started", "mode": "testnet"}, {"kind": kind}])
    with pytest.raises(LifecycleError, match="action-bearing or unknown"):
        no_exchange(tmp_path)


def test_missing_startup_cannot_be_misread_as_zero_requests(tmp_path: Path) -> None:
    journal(tmp_path, [{"kind": "stopped"}])
    with pytest.raises(LifecycleError, match="positive control"):
        no_exchange(tmp_path)


@pytest.mark.parametrize("failure", ["missing", "truncated", "checksum", "symlink", "emergency"])
def test_incomplete_or_emergency_journal_cannot_claim_read_only_runtime(
    tmp_path: Path, failure: str
) -> None:
    journal(tmp_path, [{"kind": "started", "mode": "testnet"}])
    path = tmp_path / "decisions.jsonl"
    if failure == "missing":
        path.unlink()
    elif failure == "truncated":
        path.write_bytes(path.read_bytes().rstrip(b"\n"))
    elif failure == "checksum":
        record = json.loads(path.read_bytes())
        record["event"]["version"] = "tampered"
        path.write_text(json.dumps(record) + "\n")
    elif failure == "symlink":
        target = tmp_path / "original"
        path.rename(target)
        path.symlink_to(target)
    else:
        emergency = tmp_path / "emergency"
        emergency.mkdir()
        (emergency / "attempt").write_text("protective send requires human review")
    with pytest.raises(LifecycleError):
        no_exchange(tmp_path)


def test_retention_keeps_pairing_and_populated_testnet_journal_prefix(tmp_path: Path) -> None:
    (tmp_path / "guard.toml").write_bytes(b"paired synthetic configuration")
    (tmp_path / "risk.jsonl").write_bytes(b"risk prefix\n" + b"\x00" * 20)
    journal(tmp_path, [{"kind": "started", "mode": "testnet"}])
    before = retained(tmp_path)
    (tmp_path / "risk.jsonl").write_bytes(b"risk prefix\nnext risk event\n")
    preserved(tmp_path, before)
    (tmp_path / "guard.toml").write_bytes(b"replaced pairing")
    with pytest.raises(LifecycleError, match="pairing/configuration"):
        preserved(tmp_path, before)


@pytest.mark.parametrize("action", ["start", "stop", "restart"])
def test_uncertain_flat_scan_never_mutates_or_removes_service(
    monkeypatch: pytest.MonkeyPatch, action: str
) -> None:
    lifecycle = object.__new__(ProtectedLifecycle)
    lifecycle.unit = "synthetic-testnet.service"

    def unknown() -> None:
        raise ScanError("testnet HTTP/JSON read failed")

    monkeypatch.setattr(lifecycle, "flat", unknown)
    monkeypatch.setattr(lifecycle, "command", lambda *args: pytest.fail("no mutation authorized"))
    with pytest.raises(ScanError):
        lifecycle.control("fixture", action)


def test_guest_key_transport_is_only_encrypted_ssh_stdin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = b"a" * 64 + b"\n"
    guest = Guest(tmp_path, tmp_path)
    guest.ssh = ["ssh", "fixture-guest"]

    def invoke(argv: list[str], **kwargs: Any) -> RunResult:
        assert argv == ["ssh", "fixture-guest", "sudo protected-helper"]
        assert kwargs["stdin"] == key
        assert kwargs["secrets"] == [key.decode().strip()]
        assert kwargs["sensitive_output"] is True
        assert key.decode().strip() not in str(kwargs["env"])
        return RunResult(0, "safe metadata", tmp_path / "withheld.log")

    monkeypatch.setattr(linux_guest, "run", invoke)
    assert guest.private_remote("sudo protected-helper", key) == "safe metadata"
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("key", [b"", b"b" * 64, b"b" * 65 + b"\n", b"b" * 64 + b"\nextra"])
def test_guest_key_framing_refuses_before_ssh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, key: bytes
) -> None:
    monkeypatch.setattr(linux_guest, "run", lambda *args, **kwargs: pytest.fail("no SSH allowed"))
    with pytest.raises(LifecycleError, match="frame"):
        Guest(tmp_path, tmp_path).private_remote("fixture", key)


@pytest.mark.parametrize("outcome", ["unknown", "timeout", "malformed", "not-flat"])
def test_unknown_cleanup_preserves_live_guest_and_private_disk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, outcome: str
) -> None:
    disk = tmp_path / "private-disk"
    disk.mkdir()
    (disk / "encrypted-custody").write_bytes(b"synthetic encrypted disk")
    guest = Guest(disk, tmp_path)

    class Process:
        def poll(self) -> None:
            return None

        def terminate(self) -> None:
            pytest.fail("uncertain cleanup must not terminate protection")

        def kill(self) -> None:
            pytest.fail("uncertain cleanup must not kill protection")

    def observation(command: str, *, timeout: float) -> str:
        assert timeout == 900
        if outcome in {"unknown", "timeout"}:
            raise RuntimeError("bounded SSH read failed or timed out")
        return "malformed" if outcome == "malformed" else '{"flat":false}'

    monkeypatch.setattr(guest, "remote", observation)
    with pytest.raises(RuntimeError, match="owned guest preserved"):
        guest.destroy_testnet(cast(subprocess.Popen[bytes], Process()), [])
    assert (disk / "encrypted-custody").is_file()
    assert json.loads((tmp_path / "cleanup-required.json").read_bytes()) == {
        "cleanup_complete": False,
        "disk_retained": True,
        "runtime_alive": True,
    }


@pytest.mark.parametrize("fresh", [True, False])
def test_container_installer_stdin_consumption_matches_released_setup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fresh: bool
) -> None:
    root = tmp_path / "synthetic-root"
    marker = tmp_path / "marker"
    marker.write_text("a" * 32)
    account = "0x" + "b" * 40
    key = b"c" * 64 + b"\n"

    def mapped(value: str) -> Path:
        return root / value.lstrip("/")

    mapped("/run/systemd/system").mkdir(parents=True)
    config = mapped("/etc/zunder-guard-container/config.json")
    config.parent.mkdir(parents=True)
    config_body = json.dumps({"mode": "testnet", "account": account, "volume": "fixture"})
    if not fresh:
        config.write_text(config_body)
    credential = config.parent / "credential.cred"
    credential.write_bytes(b"synthetic encrypted credential")
    credential.chmod(0o600)
    unit = mapped("/etc/systemd/system/zunder-guard-container.service")
    unit.parent.mkdir(parents=True)
    unit.write_text("LoadCredentialEncrypted=guard-api-wallet:synthetic")
    monkeypatch.setattr(linux_testnet_service, "Path", mapped)
    monkeypatch.setattr(linux_testnet_service, "MARKER", marker)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(linux_testnet_service, "authenticated_file", lambda *args: None)
    # Synthetic private-file ownership is fixed independently of the test user.
    original_stat = Path.stat

    def owned_stat(path: Path, *args: Any, **kwargs: Any) -> Any:
        stat = original_stat(path, *args, **kwargs)
        if path == credential:
            from types import SimpleNamespace

            return SimpleNamespace(st_uid=0, st_mode=stat.st_mode)
        return stat

    monkeypatch.setattr(Path, "stat", owned_stat)
    calls = []

    def invoke(argv: list[str], **kwargs: Any) -> RunResult:
        calls.append(argv)
        assert kwargs["sensitive_output"] is True
        if argv[0] == "sh":
            assert kwargs["stdin"] == key * (2 if fresh else 1)
            assert kwargs["secrets"] == [key.decode().strip()]
            assert "--container" in argv and "--key-stdin" in argv
            assert "--listen" not in argv
            for setup_choice in ("--rules", "--equity-cap", "--ip-share"):
                assert (setup_choice in argv) is fresh
            assert argv[argv.index("--network") + 1] == "testnet"
            assert argv[argv.index("--account") + 1] == account
            assert key.decode().strip() not in str(argv)
            config.write_text(config_body)
            return RunResult(0, "withheld", tmp_path / "private.log")
        return RunResult(0, "/var/lib/docker/volumes/fixture/_data", tmp_path / "private.log")

    monkeypatch.setattr(linux_testnet_service, "run", invoke)
    service = linux_testnet_service.TestnetService(
        tmp_path / "install.sh",
        "d" * 64,
        account,
        "synthetic-rules",
        8547,
        tmp_path,
        "a" * 32,
        container=True,
    )
    assert service.setup(key)["unit"] == "zunder-guard-container.service"
    assert len(calls) == 2


@pytest.mark.parametrize(
    "failure",
    ["none", "credential-changed", "config-changed", "broken-unit", "journal-lost", "volume-lost"],
)
def test_container_uninstall_credit_requires_recovery_preservation_and_absent_software(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    root = tmp_path / "root"

    def mapped(*parts: str) -> Path:
        return root / Path(*parts).as_posix().lstrip("/")

    home = mapped("/var/lib/docker/volumes/fixture/_data")
    home.mkdir(parents=True)
    (home / "guard.toml").write_bytes(b"synthetic paired config")
    (home / "risk.jsonl").write_bytes(b"synthetic risk prefix\n")
    journal(home, [{"kind": "started", "mode": "testnet"}])
    recovery = mapped("/etc/zunder-guard-container")
    recovery.mkdir(parents=True)
    for name in ("credential.cred", "config.json"):
        (recovery / name).write_bytes(b"synthetic retained " + name.encode())
    (recovery / "config.json").write_text(json.dumps({"volume": "fixture"}))
    owned = [
        "/etc/systemd/system/zunder-guard-container.service",
        "/etc/systemd/system/zunder-guard-setup-guardian.service",
        "/usr/local/libexec/zunder-guard-container/supervisor.py",
        "/usr/local/libexec/zunder-guard-container/operations.py",
        "/usr/local/libexec/zunder-guard-container/zunder-guard-container.service",
        "/etc/systemd/system/zunder-guard-container.service.d/10-install-transaction.conf",
    ]
    for path in owned:
        file = mapped(path)
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(b"synthetic owned software")
    boot = mapped("/proc/sys/kernel/random/boot_id")
    boot.parent.mkdir(parents=True)
    boot.write_text("synthetic boot")
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    snapshot = private / "snapshot.json"
    snapshot.write_text(json.dumps(retained(home)))
    snapshot.chmod(0o600)
    lifecycle = object.__new__(ProtectedLifecycle)
    lifecycle.route, lifecycle.unit = "container", "zunder-guard-container.service"
    lifecycle.home, lifecycle.private = home, private
    lifecycle.inputs = cast(
        Any,
        SimpleNamespace(
            installer=tmp_path / "released-install.sh",
            installer_sha256="a" * 64,
            previous_installer_sha256="b" * 64,
            version="v1.2.3",
            previous_version="v1.2.2",
        ),
    )
    lifecycle.binary_sha256 = lifecycle.previous_binary_sha256 = "c" * 64
    lifecycle.image = lifecycle.previous_image = "synthetic immutable descriptor"
    lifecycle.record_path = tmp_path / "testnet-lifecycle.json"
    lifecycle.record_path.write_text(
        json.dumps(
            {
                "stage": "awaiting-reboot",
                "boot_id": "synthetic boot",
                "installer_sha256": "a" * 64,
                "previous_installer_sha256": "b" * 64,
            }
        )
    )
    monkeypatch.setattr(lifecycle, "healthy", lambda *args: None)
    monkeypatch.setattr(lifecycle, "control", lambda *args: None)
    monkeypatch.setattr(lifecycle, "flat", lambda: None)
    monkeypatch.setattr(lifecycle, "install", lambda *args, **kwargs: None)
    monkeypatch.setattr(linux_testnet_lifecycle, "Path", mapped)
    original_stat = Path.stat

    def owned_stat(path: Path, *args: Any, **kwargs: Any) -> Any:
        value = original_stat(path, *args, **kwargs)
        return SimpleNamespace(st_uid=0, st_mode=value.st_mode) if path == snapshot else value

    monkeypatch.setattr(Path, "stat", owned_stat)
    calls = []

    def command(name: str, argv: list[str]) -> str:
        calls.append(name)
        if name == "owned-volume":
            return "/var/lib/docker/volumes/fixture/_data"
        if name == "retained-volume":
            return "" if failure == "volume-lost" else str(lifecycle.home)
        if name == "uninstall":
            assert argv == [
                "sh",
                str(lifecycle.inputs.installer),
                "--container",
                "--uninstall",
                "--network",
                "testnet",
                "--non-interactive",
            ]
            for file in owned:
                mapped(file).unlink()
            if failure == "broken-unit":
                mapped(owned[0]).symlink_to("synthetic-missing-target")
            elif failure in {"credential-changed", "config-changed"}:
                name = "credential.cred" if failure == "credential-changed" else "config.json"
                (recovery / name).write_bytes(b"replaced")
            elif failure == "journal-lost":
                (home / "risk.jsonl").write_bytes(b"lost prefix\n")
        return ""

    monkeypatch.setattr(lifecycle, "command", command)
    if failure != "none":
        with pytest.raises(LifecycleError):
            lifecycle.after(b"d" * 64 + b"\n", reboot_required=False)
        assert json.loads(lifecycle.record_path.read_bytes())["stage"] == "awaiting-reboot"
        assert snapshot.is_file()
    else:
        lifecycle.after(b"d" * 64 + b"\n", reboot_required=False)
        result = json.loads(lifecycle.record_path.read_bytes())
        assert result["stage"] == "passed" and result["cleanup_complete"] is True
        assert "uninstall" in result["coverage"] and "supervisor-retired" not in result["coverage"]
        assert not snapshot.exists()
        assert (recovery / "credential.cred").read_bytes() == b"synthetic retained credential.cred"
    assert "uninstall" in calls
