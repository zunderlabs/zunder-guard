"""Fail closed on wrong bytes, mode, missing state and absent systemd recovery."""

import hashlib
from pathlib import Path
from typing import Any

import pytest

from guard_harness.linux_guest import Guest
from guard_harness.linux_lifecycle import (
    Inputs,
    LifecycleError,
    NativeLifecycle,
    authenticated_file,
    preserved,
    snapshot,
    wait_healthy,
)
from guard_harness.linux_testnet_service import TestnetService as ProtectedService
from guard_harness.paper_bot import LocalGuard


def test_installer_bytes_and_symlink(tmp_path: Path) -> None:
    installer = tmp_path / "install.sh"
    installer.write_bytes(b"signed installer bytes")
    digest = hashlib.sha256(installer.read_bytes()).hexdigest()
    authenticated_file(installer, digest)
    installer.write_bytes(b"changed installer bytes")
    with pytest.raises(LifecycleError, match="digest differs"):
        authenticated_file(installer, digest)
    alias = tmp_path / "alias"
    alias.symlink_to(installer)
    with pytest.raises(LifecycleError, match="regular file"):
        authenticated_file(alias, digest)


@pytest.mark.parametrize("digest", ["", "a" * 63, "A" * 64, "f" * 65])
def test_authentication_rejects_malformed_digest(tmp_path: Path, digest: str) -> None:
    with pytest.raises(LifecycleError, match="shape"):
        authenticated_file(tmp_path / "missing", digest)


def test_snapshot_hashes_but_does_not_expose_configuration(tmp_path: Path) -> None:
    config = tmp_path / "guard.toml"
    config.write_text("private pairing/config bytes")
    hashes = snapshot(tmp_path)
    assert hashes == {"guard.toml": hashlib.sha256(config.read_bytes()).hexdigest()}
    assert "private" not in repr(hashes)
    config.write_text("replaced")
    with pytest.raises(LifecycleError, match="changed persistent state"):
        preserved(hashes, snapshot(tmp_path))


def test_snapshot_rejects_symlink(tmp_path: Path) -> None:
    (tmp_path / "guard.toml").write_text("config")
    (tmp_path / "journal").symlink_to(tmp_path / "guard.toml")
    with pytest.raises(LifecycleError, match="symlink"):
        snapshot(tmp_path)


def test_paper_health_rejects_other_network(monkeypatch: pytest.MonkeyPatch) -> None:
    guard = LocalGuard("http://127.0.0.1:8547")
    monkeypatch.setattr(guard, "request", lambda _: {"mode": "testnet", "last_sync_ms": 1})
    with pytest.raises(LifecycleError, match="another mode"):
        wait_healthy(guard, pause=lambda _: None)


def test_paper_health_requires_initial_account_sync(monkeypatch: pytest.MonkeyPatch) -> None:
    guard = LocalGuard("http://127.0.0.1:8547")
    monkeypatch.setattr(guard, "request", lambda _: {"mode": "paper", "last_sync_ms": None})
    with pytest.raises(LifecycleError, match="deadline"):
        wait_healthy(guard, timeout=0, pause=lambda _: None)


def test_journal_recovery_requires_each_observed_decision(monkeypatch: pytest.MonkeyPatch) -> None:
    lifecycle = object.__new__(NativeLifecycle)
    lifecycle.guard = LocalGuard("http://127.0.0.1:8547")
    monkeypatch.setattr(lifecycle.guard, "request", lambda _: [{"seq": 3}, {"seq": 5}])
    lifecycle.recover([3, 5])
    with pytest.raises(LifecycleError, match="every paper decision"):
        lifecycle.recover([3, 4, 5])


def test_kvm_is_required_for_real_guest_tier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("guard_harness.linux_guest.os.access", lambda *args: False)
    guest = Guest(tmp_path, tmp_path)
    with pytest.raises(LifecycleError, match="requires KVM"):
        guest.prepare("a" * 32)


def test_failed_reboot_never_emits_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    inputs = Inputs(
        tmp_path / "candidate",
        "a" * 64,
        tmp_path / "previous",
        "b" * 64,
        "v1.0.0-rc.3",
        "v1.0.0-rc.2",
        "zr1_rules",
        "0x" + "1" * 40,
        tmp_path,
        "a" * 32,
    )
    lifecycle = object.__new__(NativeLifecycle)
    lifecycle.inputs = inputs
    boot = "same-boot"
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda *args, **kwargs: boot if str(args[0]).endswith("boot_id") else "{}",
    )
    record: dict[str, Any] = {
        "stage": "awaiting-reboot",
        "boot_id": boot,
        "installer_sha256": "a" * 64,
        "previous_installer_sha256": "b" * 64,
    }
    monkeypatch.setattr("guard_harness.linux_lifecycle.json.loads", lambda _: record)
    with pytest.raises(LifecycleError, match="reboot not observed"):
        lifecycle.after_reboot()
    assert record["stage"] == "awaiting-reboot"


def test_testnet_setup_refuses_outside_disposable_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = ProtectedService(
        tmp_path / "installer", "a" * 64, "0x" + "1" * 40, "zr1_rules", 18547, tmp_path, "a" * 32
    )
    monkeypatch.setattr("guard_harness.linux_testnet_service.os.geteuid", lambda: 1000)
    with pytest.raises(LifecycleError, match="root systemd"):
        service.setup(b"a" * 64 + b"\n")


@pytest.mark.parametrize("encrypted", [True, False])
def test_testnet_service_never_places_key_in_argv_or_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, encrypted: bool
) -> None:
    service = ProtectedService(
        tmp_path / "installer", "a" * 64, "0x" + "1" * 40, "zr1_rules", 18547, tmp_path, "a" * 32
    )
    key = b"b" * 64 + b"\n"
    observed: list[dict[str, Any]] = []

    def fake_run(argv: list[str], **kwargs: Any) -> None:
        assert key.decode().strip() not in repr(argv)
        assert key.decode().strip() not in repr(kwargs["env"])
        assert kwargs["stdin"] == key
        assert kwargs["sensitive_output"] is True
        assert "/usr/sbin" in kwargs["env"]["PATH"].split(":")
        assert "--key-stdin" in argv and "--key-file" not in argv
        observed.append(kwargs)

    def fake_read(path: Path, *args: Any, **kwargs: Any) -> str:
        if path.name == "zunder-native-disposable":
            return "a" * 32
        credential = "LoadCredentialEncrypted=" if encrypted else "LoadCredential="
        return credential + "wallet:credential\nExecStart=guard run --network testnet --key-stdin\n"

    monkeypatch.setattr("guard_harness.linux_testnet_service.os.geteuid", lambda: 0)
    monkeypatch.setattr(Path, "is_dir", lambda _: True)
    monkeypatch.setattr(Path, "is_file", lambda _: True)
    monkeypatch.setattr(Path, "read_text", fake_read)
    monkeypatch.setattr(Path, "exists", lambda _: False)
    monkeypatch.setattr(
        "guard_harness.linux_testnet_service.authenticated_file", lambda *args: None
    )
    monkeypatch.setattr("guard_harness.linux_testnet_service.run", fake_run)
    if encrypted:
        result = service.setup(key)
        assert result["url"] == "http://127.0.0.1:18547"
        assert result["unit"] == "zunder-guard-testnet.service"
        assert key.decode().strip() not in repr(result)
    else:
        with pytest.raises(LifecycleError, match="not encrypted"):
            service.setup(key)
    assert len(observed) == 1
