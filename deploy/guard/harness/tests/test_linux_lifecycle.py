"""Fail closed on wrong bytes, mode, missing state and absent systemd recovery."""

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from guard_harness.linux_container_lifecycle import ContainerLifecycle
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


@pytest.mark.parametrize("mutation", [None, "mode", "account", "journal"])
def test_container_status_uses_image_listen_without_url_and_preserves_admission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str | None
) -> None:
    inputs = Inputs(
        tmp_path / "candidate",
        "a" * 64,
        tmp_path / "previous",
        "b" * 64,
        "v1.2.3",
        "v1.2.2",
        "rules",
        "0x" + "1" * 40,
        tmp_path,
        "a" * 32,
    )
    instance = object.__new__(ContainerLifecycle)
    instance.inputs = inputs
    instance.guard = LocalGuard("http://127.0.0.1:8547")
    image = "ghcr.io/zunderlabs/zunder-guard@sha256:" + "c" * 64
    monkeypatch.setattr(instance, "image", lambda: image)
    monkeypatch.setattr("guard_harness.linux_lifecycle.wait_healthy", lambda guard: None)
    status: dict[str, Any] = {
        "version": "1.2.3",
        "network": "paper",
        "account": inputs.account,
        "mode": "paper",
        "halted": False,
        "kill_switch": False,
        "journal": {"ok": True},
        "licence": {
            "state": "none",
            "licensee": None,
            "expires_at_ms": None,
            "fee_free": False,
            "source": "file",
        },
    }
    if mutation == "mode":
        status["mode"] = "testnet"
    elif mutation == "account":
        status["account"] = "0x" + "2" * 40
    elif mutation == "journal":
        status["journal"] = {"ok": False}
    captured: list[list[str]] = []

    def command(name: str, words: list[str]) -> str:
        assert name == "status"
        captured.append(words)
        return json.dumps(status)

    monkeypatch.setattr(instance, "command", command)
    if mutation is None:
        instance.healthy()
    else:
        with pytest.raises(LifecycleError, match="journal|account"):
            instance.healthy()
    assert len(captured) == 1
    assert "--network=host" in captured[0]
    assert captured[0][-3:] == [image, "status", "--json"]
    assert "--url" not in captured[0]
    assert not any("ZUNDER_GUARD_LISTEN" in word for word in captured[0])


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


@pytest.mark.parametrize("tamper", [False, True])
def test_candidate_runtime_version_also_binds_installed_binary_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tamper: bool
) -> None:
    from guard_harness import linux_lifecycle as source

    binary = tmp_path / "binary"
    binary.write_bytes(b"released candidate")
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    value = Inputs(
        tmp_path / "candidate",
        "a" * 64,
        tmp_path / "previous",
        "b" * 64,
        "v1.2.3",
        "v1.2.2",
        "rules",
        "0x" + "1" * 40,
        tmp_path,
        "a" * 32,
        binary_sha256=digest,
    )
    instance = object.__new__(NativeLifecycle)
    instance.inputs = value
    monkeypatch.setattr(source, "BINARY", binary)
    monkeypatch.setattr(instance, "command", lambda *a: "zunder-guard 1.2.3")
    if tamper:
        binary.write_bytes(b"same version; altered executable")
        with pytest.raises(LifecycleError, match="digest differs"):
            instance.version("v1.2.3")
    else:
        instance.version("v1.2.3")


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
        "scenario": "upgrade",
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


@pytest.mark.parametrize("scenario,expected", [("fresh", "candidate"), ("upgrade", "previous")])
def test_fresh_and_upgrade_initial_bytes_are_distinct(
    tmp_path: Path, scenario: str, expected: str
) -> None:
    inputs = Inputs(
        tmp_path / "candidate",
        "a" * 64,
        tmp_path / "previous",
        "b" * 64,
        "v1.2.3",
        "v1.2.2",
        "rules",
        "0x" + "1" * 40,
        tmp_path,
        "a" * 32,
        scenario=scenario,
    )
    assert inputs.initial[0] == tmp_path / expected
    assert inputs.initial[1] == ("a" if scenario == "fresh" else "b") * 64
    assert inputs.initial[2] == ("v1.2.3" if scenario == "fresh" else "v1.2.2")


def test_guest_scenarios_keep_independent_disks_and_evidence_arguments(tmp_path: Path) -> None:
    from guard_harness.linux_guest import scenario_arguments

    words = [
        "--candidate",
        "signed-current",
        "--previous",
        "signed-old",
        "--scenario",
        "both",
        "--output",
        str(tmp_path),
        "--testnet-lifecycle",
    ]
    for scenario in ("fresh", "upgrade"):
        args = scenario_arguments(words, scenario, tmp_path / scenario)
        assert args.count("--scenario") == args.count("--output") == 1
        assert args[args.index("--scenario") + 1] == scenario
        assert args[args.index("--output") + 1] == str(tmp_path / scenario)
        assert args[args.index("--candidate") + 1] == "signed-current"
        assert "--testnet-lifecycle" in args


@pytest.mark.parametrize("scenario", ["fresh", "upgrade"])
def test_initial_lifecycle_installs_selected_release_before_pair_crash_reboot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scenario: str
) -> None:
    from types import SimpleNamespace

    from guard_harness import linux_lifecycle as source
    from guard_harness.cli import Pair

    inputs = Inputs(
        tmp_path / "candidate",
        "a" * 64,
        tmp_path / "previous",
        "b" * 64,
        "v1.2.3",
        "v1.2.2",
        "rules",
        "0x" + "1" * 40,
        tmp_path,
        "a" * 32,
        scenario=scenario,
    )
    instance = object.__new__(NativeLifecycle)
    instance.inputs = inputs
    instance.guard = LocalGuard("http://127.0.0.1:8547")
    pair = Pair("0x" + "c" * 40, "0x" + "d" * 64)
    instance.cli = SimpleNamespace(pair=lambda: pair)  # type: ignore[assignment]
    observed: list[Any] = []
    monkeypatch.setattr(source, "HOME", tmp_path / "fresh-home")
    monkeypatch.setattr(source, "BINARY", tmp_path / "fresh-binary")
    monkeypatch.setattr(instance, "install", lambda name, path: observed.append(("install", path)))
    monkeypatch.setattr(instance, "version", lambda version: observed.append(("version", version)))
    monkeypatch.setattr(instance, "healthy", lambda: observed.append("healthy"))
    monkeypatch.setattr(instance, "command", lambda *a, **k: "")
    monkeypatch.setattr(instance, "keep_pair", lambda value: observed.append(("pair", value)))
    monkeypatch.setattr(instance, "recover", lambda seqs: observed.append(("recover", seqs)))
    monkeypatch.setattr(
        source, "round_trip", lambda *a: [SimpleNamespace(seq=1), SimpleNamespace(seq=2)]
    )

    def control(name: str, *args: str) -> str:
        observed.append(name)
        return (
            "123"
            if name == "pid-before-crash"
            else "456"
            if name == "pid-after-crash"
            else "enabled"
        )

    monkeypatch.setattr(instance, "systemctl", control)
    original_read = Path.read_text
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda path, *a, **k: (
            "synthetic-boot" if str(path).endswith("/boot_id") else original_read(path, *a, **k)
        ),
    )
    instance.before_reboot()
    record = __import__("json").loads((tmp_path / "linux-lifecycle.json").read_bytes())
    assert observed[0] == ("install", inputs.initial[0])
    assert observed[1] == ("version", inputs.initial[2])
    assert observed.index(("pair", pair)) < observed.index("crash")
    assert record["scenario"] == scenario and record["stage"] == "awaiting-reboot"
    assert record["initial_release"] == {
        "version": inputs.initial[2],
        "installer_sha256": inputs.initial[1],
    }


@pytest.mark.parametrize("scenario", ["fresh", "upgrade"])
def test_post_reboot_reuses_original_pair_for_every_candidate_roundtrip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scenario: str
) -> None:
    from types import SimpleNamespace

    from guard_harness import linux_channels
    from guard_harness import linux_lifecycle as source
    from guard_harness.cli import Pair

    inputs = Inputs(
        tmp_path / "candidate",
        "a" * 64,
        tmp_path / "previous",
        "b" * 64,
        "v1.2.3",
        "v1.2.2",
        "rules",
        "0x" + "1" * 40,
        tmp_path,
        "a" * 32,
        scenario=scenario,
    )
    instance = object.__new__(NativeLifecycle)
    instance.inputs = inputs
    instance.guard = LocalGuard("http://127.0.0.1:8547")
    original_pair = Pair("0x" + "c" * 40, "0x" + "d" * 64)
    private = tmp_path / "private-pair"
    private.touch()
    home = tmp_path / "retained-home"
    home.mkdir()
    (home / "guard.toml").write_bytes(b"original paired config")
    monkeypatch.setattr(source, "HOME", home)
    monkeypatch.setattr(source, "BINARY", tmp_path / "removed-binary")
    record = dict(
        stage="awaiting-reboot",
        scenario=scenario,
        boot_id="old",
        installer_sha256="a" * 64,
        previous_installer_sha256="b" * 64,
        decision_seqs=[1, 2],
    )
    (tmp_path / "linux-lifecycle.json").write_text(json.dumps(record))
    observed: list[Any] = []
    monkeypatch.setattr(instance, "restored_pair", lambda: original_pair)
    monkeypatch.setattr(instance, "private_pair", lambda: private)
    monkeypatch.setattr(instance, "version", lambda version: observed.append(("version", version)))
    monkeypatch.setattr(instance, "healthy", lambda: None)
    monkeypatch.setattr(instance, "systemctl", lambda name, *a: observed.append(name))
    monkeypatch.setattr(instance, "install", lambda name, path, **k: observed.append((name, path)))
    monkeypatch.setattr(instance, "command", lambda *a: "")
    monkeypatch.setattr(instance, "recover", lambda seqs: None)
    monkeypatch.setattr(linux_channels, "curl_receipt", lambda value, execution: None)
    monkeypatch.setattr(linux_channels, "website_install", lambda value: {})
    monkeypatch.setattr(linux_channels, "manual", lambda value: None)
    reads = Path.read_text
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda path, *a, **k: "new" if str(path).endswith("/boot_id") else reads(path, *a, **k),
    )
    pairs: list[Pair] = []

    def roundtrip(guard: LocalGuard, pair: Pair) -> list[Any]:
        pairs.append(pair)
        return [SimpleNamespace(seq=2 + len(pairs))]

    monkeypatch.setattr(source, "round_trip", roundtrip)
    instance.after_reboot()
    steps = [
        event[0]
        for event in observed
        if isinstance(event, tuple) and event[0] in {"upgrade", "reinstall"}
    ]
    assert steps == (["upgrade", "reinstall"] if scenario == "upgrade" else ["reinstall"])
    assert pairs == [original_pair] * len(steps)
    assert observed[0] == ("version", inputs.initial[2])
    receipt = json.loads((tmp_path / "linux-lifecycle.json").read_bytes())
    from guard_harness.install_evidence import PAPER, completed

    required = (
        PAPER
        if scenario == "upgrade"
        else PAPER - {"upgrade", "paper-post-upgrade-allow-resize-veto"} | {"fresh-candidate-paper"}
    )
    required |= {"kernel-reboot"}
    assert completed(receipt, required, mode="paper") == required
    assert receipt["result"] == "passed" and len(receipt["decision_seqs"]) == 2 + len(steps)
    assert not private.exists() and (home / "guard.toml").read_bytes() == b"original paired config"


@pytest.mark.parametrize("fail_locked_install", [False, True])
def test_guest_requires_hashed_binary_dependencies_and_locked_build_tools_before_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fail_locked_install: bool
) -> None:
    import subprocess
    from typing import cast

    guest = Guest(tmp_path, tmp_path)
    observed: list[str] = []
    monkeypatch.setattr(guest, "wait", lambda *args, **kwargs: "boot")

    def remote(command: str, **kwargs: Any) -> str:
        observed.append(command)
        if " -m pip install " in command:
            assert "--require-hashes --only-binary=:all:" in command
            assert "harness/requirements-runtime.lock && " in command
            assert "--no-deps --no-build-isolation" in command
            if fail_locked_install:
                raise RuntimeError("locked install refused")
        return "boot"

    def private(command: str, key: bytes, **kwargs: Any) -> str:
        assert any("--require-hashes" in entry for entry in observed)
        assert key == b"a" * 64 + b"\n"
        observed.append("private lifecycle input")
        return ""

    monkeypatch.setattr(guest, "remote", remote)
    monkeypatch.setattr(guest, "private_remote", private)
    monkeypatch.setattr(guest, "testnet_command", lambda args: "released protected service")
    if fail_locked_install:
        with pytest.raises(RuntimeError, match="locked install"):
            guest.exercise(
                [], cast(subprocess.Popen[bytes], object()), testnet_key=b"a" * 64 + b"\n"
            )
        assert "private lifecycle input" not in observed
    else:
        guest.exercise([], cast(subprocess.Popen[bytes], object()), testnet_key=b"a" * 64 + b"\n")
        assert observed.count("private lifecycle input") == 2
