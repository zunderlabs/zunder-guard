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
from guard_harness.linux_lifecycle import ROOT_PATH, LifecycleError
from guard_harness.linux_testnet_lifecycle import (
    TestnetLifecycle as ProtectedLifecycle,
)
from guard_harness.linux_testnet_lifecycle import (
    no_exchange,
    preserved,
    retained,
)
from guard_harness.runner import RunResult
from guard_harness.testnet_scan import SCAN_TIMEOUT, ScanError


@pytest.fixture(autouse=True)
def no_hosted_opt_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    """The hosted /opt step reads the real machine; these unit tests never depend on it.

    On a GitHub-hosted runner /opt is 0777, so the step switched itself on inside unrelated
    lifecycle tests (public ci on rc.16). Tests of the step itself patch it back on.
    """
    monkeypatch.setattr("guard_harness.linux_policy.eligible", lambda: False)


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
def test_uncertain_runtime_audit_never_mutates_or_removes_service(
    monkeypatch: pytest.MonkeyPatch, action: str
) -> None:
    lifecycle = object.__new__(ProtectedLifecycle)
    lifecycle.unit = "synthetic-testnet.service"

    def unknown() -> None:
        raise ScanError("testnet HTTP/JSON read failed")

    monkeypatch.setattr(lifecycle, "audit", unknown)
    monkeypatch.setattr(lifecycle, "command", lambda *args: pytest.fail("no mutation authorized"))
    with pytest.raises(ScanError):
        lifecycle.control("fixture", action)


@pytest.mark.parametrize("mutation", ["none", "account", "binary", "action"])
def test_same_scenario_controls_require_real_identity_and_complete_journal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    lifecycle = object.__new__(ProtectedLifecycle)
    lifecycle.home = tmp_path
    lifecycle.route = "native"
    lifecycle.unit = "synthetic-testnet.service"
    account = "0x" + "1" * 40
    lifecycle.inputs = cast(Any, SimpleNamespace(account=account))
    lifecycle.binary = tmp_path / "guard-fixture"
    lifecycle.binary.write_bytes(b"candidate bytes")
    digest = hashlib.sha256(lifecycle.binary.read_bytes()).hexdigest()
    lifecycle.admitted_release = ("v1.2.3", digest, "")
    (tmp_path / "guard.toml").write_text(
        'mode="testnet"\nnetwork="testnet"\naccount="' + account + '"\n'
    )
    events: list[dict[str, Any]] = [{"kind": "started", "mode": "testnet"}]
    if mutation == "account":
        (tmp_path / "guard.toml").write_text('mode="testnet"\nnetwork="testnet"\naccount="x"')
    elif mutation == "binary":
        lifecycle.binary.write_bytes(b"altered executable")
    elif mutation == "action":
        events.append({"kind": "intent"})
    journal(tmp_path, events)
    calls: list[list[str]] = []

    def command(label: str, argv: list[str]) -> str:
        calls.append(argv)
        return "zunder-guard 1.2.3" if label == "audit-version" else ""

    monkeypatch.setattr(lifecycle, "command", command)
    monkeypatch.setattr(lifecycle, "flat", lambda: pytest.fail("audit is not venue-flat proof"))
    if mutation != "none":
        with pytest.raises(LifecycleError):
            lifecycle.control("restart", "restart")
        assert not any(argv[0] == "systemctl" for argv in calls)
    else:
        lifecycle.control("restart", "restart")
        assert calls[-1] == ["systemctl", "restart", lifecycle.unit]


def test_failed_preflight_prevents_initial_custody_and_upgrade(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    lifecycle = object.__new__(ProtectedLifecycle)
    monkeypatch.setattr(lifecycle, "flat", lambda: (_ for _ in ()).throw(ScanError("unknown")))
    monkeypatch.setattr(lifecycle, "command", lambda *a: pytest.fail("no install after unknown"))
    for initial in (True, False):
        with pytest.raises(ScanError):
            lifecycle.install(tmp_path / "installer", "a" * 64, b"b" * 64 + b"\n", initial=initial)


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
        assert timeout == SCAN_TIMEOUT + 120
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


@pytest.mark.parametrize("container,fresh", [(True, True), (True, False), (False, True)])
def test_container_installer_stdin_consumption_matches_released_setup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, container: bool, fresh: bool
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
    dropin = mapped("/etc/systemd/system/zunder-guard-testnet.service.d/10-install.conf")
    dropin.parent.mkdir(parents=True)
    dropin.write_text("LoadCredentialEncrypted=fixture\n--key-stdin --network testnet")
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
            assert kwargs["stdin"] == key * (2 if container and fresh else 1)
            assert kwargs["secrets"] == [key.decode().strip()]
            assert ("--container" in argv) is container and "--key-stdin" in argv
            assert ("--listen" in argv) is not container
            for setup_choice in ("--rules", "--equity-cap", "--ip-share"):
                assert (setup_choice in argv) is fresh
            if fresh:
                assert argv[argv.index("--ip-share") + 1] == "1"
                assert argv[argv.index("--equity-cap") + 1] == "40"
                assert argv[argv.index("--rules") + 1] == "synthetic-rules"
            if not container:
                assert argv[argv.index("--service-instance") + 1] == "testnet"
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
        8547 if container else 18548,
        tmp_path,
        "a" * 32,
        container=container,
    )
    expected = "zunder-guard-container.service" if container else "zunder-guard-testnet.service"
    assert service.setup(key)["unit"] == expected
    assert len(calls) == (2 if container else 1)


@pytest.mark.parametrize(
    "failure",
    [
        "none",
        "credential-changed",
        "config-changed",
        "broken-unit",
        "journal-lost",
        "volume-lost",
        "refusal-stopped",
        "refusal-gate-changed",
        "unknown-helper",
    ],
)
def test_container_uninstall_credit_requires_recovery_preservation_and_absent_software(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    root = tmp_path / "root"

    def mapped(*parts: str) -> Path:
        path = Path(*parts)
        return path if path.is_relative_to(root) else root / path.as_posix().lstrip("/")

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
    (recovery / "managed-install.json").write_text(
        json.dumps({"allowed_files": {file: ["a" * 64] for file in owned[:5]}})
    )
    if failure == "unknown-helper":
        mapped("/usr/local/libexec/zunder-guard-container/unknown-helper.py").write_bytes(
            b"unexpected helper"
        )
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
            output=tmp_path,
            installer=tmp_path / "released-install.sh",
            installer_sha256="a" * 64,
            previous_installer_sha256="b" * 64,
            version="v1.2.3",
            previous_version="v1.2.2",
            scenario="upgrade",
            initial=(tmp_path / "previous.sh", "b" * 64, "v1.2.2"),
        ),
    )
    lifecycle.binary_sha256 = lifecycle.previous_binary_sha256 = "c" * 64
    lifecycle.image = lifecycle.previous_image = "synthetic immutable descriptor"
    lifecycle.record_path = tmp_path / "testnet-lifecycle.json"
    lifecycle.record_path.write_text(
        json.dumps(
            {
                "stage": "awaiting-reboot",
                "scenario": "upgrade",
                "boot_id": "synthetic boot",
                "installer_sha256": "a" * 64,
                "previous_installer_sha256": "b" * 64,
            }
        )
    )
    monkeypatch.setattr(lifecycle, "audit", lambda: None)

    def refusal(words: list[str]) -> None:
        if failure == "refusal-gate-changed":
            mapped("/etc/zunder-guard-container/install-transaction.json").write_bytes(b"changed")

    monkeypatch.setattr(lifecycle, "refuse_pending_uninstall", refusal)
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
        if name == "owned-fragment":
            return "/etc/systemd/system/" + argv[-1]
        if name in {"live-uninstall-pid", "refused-uninstall-pid"}:
            return "0" if failure == "refusal-stopped" and name == "refused-uninstall-pid" else "42"
        if name in {"live-uninstall-state", "refused-uninstall-state"}:
            return "active"
        if name in {"live-container-id", "refused-container-id"}:
            return "e" * 64
        if name == "removed-unit-state":
            return "not-found"
        if name == "removed-unit-pid":
            return "0"
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
            if failure != "unknown-helper":
                mapped("/usr/local/libexec/zunder-guard-container").rmdir()
            mapped("/etc/systemd/system/zunder-guard-container.service.d").rmdir()
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
        assert result["binary_sha256"] == lifecycle.binary_sha256
        assert result["previous_binary_sha256"] == lifecycle.previous_binary_sha256
        assert (
            result["image"] == lifecycle.image
            and result["previous_image"] == lifecycle.previous_image
        )
        assert result["runtime_identity_evidence"] == "signed-immutable-prebuilt-image"
        from guard_harness.install_evidence import TESTNET, completed

        required = TESTNET | {
            "uninstall-live-stop",
            "uninstall-transaction-refusal",
            "owned-software-inventory",
        }
        assert completed(result, required, mode="testnet") == required
        assert "uninstall" in result["coverage"] and "supervisor-retired" not in result["coverage"]
        assert not snapshot.exists()
        assert (recovery / "credential.cred").read_bytes() == b"synthetic retained credential.cred"
    assert ("uninstall" in calls) is (failure not in {"refusal-stopped", "refusal-gate-changed"})


@pytest.mark.parametrize(
    "code,body",
    [
        (0, b"Resolve installer transaction before uninstall."),
        (1, b"wrong refusal"),
        (1, b"Resolve installer transaction before uninstall."),
    ],
)
def test_actual_refusal_status_and_diagnostics_are_admitted_without_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: int, body: bytes
) -> None:
    lifecycle = object.__new__(ProtectedLifecycle)
    lifecycle.inputs = cast(Any, SimpleNamespace(output=tmp_path))

    def invoke(words: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        assert kwargs["stdin"] == subprocess.DEVNULL and kwargs["timeout"] == 120
        return subprocess.CompletedProcess(words, code, b"private needle", body)

    monkeypatch.setattr(subprocess, "run", invoke)
    if code == 1 and body.startswith(b"Resolve"):
        lifecycle.refuse_pending_uninstall(["released-uninstall"])
    else:
        with pytest.raises(LifecycleError):
            lifecycle.refuse_pending_uninstall(["released-uninstall"])
    assert b"private needle" not in (tmp_path / "uninstall-refusal.log").read_bytes()


@pytest.mark.parametrize(
    "kind,category",
    [
        ("error", "error"),
        ("decision", "decision"),
        ("intent", "intent"),
        ("done", "done"),
        ("sent", "sent"),
        ("recovered", "recovered"),
        ("flatten", "flatten"),
        ("protect", "protect"),
        ("kill", "kill"),
        ("private-token-sentinel", "unknown"),
        (None, "unknown"),
        ({"private-token-sentinel": "fixture"}, "unknown"),
    ],
)
def test_authenticated_refusal_reports_only_known_kind_and_bounded_sequence(
    tmp_path: Path, kind: Any, category: str
) -> None:
    account = "0x" + "a" * 40
    journal(
        tmp_path,
        [
            {"kind": "started", "mode": "testnet"},
            {
                "kind": kind,
                "text": "private-token-sentinel",
                "account": account,
                "action": {"private-payload-sentinel": "fixture"},
            },
        ],
    )
    with pytest.raises(LifecycleError) as caught:
        no_exchange(tmp_path)
    text = str(caught.value)
    assert text.endswith(f"(kind={category}, seq=2)")
    assert all(private not in text for private in [account, "private-token", "private-payload"])


@pytest.mark.parametrize("tamper", ["check", "prev", "seq"])
def test_unvalidated_record_cannot_claim_observed_kind(tmp_path: Path, tamper: str) -> None:
    journal(tmp_path, [{"kind": "started", "mode": "testnet"}, {"kind": "error"}])
    path = tmp_path / "decisions.jsonl"
    records = [json.loads(line) for line in path.read_text().splitlines()]
    if tamper == "seq":
        records[1]["event"]["seq"] = 99999
    else:
        records[1][tamper] = "private-token-sentinel"
    path.write_text("\n".join(json.dumps(record) for record in records) + "\n")
    with pytest.raises(LifecycleError) as caught:
        no_exchange(tmp_path)
    assert "kind=" not in str(caught.value) and "seq=" not in str(caught.value)
    assert "private-token" not in str(caught.value)


def test_validated_large_sequence_stays_unknown_in_refusal(tmp_path: Path) -> None:
    journal(tmp_path, [{"kind": "started", "mode": "testnet"}] * 4096 + [{"kind": "error"}])
    with pytest.raises(LifecycleError, match=r"kind=error, seq=unknown"):
        no_exchange(tmp_path)


@pytest.mark.parametrize(
    "body,category",
    [
        ("reading the account: private-sentinel", "account-read"),
        (
            "reading the account: HIP-3 dex private-sentinel could not be read; its positions "
            "go unprotected by Guard until it can be, and no entry is judged",
            "account-dex-read",
        ),
        (
            "the decision journal ended in writes a crash cut short (never synced, so nothing "
            "was sent on their strength): 12 bytes moved to /private-sentinel",
            "crash-cut-journal",
        ),
        (
            "the account's ledger has an entry Guard cannot account for (private-sentinel)",
            "unaccounted-ledger",
        ),
        ("account-flow arithmetic cannot be represented: private-sentinel", "flow-arithmetic"),
        ("account value at a flow is uncertain: private-sentinel", "flow-uncertain"),
        (
            "a flow of private-sentinel USDC (deposit, withdrawal or transfer) kept out of the "
            "account stops",
            "account-flow",
        ),
        (
            "positions on HIP-3 dex private-sentinel (private-sentinel), which the rules' markets "
            "do not name: Guard neither judges nor protects them, and the kill switch leaves them",
            "unmanaged-dex",
        ),
        ("private-sentinel", "unknown"),
        ({"reading the account: ": "private-sentinel"}, "unknown"),
        (None, "unknown"),
        ("reading the account: " + "private-sentinel" * 2000, "unknown"),
    ],
)
def test_error_producer_categories_remain_refused_without_private_message(
    tmp_path: Path, body: Any, category: str
) -> None:
    journal(tmp_path, [{"kind": "started", "mode": "testnet"}, {"kind": "error", "text": body}])
    with pytest.raises(LifecycleError) as caught:
        no_exchange(tmp_path)
    diagnostic = str(caught.value)
    assert f"error_category={category} (kind=error, seq=2)" in diagnostic
    assert "private-sentinel" not in diagnostic


def test_tampered_error_template_cannot_claim_producer_category(tmp_path: Path) -> None:
    journal(tmp_path, [{"kind": "started", "mode": "testnet"}, {"kind": "error", "text": "x"}])
    path = tmp_path / "decisions.jsonl"
    records = [json.loads(line) for line in path.read_text().splitlines()]
    records[1]["event"]["text"] = "reading the account: private-sentinel"
    path.write_text("\n".join(json.dumps(record) for record in records) + "\n")
    with pytest.raises(LifecycleError, match="decision checksum differs") as caught:
        no_exchange(tmp_path)
    assert "error_category=" not in str(caught.value)
    assert "private-sentinel" not in str(caught.value)


def test_typed_successful_fee_read_is_not_an_exchange(tmp_path: Path) -> None:
    event = {"kind": "fee_approval", "approved": True, "text": "builder fee approved"}
    journal(tmp_path, [{"kind": "started", "mode": "testnet"}, event])
    assert no_exchange(tmp_path) == 2


@pytest.mark.parametrize(
    "mutation",
    [
        {"approved": False},
        {"approved": 1},
        {"approved": "true"},
        {"text": None},
        {"text": ""},
        {"text": "x" * 16385},
        {"action": {}},
        {"sent": False},
    ],
)
def test_fee_notice_cannot_hide_failed_or_action_bearing_state(
    tmp_path: Path, mutation: dict[str, Any]
) -> None:
    event = {"kind": "fee_approval", "approved": True, "text": "private-sentinel"} | mutation
    journal(tmp_path, [{"kind": "started", "mode": "testnet"}, event])
    with pytest.raises(LifecycleError, match="fee approval journal event differs") as caught:
        no_exchange(tmp_path)
    assert "private-sentinel" not in str(caught.value)


def test_legacy_builder_approval_error_still_refuses_credit(tmp_path: Path) -> None:
    event = {
        "kind": "error",
        "text": "builder fee approved (private-sentinel); Guard's orders carry it",
    }
    journal(tmp_path, [{"kind": "started", "mode": "testnet"}, event])
    with pytest.raises(LifecycleError, match="error_category=fee-approved") as caught:
        no_exchange(tmp_path)
    assert "private-sentinel" not in str(caught.value)


@pytest.mark.parametrize("operation", ["crash", "install", "readiness", "PRIVATE-ACCOUNT-KEY"])
def test_lifecycle_cli_retains_finite_terminal_failure_without_credit_or_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    import io
    import sys

    from guard_harness.runner import RunError

    output = tmp_path / "evidence"
    output.mkdir(mode=0o700)
    completed: list[str] = []

    class FailedLifecycle:
        def __init__(self, inputs: Any, **kwargs: Any) -> None:
            self.operation = operation

        def before(self, key: bytes) -> None:
            assert key == b"a" * 64 + b"\n"
            raise RunError("PRIVATE-ACCOUNT-KEY raw command args/body")

        def after(self, *args: Any, **kwargs: Any) -> None:
            completed.append("after")

        def flat(self) -> None:
            pytest.fail("no new venue reads on diagnostic failure")

    argv = ["testnet-lifecycle"]
    for name, value in {
        "installer": str(tmp_path / "installer"),
        "previous-installer": str(tmp_path / "previous"),
        "output": str(output),
        "installer-sha256": "a" * 64,
        "previous-installer-sha256": "b" * 64,
        "version": "v1.0.0-rc.14",
        "previous-version": "v1.0.0-rc.13",
        "rules": "fixture",
        "account": "0x" + "1" * 40,
        "marker": "c" * 32,
        "binary-sha256": "d" * 64,
        "previous-binary-sha256": "e" * 64,
        "route": "container",
        "phase": "before-reboot",
    }.items():
        argv.extend(["--" + name, value])
    monkeypatch.setattr(sys, "argv", argv)
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(b"a" * 64 + b"\n")))
    monkeypatch.setattr(linux_testnet_lifecycle, "TestnetLifecycle", FailedLifecycle)
    with pytest.raises(RunError):
        linux_testnet_lifecycle.main()
    record = output / "lifecycle-before-reboot-failure.json"
    value = json.loads(record.read_bytes())
    assert value == {
        "schema": 1,
        "result": "failed",
        "gate_eligible": False,
        "phase": "before-reboot",
        "operation": operation if operation != "PRIVATE-ACCOUNT-KEY" else "unknown",
        "failure": "command",
    }
    assert "PRIVATE" not in record.read_text() and completed == []
    assert record.stat().st_mode & 0o777 == 0o600
    assert not (output / "testnet-lifecycle.json").exists()


def test_sensitive_crash_command_failure_retains_exact_exit_and_authored_operation(
    tmp_path: Path,
) -> None:
    import sys

    from guard_harness.runner import RunError

    lifecycle = object.__new__(ProtectedLifecycle)
    lifecycle.inputs = cast(Any, SimpleNamespace(output=tmp_path))
    with pytest.raises(RunError):
        lifecycle.command(
            "crash", [sys.executable, "-c", "print('PRIVATE-BODY'); raise SystemExit(7)"]
        )
    assert lifecycle.operation == "crash"
    assert (tmp_path / "crash.log").read_text() == (
        "[sensitive command output withheld]\nexit status: 7\ncommand outcome: exited\n"
    )


def test_failure_evidence_filters_non_authored_phase_type_and_operation(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    linux_testnet_lifecycle.failure_evidence(
        tmp_path, "PRIVATE-PHASE", "PRIVATE-KEY", "PRIVATE-ERROR"
    )
    value = json.loads((tmp_path / "lifecycle-unknown-failure.json").read_bytes())
    assert value["phase"] == value["operation"] == value["failure"] == "unknown"
    assert "PRIVATE" not in json.dumps(value)


def before_crash_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, route: str, refusal: str
) -> tuple[ProtectedLifecycle, list[str]]:
    from guard_harness.runner import RunError

    lifecycle = object.__new__(ProtectedLifecycle)
    lifecycle.route, lifecycle.unit = (
        route,
        "zunder-guard-container.service"
        if route == "container"
        else "zunder-guard-testnet.service",
    )
    lifecycle.home, lifecycle.binary = tmp_path / "home", tmp_path / "binary"
    lifecycle.private = tmp_path / "private"
    lifecycle.inputs = cast(
        Any,
        SimpleNamespace(
            initial=(tmp_path / "installer", "a" * 64, "v1.0.0-rc.14"),
            scenario="fresh",
            output=tmp_path,
        ),
    )
    lifecycle.binary_sha256 = lifecycle.previous_binary_sha256 = "b" * 64
    lifecycle.image = lifecycle.previous_image = "signed-image-fixture"
    trace: list[str] = []
    healthy_calls = 0
    state_calls = 0

    def install(*args: Any, **kwargs: Any) -> None:
        trace.append("install")
        lifecycle.home.mkdir(mode=0o700)
        for name in linux_testnet_lifecycle.JOURNALS:
            (lifecycle.home / name).write_bytes(b"private retained fixture\n")

    def healthy(*args: Any) -> None:
        nonlocal healthy_calls
        healthy_calls += 1
        trace.append("healthy")
        if healthy_calls == 4 and refusal == "health":
            raise LifecycleError("public readiness fixture")

    def command(name: str, argv: list[str], **kwargs: Any) -> str:
        nonlocal state_calls
        lifecycle.operation = name
        trace.append(name)
        if name == "private-pair":
            return json.dumps({"client_address": "0x" + "1" * 40, "client_key": "0x" + "2" * 64})
        if name == "old-pid":
            return "42"
        if name == "service-state":
            state_calls += 1
            if state_calls == 2 and refusal == "snapshot-read":
                raise OSError("PRIVATE-read-failure")
            active = "inactive" if refusal == "inactive" else "active"
            sub = "auto-restart" if refusal == "restarting" else "running"
            pid = "43" if refusal == "pid-changed" else "42"
            return (
                f"ActiveState={active}\nSubState={sub}\nResult=success\nMainPID={pid}\n"
                "ExecMainCode=0\nExecMainStatus=0"
            )
        if name == "crash":
            assert argv == [
                "systemctl",
                "kill",
                "--kill-whom=main",
                "--signal=SIGKILL",
                lifecycle.unit,
            ]
            raise RunError("original fixed crash failure")
        return ""

    monkeypatch.setattr(lifecycle, "install", install)
    monkeypatch.setattr(lifecycle, "healthy", healthy)
    monkeypatch.setattr(lifecycle, "audit", lambda: trace.append("audit"))
    monkeypatch.setattr(lifecycle, "control", lambda name, action: trace.append(name))
    monkeypatch.setattr(lifecycle, "command", command)
    monkeypatch.setattr(lifecycle, "docker", lambda words, **kwargs: ["fixture-docker", *words])
    return lifecycle, trace


@pytest.mark.parametrize("route", ["native", "container"])
@pytest.mark.parametrize(
    "refusal", ["none", "health", "inactive", "restarting", "pid-changed", "snapshot-read"]
)
def test_reload_restart_requires_health_and_running_captured_pid_before_one_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, route: str, refusal: str
) -> None:
    from guard_harness.runner import RunError

    lifecycle, trace = before_crash_fixture(tmp_path, monkeypatch, route=route, refusal=refusal)
    error = RunError if refusal in {"none", "snapshot-read"} else LifecycleError
    with pytest.raises(error) as caught:
        lifecycle.before(b"a" * 64 + b"\n")
    reload_index = trace.index("reload-restart")
    assert trace[reload_index + 1] == "healthy"
    if refusal in {"none", "snapshot-read"}:
        assert trace.index("old-pid") > reload_index + 1
        assert trace.index("service-state") < trace.index("crash")
        assert trace.count("crash") == 1
        assert str(caught.value) == "original fixed crash failure"
        value = json.loads((tmp_path / "crash-service-state.json").read_bytes())
        assert value["diagnostic"] is True and value["gate_eligible"] is False
        assert value["main_pid_present"] is (True if refusal == "none" else None)
        assert value["active_state"] == ("active" if refusal == "none" else "unknown")
        assert "42" not in json.dumps(value) and "PRIVATE" not in json.dumps(value)
        assert lifecycle.operation == "crash"
    else:
        assert "crash" not in trace and not (tmp_path / "crash-service-state.json").exists()
    if refusal == "health":
        assert "old-pid" not in trace


@pytest.mark.parametrize(
    "raw",
    [
        "ActiveState=PRIVATE\nSubState=PRIVATE\nResult=PRIVATE\nMainPID=PRIVATE\nExecMainCode=PRIVATE\nExecMainStatus=PRIVATE",
        "ActiveState=active\nSubState=running\nResult=success\nMainPID=999999999999999999\nExecMainCode=999\nExecMainStatus=999",
    ],
)
def test_service_state_snapshot_never_copies_unrecognized_values_or_numeric_pid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, raw: str
) -> None:
    lifecycle = object.__new__(ProtectedLifecycle)
    lifecycle.unit = "zunder-guard-container.service"
    monkeypatch.setattr(lifecycle, "command", lambda *args, **kwargs: raw)
    state, pid = lifecycle.service_state()
    assert pid is None and state["main_pid_present"] is None
    assert state["exec_main_code"] is None and state["exec_main_status"] is None
    assert "PRIVATE" not in json.dumps(state) and "999999" not in json.dumps(state)


def diagnostic_status_body() -> bytes:
    return json.dumps(
        {
            "version": "1.0.0-rc.14",
            "network": "testnet",
            "account": "0x" + "1" * 40,
            "mode": "testnet",
            "halted": False,
            "kill_switch": False,
            "last_sync_ms": 10,
            "licence": {
                "state": "valid",
                "licensee": "PRIVATE-EMAIL",
                "expires_at_ms": None,
                "fee_free": False,
                "source": "file",
            },
            "journal": {"ok": True},
            "extra": "PRIVATE-KEY-BODY",
        }
    ).encode()


@pytest.mark.parametrize(
    "route,initial", [("native", True), ("container", True), ("container", False)]
)
@pytest.mark.parametrize(
    "observer", ["ready", "read-failed", "http-failed", "bad-json", "write-failed"]
)
def test_initial_install_failure_retains_only_typed_unit_and_local_read_diagnostics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, observer: str, route: str, initial: bool
) -> None:
    import urllib.error

    from guard_harness.runner import RunError

    lifecycle = object.__new__(ProtectedLifecycle)
    lifecycle.route, lifecycle.unit, lifecycle.port = (
        route,
        "zunder-guard-container.service"
        if route == "container"
        else "zunder-guard-testnet.service",
        18548,
    )
    lifecycle.guard = cast(Any, SimpleNamespace(url="http://127.0.0.1:18548"))
    lifecycle.inputs = cast(
        Any,
        SimpleNamespace(account="0x" + "1" * 40, rules="fixture", marker="a" * 32, output=tmp_path),
    )
    trace: list[str] = []
    calls: list[tuple[str, float]] = []

    def setup(self: Any, key: bytes) -> dict[str, str]:
        trace.append("setup")
        assert key == b"a" * 64 + b"\n"
        raise RunError("original fixed initial install failure")

    def command(name: str, argv: list[str], **kwargs: Any) -> str:
        assert name == "service-state" and kwargs["timeout"] == 5
        assert argv == [
            "systemctl",
            "show",
            "--property=ActiveState",
            "--property=SubState",
            "--property=Result",
            "--property=MainPID",
            "--property=ExecMainCode",
            "--property=ExecMainStatus",
            lifecycle.unit,
        ]
        if observer == "read-failed":
            raise OSError("PRIVATE-provider-error")
        return (
            "ActiveState=activating\nSubState=auto-restart\nResult=exit-code\nMainPID=0\n"
            "ExecMainCode=1\nExecMainStatus=1"
        )

    def read(url: str, data: bytes | None, *, timeout: float) -> bytes:
        assert data is None and 0 < timeout <= 2
        calls.append((url, timeout))
        if observer == "http-failed":
            raise urllib.error.URLError("PRIVATE-network-body")
        if observer == "bad-json":
            return b"PRIVATE-malformed-body"
        return b'{"ok":false}' if url.endswith("/healthz") else diagnostic_status_body()

    monkeypatch.setattr(lifecycle, "flat", lambda: trace.append("flat"))
    monkeypatch.setattr(lifecycle, "command", command)
    monkeypatch.setattr(linux_testnet_service.TestnetService, "setup", setup)
    monkeypatch.setattr(linux_testnet_lifecycle, "bounded_read", read)
    if observer == "write-failed":
        (tmp_path / "install-service-state.json").mkdir()
    with pytest.raises(RunError, match="original fixed initial install failure"):
        lifecycle.install(tmp_path / "installer", "b" * 64, b"a" * 64 + b"\n", initial=initial)
    assert trace == ["flat", "setup"] and lifecycle.operation == "install"
    assert [url for url, _ in calls] == [
        "http://127.0.0.1:18548/healthz",
        "http://127.0.0.1:18548/guard/status",
    ]
    if observer == "write-failed":
        return
    path = tmp_path / "install-service-state.json"
    state = json.loads(path.read_bytes())
    assert state["diagnostic"] is True and state["gate_eligible"] is False
    if route == "native":
        assert state["service_host_opt"] == linux_testnet_service.opt_metadata()
    else:
        assert "service_host_opt" not in state
    assert "PRIVATE" not in path.read_text() and "account" not in state
    assert path.stat().st_mode & 0o777 == 0o600
    assert state["active_state"] == ("unknown" if observer == "read-failed" else "activating")
    assert state["exec_main_code"] == (None if observer == "read-failed" else 1)
    assert state["exec_main_status"] == (None if observer == "read-failed" else 1)
    status = state["local_http"]["status"]
    if observer in {"ready", "read-failed"}:
        assert status == {
            "transport": "response",
            "http": "success",
            "json": "valid",
            "mode_network_match": True,
            "last_sync_present": True,
            "halted": False,
            "journal_ok": True,
        }
    elif observer == "bad-json":
        assert status["json"] == "invalid" and status["mode_network_match"] is None
    else:
        assert status["http"] == "unknown" and status["json"] == "unknown"


def test_local_failure_observations_never_start_second_read_after_shared_short_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lifecycle = object.__new__(ProtectedLifecycle)
    lifecycle.guard = cast(Any, SimpleNamespace(url="http://127.0.0.1:18548"))
    clock = [0.0]
    calls: list[str] = []
    monkeypatch.setattr("guard_harness.linux_testnet_lifecycle.time.monotonic", lambda: clock[0])

    def read(url: str, data: bytes | None, *, timeout: float) -> bytes:
        calls.append(url)
        assert timeout == 2
        clock[0] = 4.0
        return b"{}"

    monkeypatch.setattr(linux_testnet_lifecycle, "bounded_read", read)
    value = lifecycle.local_failure_observations()
    assert calls == ["http://127.0.0.1:18548/healthz"]
    assert value["status"]["transport"] == "unknown"


@pytest.mark.parametrize(
    "mutation", ["string-halted", "bool-stamp", "negative-stamp", "string-journal"]
)
def test_local_status_diagnostic_has_no_untyped_predicate_values(
    monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    value = json.loads(diagnostic_status_body())
    if mutation == "string-halted":
        value["halted"] = "PRIVATE"
    elif mutation == "bool-stamp":
        value["last_sync_ms"] = True
    elif mutation == "negative-stamp":
        value["last_sync_ms"] = -1
    else:
        value["journal"]["ok"] = "PRIVATE"
    lifecycle = object.__new__(ProtectedLifecycle)
    lifecycle.guard = cast(Any, SimpleNamespace(url="http://127.0.0.1:18548"))
    monkeypatch.setattr(
        linux_testnet_lifecycle, "bounded_read", lambda *args, **kwargs: json.dumps(value).encode()
    )
    observed = lifecycle.local_failure_observations()["status"]
    assert "PRIVATE" not in json.dumps(observed)
    if mutation in {"bool-stamp", "negative-stamp"}:
        assert observed["last_sync_present"] is None
    else:
        assert observed["json"] == "invalid" and observed["halted"] is None


@pytest.mark.parametrize(
    "code,status,expected",
    [
        ("0", "0", (0, 0)),
        ("1", "1", (1, 1)),
        ("2", "9", (2, 9)),
        ("6", "255", (6, 255)),
        ("7", "256", (None, None)),
        ("-1", "-1", (None, None)),
        ("PRIVATE-KEY-BYTES", "PRIVATE-KEY-BYTES", (None, None)),
        ("0" * 8192, "0" * 8192, None),
    ],
    ids=["zero", "exit", "signal", "upper", "outside", "negative", "private", "oversized"],
)
def test_systemd_exit_metadata_is_nullable_and_finitely_bounded(
    monkeypatch: pytest.MonkeyPatch, code: str, status: str, expected: tuple[int, int] | None
) -> None:
    lifecycle = object.__new__(ProtectedLifecycle)
    lifecycle.unit = "zunder-guard-testnet.service"
    raw = (
        "ActiveState=failed\nSubState=failed\nResult=exit-code\nMainPID=0\n"
        f"ExecMainCode={code}\nExecMainStatus={status}"
    )
    monkeypatch.setattr(lifecycle, "command", lambda *args, **kwargs: raw)
    if expected is None:
        with pytest.raises(LifecycleError, match="service state exceeds bound"):
            lifecycle.service_state()
        return
    observed, _ = lifecycle.service_state()
    assert (observed["exec_main_code"], observed["exec_main_status"]) == expected
    assert "PRIVATE" not in json.dumps(observed)


def test_service_state_command_wholly_withholds_private_stdout_and_stderr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lifecycle = object.__new__(ProtectedLifecycle)
    lifecycle.unit = "zunder-guard-testnet.service"
    lifecycle.inputs = cast(Any, SimpleNamespace(output=tmp_path))
    private = "PRIVATE-KEY-BYTES-" + "b" * 64
    raw = (
        f"ActiveState={private}\nSubState=failed\nResult=exit-code\nMainPID=0\n"
        f"ExecMainCode={private}\nExecMainStatus={private}"
    )

    def child(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        assert argv[0:2] == ["systemctl", "show"] and argv[-1] == lifecycle.unit
        assert kwargs["timeout"] == 5 and kwargs["input"] is None
        assert kwargs["env"] == {"PATH": ROOT_PATH, "HOME": "/root"}
        return subprocess.CompletedProcess(argv, 0, raw.encode(), private.encode())

    monkeypatch.setattr(subprocess, "run", child)
    observed, _ = lifecycle.service_state()
    assert observed["active_state"] == "unknown"
    assert observed["exec_main_code"] is None and observed["exec_main_status"] is None
    log = tmp_path / "service-state.log"
    assert log.read_text() == "[sensitive command output withheld]\n"
    assert private not in json.dumps(observed) and private not in log.read_text()
