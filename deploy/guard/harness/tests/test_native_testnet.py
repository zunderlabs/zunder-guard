"""Offline launchd reload races; no native services, credentials or venue calls."""

import subprocess
from pathlib import Path

import pytest

from guard_harness.native_paper import LifecycleError
from guard_harness.native_release import Release
from guard_harness.native_testnet import NativeTestnet


@pytest.fixture
def mac(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[NativeTestnet, list[float]]:
    monkeypatch.setattr("guard_harness.native_testnet.platform.system", lambda: "Darwin")
    release = Release("v1.0.0", "a" * 40, tmp_path / "assets")
    controller = NativeTestnet(release, release, tmp_path, "fixture-account", "sh")
    sleeps: list[float] = []
    monkeypatch.setattr("guard_harness.native_testnet.time.sleep", sleeps.append)
    return controller, sleeps


@pytest.mark.parametrize(
    ("events", "error", "sleep_count"),
    [
        ([("print", 113), ("bootstrap", 0)], None, 0),
        ([("print", 0), ("print", 0), ("print", 113), ("bootstrap", 0)], None, 2),
        (
            [
                ("print", 113),
                ("bootstrap", 5),
                ("print", 0),
                ("print", 113),
                ("bootstrap", 5),
                ("print", 113),
                ("bootstrap", 0),
            ],
            None,
            3,
        ),
        (
            [("print", 113), ("bootstrap", 5)] * 3,
            "bootstrap failed with exit 5",
            2,
        ),
        ([("print", 113), ("bootstrap", 78)], "bootstrap failed with exit 78", 0),
        (
            [("print", 113), ("bootstrap", 5), ("print", 113), ("bootstrap", 1)],
            "bootstrap failed with exit 1",
            1,
        ),
        ([("print", 5)], "print failed with exit 5", 0),
        ([("print", 1)], "print failed with exit 1", 0),
        ([("print", 0)] * 30, "did not unload before deadline", 29),
    ],
)
def test_mac_start_waits_for_absence_and_retries_only_bootstrap_eio(
    mac: tuple[NativeTestnet, list[float]],
    monkeypatch: pytest.MonkeyPatch,
    events: list[tuple[str, int]],
    error: str | None,
    sleep_count: int,
) -> None:
    controller, sleeps = mac
    pending = iter(events)
    calls: list[list[str]] = []

    def execute(words: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        operation, status = next(pending)
        assert words == ["sudo", "launchctl", operation] + (
            [controller.label] if operation == "print" else ["system", str(controller.plist)]
        )
        assert kwargs == dict(
            env=controller.env,
            capture_output=True,
            timeout=10,
            check=False,
            stdin=subprocess.DEVNULL,
        )
        calls.append(words)
        return subprocess.CompletedProcess(words, status, b"private launchd data", b"private data")

    monkeypatch.setattr("guard_harness.native_testnet.subprocess.run", execute)
    if error is None:
        controller.start()
    else:
        with pytest.raises(LifecycleError, match=error):
            controller.start()
    assert len(calls) == len(events)
    assert sleeps == [1] * sleep_count
    logs = sorted(controller.work.glob("step-*.log"))
    assert len(logs) == len(events)
    assert all("private" not in log.read_text() for log in logs)
    for index, (_, status) in enumerate(events, 1):
        assert (controller.work / f"step-{index}.log").read_text() == (
            f"[launchctl output withheld]\nexit status: {status}\n"
        )


def test_mac_stop_waits_after_successful_bootout(
    mac: tuple[NativeTestnet, list[float]], monkeypatch: pytest.MonkeyPatch
) -> None:
    controller, sleeps = mac
    calls: list[object] = []

    def command(words: list[str]) -> str:
        calls.append(words)
        return ""

    statuses = iter([0, 113])

    def status(*words: str) -> int:
        calls.append(words)
        return next(statuses)

    monkeypatch.setattr(controller, "command", command)
    monkeypatch.setattr(controller, "launchctl_status", status)
    controller.stop()
    assert calls == [
        ["sudo", "launchctl", "bootout", controller.label],
        ("print", controller.label),
        ("print", controller.label),
    ]
    assert sleeps == [1]


@pytest.mark.parametrize("failure", ["timeout", "unavailable"])
@pytest.mark.parametrize("operation", ["print", "bootstrap"])
def test_mac_launchctl_probe_failure_is_never_absence_or_retryable(
    mac: tuple[NativeTestnet, list[float]],
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
    operation: str,
) -> None:
    controller, sleeps = mac
    calls = 0

    def execute(words: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        nonlocal calls
        calls += 1
        if operation == "bootstrap" and words[2] == "print":
            return subprocess.CompletedProcess(words, 113, b"", b"")
        if failure == "timeout":
            raise subprocess.TimeoutExpired(words, 10, output=b"private timeout data")
        raise OSError("private failure data")

    monkeypatch.setattr("guard_harness.native_testnet.subprocess.run", execute)
    with pytest.raises(LifecycleError, match="unavailable or timed out"):
        controller.start()
    assert calls == (2 if operation == "bootstrap" else 1) and sleeps == []
    assert (controller.work / f"step-{calls}.log").read_text() == (
        "[launchctl output withheld]\ncommand outcome: unavailable\n"
    )


def test_windows_start_stop_do_not_use_launchctl(
    mac: tuple[NativeTestnet, list[float]], monkeypatch: pytest.MonkeyPatch
) -> None:
    controller, sleeps = mac
    controller.mac = False
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(controller, "action", lambda *words: calls.append(words))
    monkeypatch.setattr(
        controller, "launchctl_status", lambda *words: pytest.fail("Windows cannot use launchctl")
    )
    controller.start()
    controller.stop()
    assert calls == [("Start", "-Startup", "Manual"), ("Stop",)]
    assert sleeps == []


@pytest.mark.parametrize("shell", ["powershell.exe", "pwsh.exe"])
@pytest.mark.parametrize("scenario", ["fresh", "upgrade"])
@pytest.mark.parametrize("failure", ["helper", "stdout-only", "unknown", "timeout", "success"])
def test_windows_scm_install_retains_only_the_installer_literal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shell: str, scenario: str, failure: str
) -> None:
    import guard_harness.native_testnet as native
    from guard_harness.runner import RunError
    from guard_harness.windows_diagnostics import INSTALLER_WRAPPER

    monkeypatch.setattr("guard_harness.native_testnet.platform.system", lambda: "Windows")
    monkeypatch.setenv("ProgramData", str(tmp_path / "program-data"))
    current = Release("v1.0.0-rc.16", "a" * 40, tmp_path / "current")
    previous = Release("v1.0.0-rc.15", "b" * 40, tmp_path / "previous")
    controller = NativeTestnet(
        current, previous, tmp_path / "work", "fixture-account", shell, scenario
    )
    controller.work.mkdir()
    controller.key = b"private fixture frame\n"
    monkeypatch.setattr(native, "staged_loader", lambda *args, **kwargs: None)
    monkeypatch.setattr(Release, "asset", lambda *args: b"inert offline loader")
    identities: list[Release] = []
    monkeypatch.setattr(controller, "identity", identities.append)
    binary = tmp_path / "installed.exe"
    monkeypatch.setattr(controller, "installed", lambda: binary)
    message = "SCM operation failed; transaction remains pending."
    calls = 0

    def execute(words: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        nonlocal calls
        calls += 1
        if calls == 2:
            assert failure == "success" and words == [
                str(binary),
                "service",
                "check",
                "--binding",
                str(controller.binding),
                "--json",
            ]
            assert kwargs["input"] == b""
            return subprocess.CompletedProcess(
                words, 0, b'{"ok":true,"mode":"testnet","account":"fixture-account"}', b""
            )
        assert words[0] == shell and "-ManagedService" in words and "-KeyStdin" in words
        assert words[words.index("-Network") + 1] == "testnet"
        assert kwargs["input"] == controller.key * 2  # Init and provision get separate frames.
        assert kwargs["env"] is controller.env  # Diagnostics do not change environment or custody.
        assert kwargs["capture_output"] is True
        if failure == "timeout":
            raise subprocess.TimeoutExpired(words, 600, output=b"private timeout sentinel")
        stdout = b"private stdout sentinel\n" + controller.key
        stderr = b"private stderr sentinel\n"
        if failure == "helper":
            stderr += ("fixture\\install-windows-service.ps1 : " + message + "\n").encode()
            stderr += (INSTALLER_WRAPPER + "\n").encode()
        if failure == "stdout-only":
            stdout += message.encode()  # Private stdout never supplies the failure classifier.
        return subprocess.CompletedProcess(words, 0 if failure == "success" else 1, stdout, stderr)

    monkeypatch.setattr("guard_harness.runner.subprocess.run", execute)
    initial = current if scenario == "fresh" else previous
    if failure == "success":
        controller.install(initial, fresh=True)
    else:
        with pytest.raises(RunError):
            controller.install(initial, fresh=True)
        body = (controller.work / "windows-scm-install-failure.log").read_text()
        assert body == (
            "Windows lifecycle failure step: scm-install\nfailure reason: command-failed\n"
            f"installer refusal: {message if failure == 'helper' else 'unknown'}\n"
        )
    assert calls == (2 if failure == "success" else 1)
    assert identities == ([initial] if failure == "success" else [])
    logs = "\n".join(path.read_text() for path in controller.work.glob("*.log"))
    assert "private" not in logs and "fixture\\" not in logs
    assert not list(controller.work.glob("*.json"))
    assert (controller.work / "windows-scm-install-failure.log").exists() is (failure != "success")
