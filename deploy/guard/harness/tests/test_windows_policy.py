import hashlib
import json
import subprocess
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from test_install_evidence import release

from guard_harness import windows_policy as policy
from guard_harness.native_paper import LifecycleError
from guard_harness.native_release import Release


class Registry:
    def __init__(self, work: Path) -> None:
        self.work = work
        self.removed = False
        self.excluded = False
        self.keep_policy = False

    def scan(self) -> list[dict[str, str]]:
        return [
            dict(
                hive=hive,
                path=path,
                view="Registry64",
                status="absent" if self.removed and not self.keep_policy else "present",
            )
            for hive, path in policy.POLICY_KEYS
        ]

    def exclude(self) -> None:
        self.excluded = True

    def remove(self) -> None:
        assert (self.work / "refusal.receipt.json").is_file()
        assert not (self.work / "removal.receipt.json").exists()
        self.removed = True


def completed(**changes: Any) -> subprocess.CompletedProcess[bytes]:
    values: dict[str, Any] = dict(
        returncode=2, stdout=b"", stderr=policy.REFUSAL.encode() + b"\r\n"
    )
    values.update(changes)
    return subprocess.CompletedProcess(
        args=[], returncode=values["returncode"], stdout=values["stdout"], stderr=values["stderr"]
    )


def policy_fixture(current: Release, work: Path) -> dict[str, object]:
    with patch("guard_harness.windows_policy.subprocess.run", return_value=completed()):
        return policy._prepare(current, work, {}, Registry(work))


def test_refusal_is_durable_before_removal_and_receipts_bind_candidate(tmp_path: Path) -> None:
    current = release(tmp_path / "assets")
    work = tmp_path / "policy"
    registry = Registry(work)

    def probe(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        assert registry.excluded and not registry.removed
        assert Path(argv[0]).read_bytes() == current.binary("windows-amd64")
        assert "--service-key-check" in argv and "--network" in argv
        assert argv[argv.index("--network") + 1] == "testnet"
        assert kwargs["input"] == b"" and kwargs["timeout"] == 15
        assert kwargs["env"] == {"PATH": "inert-fixture"}
        return completed()

    with patch("guard_harness.windows_policy.subprocess.run", side_effect=probe):
        lifecycle = policy._prepare(current, work, {"PATH": "inert-fixture"}, registry)
    assert registry.removed
    assert lifecycle["crash_dump_policy"] == "policy removed by harness"
    policy.admit(current, work, lifecycle)


@pytest.mark.parametrize(
    "change",
    [
        {"returncode": 0},
        {"returncode": 1},
        {"returncode": 124},
        {"stdout": b"unexpected"},
        {"stderr": b"Error: unrelated refusal"},
        {"stderr": policy.REFUSAL.encode() + b"extra"},
        {"stderr": b" " + policy.REFUSAL.encode() + b"\n"},
    ],
)
def test_wrong_refusal_never_removes_policy(tmp_path: Path, change: dict[str, Any]) -> None:
    current = release(tmp_path / "assets")
    work = tmp_path / "policy"
    registry = Registry(work)
    with patch("guard_harness.windows_policy.subprocess.run", return_value=completed(**change)):
        with pytest.raises(LifecycleError, match="exact crash-policy refusal"):
            policy._prepare(current, work, {}, registry)
    assert not registry.removed and not (work / "refusal.receipt.json").exists()


def test_timeout_never_removes_policy(tmp_path: Path) -> None:
    current = release(tmp_path / "assets")
    work = tmp_path / "policy"
    registry = Registry(work)
    with patch(
        "guard_harness.windows_policy.subprocess.run", side_effect=subprocess.TimeoutExpired([], 15)
    ):
        with pytest.raises(LifecycleError, match="did not complete"):
            policy._prepare(current, work, {}, registry)
    assert not registry.removed


def test_positive_lifecycle_cannot_start_when_policy_remains(tmp_path: Path) -> None:
    current = release(tmp_path / "assets")
    work = tmp_path / "policy"
    registry = Registry(work)
    registry.keep_policy = True
    with patch("guard_harness.windows_policy.subprocess.run", return_value=completed()):
        with pytest.raises(LifecycleError, match="four absent keys"):
            policy._prepare(current, work, {}, registry)
    assert (work / "refusal.receipt.json").is_file()
    assert not (work / "removal.receipt.json").exists()


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "wrong-status",
        "wrong-message",
        "key-present",
        "other-binary",
        "other-release",
        "wrong-hive",
        "missing-token",
        "lifecycle-unbound",
        "stdout",
        "private-input",
    ],
)
def test_refusal_and_removal_have_independent_fail_closed_admission(
    tmp_path: Path, mutation: str
) -> None:
    current = release(tmp_path / "assets")
    work = tmp_path / "policy"
    lifecycle = policy_fixture(current, work)
    path = work / ("removal.receipt.json" if mutation == "key-present" else "refusal.receipt.json")
    value = json.loads(path.read_bytes())
    if mutation == "missing":
        path.unlink()
    elif mutation == "wrong-status":
        value["exit_status"] = 0
    elif mutation == "wrong-message":
        value["stderr"] = "different refusal"
    elif mutation == "key-present":
        value["after"][0]["status"] = "present"
    elif mutation == "other-binary":
        value["binary_sha256"] = "a" * 64
    elif mutation == "other-release":
        value["commit"] = "a" * 40
    elif mutation == "wrong-hive":
        value["before"][0]["hive"] = "wrong"
    elif mutation == "missing-token":
        value["coverage"] = []
    elif mutation == "lifecycle-unbound":
        lifecycle["windows_policy_receipt_sha256"] = "a" * 64
    elif mutation == "stdout":
        value["stdout"] = "unexpected"
    elif mutation == "private-input":
        value["private_stdin_supplied"] = True
    if mutation != "missing":
        path.write_text(json.dumps(value))
        # Keep digest links valid to exercise measurement validation, not just hashes.
        removal_path = work / "removal.receipt.json"
        removal = json.loads(removal_path.read_bytes())
        removal["refusal_sha256"] = hashlib.sha256(
            (work / "refusal.receipt.json").read_bytes()
        ).hexdigest()
        removal_path.write_text(json.dumps(removal))
        if mutation != "lifecycle-unbound":
            lifecycle["windows_policy_receipt_sha256"] = hashlib.sha256(
                removal_path.read_bytes()
            ).hexdigest()
    with pytest.raises(LifecycleError):
        policy.admit(current, work, lifecycle)


@pytest.mark.parametrize(
    "platform,actions,environment",
    [
        ("Darwin", "true", "github-hosted"),
        ("Windows", "false", "github-hosted"),
        ("Windows", "true", "self-hosted"),
    ],
)
def test_removal_refuses_non_disposable_hosts(
    monkeypatch: pytest.MonkeyPatch, platform: str, actions: str, environment: str
) -> None:
    monkeypatch.setattr("guard_harness.windows_policy.platform.system", lambda: platform)
    monkeypatch.setenv("GITHUB_ACTIONS", actions)
    monkeypatch.setenv("RUNNER_ENVIRONMENT", environment)
    with pytest.raises(LifecycleError, match="elevated disposable"):
        policy.hosted()


def test_registry_removal_is_registry64_and_only_four_subtrees(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keys = {(hive, path) for hive in (1, 2) for path in policy.POLICY_PATHS}
    child = (1, policy.POLICY_PATHS[0] + r"\zunder-guard.exe")
    sibling = (1, r"SOFTWARE\Microsoft\Windows\Windows Error Reporting\ExcludedApplications")
    keys.update({child, sibling})
    deleted: list[tuple[int, str]] = []

    def open_key(root: int, path: str, reserved: int, access: int) -> Any:
        assert reserved == 0 and access == (0x20019 | 0x100)
        if (root, path) not in keys:
            raise FileNotFoundError
        return nullcontext((root, path))

    def children(key: tuple[int, str]) -> list[str]:
        root, path = key
        return [
            item.removeprefix(path + "\\")
            for hive, item in keys
            if hive == root
            and item.startswith(path + "\\")
            and "\\" not in item.removeprefix(path + "\\")
        ]

    def delete(root: int, path: str, access: int, reserved: int) -> None:
        assert reserved == 0 and access == 0x100
        assert (root, path) != sibling
        assert not children((root, path))
        deleted.append((root, path))
        keys.remove((root, path))

    fake = SimpleNamespace(
        HKEY_LOCAL_MACHINE=1,
        HKEY_CURRENT_USER=2,
        KEY_READ=0x20019,
        KEY_WOW64_64KEY=0x100,
        OpenKey=open_key,
        QueryInfoKey=lambda key: (len(children(key)), 0, 0),
        EnumKey=lambda key, i: children(key)[i],
        DeleteKeyEx=delete,
    )
    monkeypatch.setattr(policy, "hosted", lambda: None)
    with patch("guard_harness.windows_policy.importlib.import_module", return_value=fake):
        registry = policy.WindowsRegistry()
        assert all(row["status"] == "present" for row in registry.scan())
        registry.remove()
        assert all(row["status"] == "absent" for row in registry.scan())
    assert set(deleted) == {(hive, path) for hive in (1, 2) for path in policy.POLICY_PATHS} | {
        child
    }
    assert keys == {sibling}


def test_unreadable_registry_is_not_absence() -> None:
    fake = SimpleNamespace(
        HKEY_LOCAL_MACHINE=1,
        HKEY_CURRENT_USER=2,
        KEY_READ=0x20019,
        KEY_WOW64_64KEY=0x100,
        OpenKey=lambda *args: (_ for _ in ()).throw(PermissionError()),
    )
    with patch("guard_harness.windows_policy.importlib.import_module", return_value=fake):
        with pytest.raises(LifecycleError, match="cannot read"):
            policy.WindowsRegistry().scan()


@pytest.mark.parametrize("refused", [False, True])
def test_scm_install_waits_for_policy_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, refused: bool
) -> None:
    from guard_harness.native_testnet import NativeTestnet

    monkeypatch.setattr("guard_harness.native_testnet.platform.system", lambda: "Windows")
    monkeypatch.setenv("ProgramData", str(tmp_path / "data"))
    current = release(tmp_path / "assets")
    controller = NativeTestnet(
        current, current, tmp_path / "work", "inert-account", "pwsh.exe", windows_service=True
    )
    calls: list[str] = []

    def prepare(subject: Release, work: Path, env: Any) -> dict[str, object]:
        assert subject == current and work == controller.work / "windows-policy"
        calls.append("policy")
        if refused:
            raise LifecycleError("policy step refused")
        return {"crash_dump_policy": policy.REMOVAL_NOTE}

    def install(subject: Release, *, fresh: bool = False) -> None:
        calls.append("install")
        raise LifecycleError("stop before real installer or venue")

    def per_user(driver: NativeTestnet, work: Path, key: bytes) -> dict[str, object]:
        calls.append("per-user")  # W6: per-user custody is measured first, independently.
        driver.key = b""
        return {}

    monkeypatch.setattr(policy, "prepare", prepare)
    monkeypatch.setattr("guard_harness.native_testnet.per_user", per_user)
    monkeypatch.setattr(controller, "install", install)
    with pytest.raises(LifecycleError, match="policy step refused|stop before real"):
        controller.execute(b"inert-fixture")
    assert calls == (["per-user", "policy"] if refused else ["per-user", "policy", "install"])
    assert controller.key == b""


def test_windows_child_environment_keeps_machine_service_roots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from guard_harness import native_run

    subjects = tmp_path / "subjects"
    current = release(subjects / "candidate/assets")
    previous = release(subjects / "previous/assets", old=True)
    (subjects / "input.json").write_text(
        json.dumps(
            dict(
                tag=current.tag,
                commit=current.commit,
                previous_tag=previous.tag,
                previous_commit=previous.commit,
                harness_commit=current.commit,
                diagnostic=False,
                loader_channel="staging",
            )
        )
    )
    monkeypatch.setenv("GITHUB_SHA", current.commit)
    monkeypatch.setenv("DIAGNOSTIC", "false")
    monkeypatch.setenv("INSTALL_MATRIX_PROFILE", "all")
    monkeypatch.setenv("GUARD_C6_SERIALIZED", "1")
    monkeypatch.setenv("WALLET_FRAME", "e" * 64)
    monkeypatch.setenv("UNRELATED_TOKEN", "inert-fixture")
    monkeypatch.setattr(native_run, "flat_scan", lambda *args: None)
    monkeypatch.setenv("PROGRAMDATA", "inert-program-data")
    monkeypatch.setenv("PROGRAMFILES", "inert-program-files")
    # rc.16: without PATHEXT PowerShell refused to run the downloaded cosign.exe.
    windows_locations = {name: f"inert-{name.lower()}" for name in native_run.WINDOWS_LOCATIONS}
    for name, value in windows_locations.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr("guard_harness.native_run.sys.platform", "win32")
    with patch("guard_harness.native_run.subprocess.run") as children:
        native_run.execute(
            subjects=subjects,
            output=tmp_path / "output",
            scenario="upgrade",
            account="inert-account",
            shell="pwsh.exe",
        )
    assert children.call_count == 2
    for call in children.call_args_list:
        env = call.kwargs["env"]
        assert env["PROGRAMDATA"] == "inert-program-data"
        assert env["PROGRAMFILES"] == "inert-program-files"
        assert "WALLET_FRAME" not in env and "UNRELATED_TOKEN" not in env
        assert all(env[name] == value for name, value in windows_locations.items())


@pytest.mark.parametrize("shell", ["pwsh.exe", "powershell.exe"])
@pytest.mark.parametrize("missing_pwd", [False, True])
def test_windows_per_user_journal_completes_before_policy_and_scm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shell: str, missing_pwd: bool
) -> None:
    from test_native_journal import journal

    from guard_harness import native_testnet as native
    from guard_harness.native_paper import Paper

    monkeypatch.setattr("guard_harness.native_testnet.platform.system", lambda: "Windows")
    # Python exposes uppercase names on Windows; model its case-insensitive lookup.
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "data"))
    monkeypatch.setenv("ProgramData", str(tmp_path / "data"))
    current = release(tmp_path / "assets")
    controller = native.NativeTestnet(
        current, current, tmp_path / "work", "inert-account", shell, "fresh", windows_service=True
    )
    monkeypatch.setattr(native, "flat_scan", lambda *args: None)
    installed: list[Release] = []

    def install(paper: Paper, subject: Release, **kwargs: object) -> None:
        installed.append(subject)
        paper.binary.parent.mkdir(parents=True, exist_ok=True)
        paper.binary.write_bytes(subject.binary("windows-amd64"))
        paper.home.mkdir(exist_ok=True)
        (paper.home / "decisions.jsonl").write_bytes(journal())

    def command(words: list[str], **kwargs: object) -> str:
        assert "-Uninstall" in words  # Setup below is inert; only real flow uninstall remains.
        (controller.work / "per-user/bin/zunder-guard.exe").unlink()
        return ""

    class Runtime:
        def __init__(self, words: list[str], **kwargs: object) -> None:
            assert "--key-stdin" not in words  # Stored-key runtime, never private argv.

        def poll(self) -> None:
            return None

        def terminate(self) -> None:
            pass

        def wait(self, *, timeout: float) -> int:
            return 0

    def prepare(subject: Release, work: Path, env: Any) -> dict[str, object]:
        assert len(installed) == 3  # Initial runtime, repeat install and reinstall all audited.
        receipt = json.loads((controller.work / "per-user/receipt.json").read_bytes())
        assert receipt["result"] == "passed" and receipt["no_exchange"] is True
        assert receipt["decision_journal_sha256"] == hashlib.sha256(journal()).hexdigest()
        raise LifecycleError("stop before actual policy mutation or SCM custody")

    monkeypatch.setattr(Paper, "install", install)
    monkeypatch.setattr(native, "candidate_user_setup", lambda *args: None)
    monkeypatch.setattr(controller, "command", command)
    monkeypatch.setattr("guard_harness.native_testnet.subprocess.Popen", Runtime)
    monkeypatch.setattr(
        "guard_harness.native_testnet.LocalGuard.request",
        lambda *args: dict(
            last_sync_ms=1, version=current.tag[1:], mode="testnet", account="inert-account"
        ),
    )
    monkeypatch.setattr(policy, "prepare", prepare)
    if missing_pwd:

        def missing_audit(*args: object, **kwargs: object) -> str:
            raise ModuleNotFoundError("private sentinel detail", name="pwd")

        monkeypatch.setattr("guard_harness.native_journal.audit", missing_audit)
        with pytest.raises(ModuleNotFoundError):
            controller.execute(b"inert frame never used for custody")
        assert len(installed) == 1  # The diagnostic's exact artifact boundary.
        assert not (controller.work / "per-user/receipt.json").exists()
        assert not (controller.work / "windows-policy").exists()
        assert (controller.work / "windows-per-user-journal-audit-failure.log").read_text() == (
            "Windows lifecycle failure step: per-user-journal-audit\n"
            "failure reason: posix-pwd-unavailable\n"
        )
    else:
        with pytest.raises(LifecycleError, match="stop before actual policy"):
            controller.execute(b"inert frame never used for custody")
        assert not (controller.work / "windows-per-user-journal-audit-failure.log").exists()
        assert (controller.work / "windows-crash-policy-prepare-failure.log").read_text() == (
            "Windows lifecycle failure step: crash-policy-prepare\nfailure reason: unknown\n"
        )
    assert controller.key == b""
