"""Offline hosted-runner eligibility, ordering and independent receipt admission."""

import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from test_install_evidence import fixture, release

from guard_harness import linux_policy as policy
from guard_harness.install_evidence import EvidenceError, predicate
from guard_harness.linux_lifecycle import Inputs, LifecycleError
from guard_harness.native_release import Release


def metadata(mode: str = "0777", **changes: object) -> dict[str, object]:
    return dict(uid=0, gid=0, mode=mode, directory=True, symlink=False, **changes)


def completed(**changes: Any) -> subprocess.CompletedProcess[bytes]:
    values: dict[str, Any] = dict(
        returncode=1, stdout=b"public download progress", stderr=policy.REFUSAL.encode() + b"\n"
    )
    values.update(changes)
    return subprocess.CompletedProcess([], **values)


def inputs(current: Release, output: Path, scenario: str = "fresh") -> Inputs:
    output.mkdir(parents=True, exist_ok=True)
    return Inputs(
        current.assets / "i",
        hashlib.sha256(current.asset("i")).hexdigest(),
        current.assets / "install.sh",
        hashlib.sha256(current.asset("install.sh")).hexdigest(),
        current.tag,
        "v0.9.0",
        "inert-rules",
        "0x" + "1" * 40,
        output,
        "a" * 32,
        account_network="testnet",
        scenario=scenario,
        release_commit=current.commit,
        manifest_sha256=hashlib.sha256(current.asset("release-manifest.json")).hexdigest(),
    )


def setup(
    monkeypatch: pytest.MonkeyPatch,
    current: Release,
    work: Path,
    *,
    mode: str = "0777",
    scenario: str = "fresh",
) -> tuple[Inputs, dict[str, Any], list[str]]:
    subject = inputs(current, work, scenario)
    state: dict[str, Any] = {"metadata": metadata(mode)}
    calls: list[str] = []
    monkeypatch.setattr("guard_harness.linux_policy.platform.system", lambda: "Linux")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("RUNNER_ENVIRONMENT", "github-hosted")
    monkeypatch.setattr("guard_harness.linux_policy.os.geteuid", lambda: 0)
    monkeypatch.setattr(policy, "opt_metadata", lambda: state["metadata"])

    def probe(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        calls.append("probe")
        assert argv[:2] == ["sh", str(current.assets / "install.sh")]
        assert Path(argv[1]).read_bytes() == current.asset("install.sh")
        assert argv[argv.index("--network") + 1] == "testnet"
        assert argv[argv.index("--service-instance") + 1] == "testnet"
        assert "--key-stdin" in argv and "--container" not in argv
        assert kwargs["input"] == b"" and kwargs["timeout"] == 600
        assert set(kwargs["env"]) == {"PATH", "HOME"}
        assert not any((work / name).exists() for name in policy.RECEIPTS)
        return completed()

    def normalize(before: dict[str, object]) -> None:
        calls.append("normalize")
        assert before == state["metadata"]
        receipt = json.loads((work / policy.RECEIPTS[0]).read_bytes())
        assert receipt["coverage"] == [policy.REFUSAL_TOKEN]
        assert not (work / policy.RECEIPTS[1]).exists()
        if not state.get("keep"):
            state["metadata"] = metadata("0755")

    monkeypatch.setattr("guard_harness.linux_policy.subprocess.run", probe)
    monkeypatch.setattr(policy, "normalize", normalize)
    return subject, state, calls


def prepare(subject: Inputs, current: Release) -> dict[str, object]:
    return policy.prepare(
        subject,
        current.assets / "install.sh",
        hashlib.sha256(current.asset("install.sh")).hexdigest(),
        hashlib.sha256(current.binary("linux-arm64")).hexdigest(),
    )


@pytest.mark.parametrize("mode", ["0777", "0775"])
@pytest.mark.parametrize("scenario", ["fresh", "upgrade"])
def test_durable_refusal_precedes_normalization_and_binds_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str, scenario: str
) -> None:
    current = release(tmp_path / "assets")
    subject, state, calls = setup(
        monkeypatch, current, tmp_path / "policy", mode=mode, scenario=scenario
    )
    lifecycle = dict(prepare(subject, current), scenario=scenario)
    assert calls == ["probe", "normalize"] and state["metadata"] == metadata("0755")
    assert lifecycle["opt_policy"] == "runner /opt normalised by harness"
    policy.admit(current, "linux-arm64", subject.output, lifecycle)


@pytest.mark.parametrize(
    "change",
    [
        {"returncode": 0},
        {"returncode": 2},
        {"returncode": 124},
        {"stderr": b"install.sh: managed software directory is not root-owned\n"},
        {"stderr": policy.REFUSAL.encode()},
        {"stderr": b"extra\n" + policy.REFUSAL.encode() + b"\n"},
        {"stderr": b" " + policy.REFUSAL.encode() + b"\n"},
    ],
)
def test_wrong_refusal_never_changes_opt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: dict[str, Any]
) -> None:
    current = release(tmp_path / "assets")
    subject, state, calls = setup(monkeypatch, current, tmp_path / "policy")
    monkeypatch.setattr(
        "guard_harness.linux_policy.subprocess.run", lambda *a, **k: completed(**change)
    )
    with pytest.raises(LifecycleError, match="exact native-software-permissions"):
        prepare(subject, current)
    assert calls == [] and state["metadata"] == metadata()
    assert not any((subject.output / name).exists() for name in policy.RECEIPTS)


@pytest.mark.parametrize("failure", [subprocess.TimeoutExpired([], 600), OSError("private text")])
def test_failed_probe_withholds_error_and_never_normalizes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: Exception
) -> None:
    current = release(tmp_path / "assets")
    subject, _, calls = setup(monkeypatch, current, tmp_path / "policy")

    def fail(*args: Any, **kwargs: Any) -> Any:
        raise failure

    monkeypatch.setattr("guard_harness.linux_policy.subprocess.run", fail)
    with pytest.raises(LifecycleError, match="probe did not complete"):
        prepare(subject, current)
    assert calls == []


@pytest.mark.parametrize(
    "changes",
    [
        {"mode": "0755"},
        {"mode": "1777"},
        {"mode": "2775"},
        {"mode": "0770"},
        {"mode": "0776"},
        {"uid": 1},
        {"directory": False},
        {"symlink": True},
        {"uid": None, "gid": None, "mode": None, "directory": None, "symlink": None},
    ],
)
def test_other_opt_states_are_left_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, changes: dict[str, object]
) -> None:
    current = release(tmp_path / "assets")
    subject, state, calls = setup(monkeypatch, current, tmp_path / "policy")
    state["metadata"].update(changes)
    assert prepare(subject, current) == {} and calls == []


@pytest.mark.parametrize(
    "system,actions,environment",
    [
        ("Darwin", "true", "github-hosted"),
        ("Linux", "false", "github-hosted"),
        ("Linux", "true", "self-hosted"),
        ("Linux", "true", ""),
    ],
)
def test_other_hosts_are_left_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, system: str, actions: str, environment: str
) -> None:
    current = release(tmp_path / "assets")
    subject, _, calls = setup(monkeypatch, current, tmp_path / "policy")
    monkeypatch.setattr("guard_harness.linux_policy.platform.system", lambda: system)
    monkeypatch.setenv("GITHUB_ACTIONS", actions)
    monkeypatch.setenv("RUNNER_ENVIRONMENT", environment)
    assert prepare(subject, current) == {} and calls == []


def test_failed_confirmation_preserves_only_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    current = release(tmp_path / "assets")
    subject, state, calls = setup(monkeypatch, current, tmp_path / "policy")
    state["keep"] = True
    with pytest.raises(LifecycleError, match="not confirmed"):
        prepare(subject, current)
    assert calls == ["probe", "normalize"]
    assert (subject.output / policy.RECEIPTS[0]).is_file()
    assert not (subject.output / policy.RECEIPTS[1]).exists()


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "symlink",
        "oversize",
        "status",
        "boolean-status",
        "boolean-schema",
        "message",
        "private-input",
        "category",
        "release",
        "installer",
        "binary",
        "manifest",
        "scenario",
        "before-owner",
        "before-mode",
        "before-symlink",
        "after-mode",
        "after-group",
        "token",
        "note",
        "lifecycle-unbound",
    ],
)
def test_independent_receipt_admission_rejects_tampering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    current = release(tmp_path / "assets")
    subject, _, _ = setup(monkeypatch, current, tmp_path / "policy")
    lifecycle = dict(prepare(subject, current), scenario="fresh")
    first, second = (subject.output / name for name in policy.RECEIPTS)
    refusal, normalized = [json.loads(path.read_bytes()) for path in (first, second)]
    if mutation == "missing":
        first.unlink()
    elif mutation == "symlink":
        alias = subject.output / "alias"
        first.rename(alias)
        first.symlink_to(alias)
    elif mutation == "oversize":
        first.write_bytes(b" " * 16385)
    else:
        if mutation == "status":
            refusal["exit_status"] = 0
        elif mutation == "boolean-status":
            refusal["exit_status"] = True
        elif mutation == "boolean-schema":
            refusal["schema"] = True
        elif mutation == "message":
            refusal["stderr"] = "different refusal"
        elif mutation == "private-input":
            refusal["private_stdin_supplied"] = True
        elif mutation == "category":
            refusal["failure_category"] = "unknown"
        elif mutation == "release":
            refusal["commit"] = "a" * 40
        elif mutation in {"installer", "binary", "manifest"}:
            refusal[mutation + "_sha256"] = "a" * 64
        elif mutation == "scenario":
            refusal["scenario"] = "upgrade"
        elif mutation == "before-owner":
            refusal["before"]["uid"] = 1
        elif mutation == "before-mode":
            refusal["before"]["mode"] = "1777"
        elif mutation == "before-symlink":
            refusal["before"]["symlink"] = True
        elif mutation == "after-mode":
            normalized["after"]["mode"] = "0777"
        elif mutation == "after-group":
            normalized["after"]["gid"] = 1
        elif mutation == "token":
            refusal["coverage"] = []
        elif mutation == "note":
            normalized["opt_policy"] = "different note"
        elif mutation == "lifecycle-unbound":
            lifecycle["linux_opt_receipt_sha256"] = "a" * 64
        first.write_text(json.dumps(refusal))
        normalized["refusal_sha256"] = hashlib.sha256(first.read_bytes()).hexdigest()
        second.write_text(json.dumps(normalized))
        if mutation != "lifecycle-unbound":
            lifecycle["linux_opt_receipt_sha256"] = hashlib.sha256(second.read_bytes()).hexdigest()
    with pytest.raises(LifecycleError):
        policy.admit(current, "linux-arm64", subject.output, lifecycle)


@pytest.mark.parametrize("change", [False, True])
def test_only_fixed_opt_descriptor_can_be_normalized(
    monkeypatch: pytest.MonkeyPatch, change: bool
) -> None:
    monkeypatch.setattr(policy, "hosted", lambda: True)
    monkeypatch.setattr("guard_harness.linux_policy.os.geteuid", lambda: 0)
    info = SimpleNamespace(st_mode=stat.S_IFDIR | 0o777, st_uid=0, st_gid=0, st_dev=1, st_ino=2)
    monkeypatch.setattr("guard_harness.linux_policy.os.fstat", lambda fd: info)
    monkeypatch.setattr(
        Path, "lstat", lambda path: SimpleNamespace(st_dev=1, st_ino=3) if change else info
    )
    monkeypatch.setattr(policy, "opt_metadata", lambda: metadata())
    calls: list[tuple[Any, ...]] = []

    def opened(path: str, flags: int) -> int:
        assert path == "/opt" and flags == os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        return 123

    monkeypatch.setattr("guard_harness.linux_policy.os.open", opened)
    monkeypatch.setattr(
        "guard_harness.linux_policy.os.fchown", lambda *args: calls.append(("chown", *args))
    )
    monkeypatch.setattr(
        "guard_harness.linux_policy.os.fchmod", lambda *args: calls.append(("chmod", *args))
    )
    monkeypatch.setattr(
        "guard_harness.linux_policy.os.close", lambda *args: calls.append(("close", *args))
    )
    if change:
        with pytest.raises(LifecycleError, match="changed before"):
            policy.normalize(metadata())
        assert calls == [("close", 123)]
    else:
        policy.normalize(metadata())
        assert calls == [("chown", 123, 0, 0), ("chmod", 123, 0o755), ("close", 123)]


@pytest.mark.parametrize(
    "eligible,route,refused",
    [
        (False, "native", False),
        (True, "container", False),
        (True, "native", False),
        (True, "native", True),
    ],
)
def test_lifecycle_policy_waits_for_flat_scan(
    monkeypatch: pytest.MonkeyPatch, eligible: bool, route: str, refused: bool
) -> None:
    from guard_harness.linux_testnet_lifecycle import TestnetLifecycle

    controller = object.__new__(TestnetLifecycle)
    controller.route = route
    controller.inputs = cast(Inputs, object())
    controller.opt_policy_installer = Path("inert-install.sh")
    controller.opt_policy_installer_sha256 = "a" * 64
    controller.binary_sha256 = "b" * 64
    calls = []

    def flat() -> None:
        calls.append("flat")
        if refused:
            raise LifecycleError("flat scan refused")

    monkeypatch.setattr(controller, "flat", flat)
    monkeypatch.setattr(policy, "eligible", lambda: eligible)

    def preparation(*args: Any) -> dict[str, object]:
        calls.append("policy")
        return {"opt_policy": policy.NORMALIZED_NOTE}

    monkeypatch.setattr(policy, "prepare", preparation)
    if refused:
        with pytest.raises(LifecycleError, match="flat scan refused"):
            controller.prepare_opt_policy()
        assert calls == ["flat"]
    else:
        value = controller.prepare_opt_policy()
        assert calls == (["flat", "policy"] if eligible and route == "native" else [])
        assert bool(value) == (eligible and route == "native")


@pytest.mark.parametrize("claim", ["unbound", "token-only", "receipt-only"])
def test_positive_install_admission_cannot_ignore_policy_claims(tmp_path: Path, claim: str) -> None:
    subjects, evidence, manifest = fixture(tmp_path, "I2")
    directory = evidence / "testnet/fresh"
    path = directory / "testnet-lifecycle.json"
    record = json.loads(path.read_bytes())
    if claim == "unbound":
        record["opt_policy"] = policy.NORMALIZED_NOTE
    elif claim == "token-only":
        record["coverage"].append(policy.NORMALIZED_TOKEN)
    else:
        (directory / policy.RECEIPTS[0]).write_text("{}")
    path.write_text(json.dumps(record))
    with pytest.raises((LifecycleError, EvidenceError)):
        predicate("I2", evidence, subjects, manifest, "b" * 40)


def test_positive_install_admission_accepts_separate_measured_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    subjects, evidence, manifest = fixture(tmp_path, "I2")
    current = Release("v1.0.0", "b" * 40, subjects / "candidate/assets")
    directory = evidence / "testnet/fresh"
    subject, _, _ = setup(monkeypatch, current, directory)
    path = directory / "testnet-lifecycle.json"
    record = json.loads(path.read_bytes())
    record.update(prepare(subject, current))
    path.write_text(json.dumps(record))
    result = predicate("I2", evidence, subjects, manifest, current.commit)
    assert policy.REFUSAL_TOKEN not in result["coverage"]
    assert policy.NORMALIZED_TOKEN not in result["coverage"]


@pytest.mark.parametrize("refused", [False, True])
def test_native_initial_install_waits_for_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, refused: bool
) -> None:
    from guard_harness.linux_testnet_lifecycle import TestnetLifecycle

    controller = object.__new__(TestnetLifecycle)
    controller.unit = "inert-nonexistent-testnet.service"
    controller.route = "native"
    controller.home = tmp_path / "absent-home"
    controller.binary = tmp_path / "absent-binary"
    controller.private = tmp_path / "private"
    controller.inputs = cast(
        Inputs, SimpleNamespace(initial=(Path("installer"), "a" * 64, "v1.0.0"))
    )
    calls = []

    def preparation() -> dict[str, object]:
        calls.append("policy")
        if refused:
            raise LifecycleError("policy refused")
        return {"opt_policy": policy.NORMALIZED_NOTE}

    def install(*args: Any, **kwargs: Any) -> None:
        calls.append("install")
        raise LifecycleError("stop before installer")

    monkeypatch.setattr(controller, "prepare_opt_policy", preparation)
    monkeypatch.setattr(controller, "install", install)
    with pytest.raises(LifecycleError, match="policy refused|stop before installer"):
        controller.before(b"inert-unused-key")
    assert calls == (["policy"] if refused else ["policy", "install"])


@pytest.mark.parametrize("failure", ["digest", "symlink", "missing-subject", "opt-changed"])
def test_unadmitted_subject_or_changed_opt_never_normalizes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    current = release(tmp_path / "assets")
    subject, state, calls = setup(monkeypatch, current, tmp_path / "policy")
    if failure == "digest":
        (current.assets / "install.sh").write_bytes(b"changed installer")
        digest = hashlib.sha256(b"candidate installer").hexdigest()
    elif failure == "symlink":
        path = current.assets / "install.sh"
        saved = current.assets / "saved"
        path.rename(saved)
        path.symlink_to(saved)
        digest = hashlib.sha256(b"candidate installer").hexdigest()
    else:
        digest = hashlib.sha256(current.asset("install.sh")).hexdigest()
    if failure == "opt-changed":

        def changed(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
            state["metadata"] = metadata("0755")
            return completed()

        monkeypatch.setattr("guard_harness.linux_policy.subprocess.run", changed)
    with pytest.raises(LifecycleError):
        policy.prepare(
            subject,
            None if failure == "missing-subject" else current.assets / "install.sh",
            digest,
            "a" * 64,
        )
    assert calls == []
