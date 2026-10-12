import json
import time
from pathlib import Path
from typing import Any

import pytest

import guard_harness.docker_paper as container
from guard_harness.install_evidence import DOCKER_PAPER, completed
from guard_harness.paper_bot import Decision, LocalGuard, PaperError
from guard_harness.runner import RunResult


class FakeDocker:
    calls: list[tuple[tuple[str, ...], bool]] = []
    crash_recovers = True

    def __init__(self, logs: Path) -> None:
        self.logs = logs
        self.inspections = 0
        self.address = ""
        self.image = ""

    def remove(self, name: str) -> None:
        self.command("rm", "--force", name)

    def command(self, *args: str, sensitive: bool = False) -> RunResult:
        self.calls.append((args, sensitive))
        output = ""
        if "--publish" in args:
            self.address = args[args.index("--publish") + 1].rsplit(":", 1)[0]
            self.image = args[-4]
        if args[-2:] == ("pair", "--json"):
            output = json.dumps({"client_address": "0x" + "1" * 40, "client_key": "0x" + "2" * 64})
        elif args[0] == "port":
            output = self.address + "\n"
        elif args[0] == "top":
            output = "PID COMMAND\n12001 docker-init\n12002 zunder-guard\n"
        elif args[:3] == ("inspect", "--format", "{{.Id}}"):
            output = "a" * 64
        elif args[:3] == ("inspect", "--format", "{{.Config.Image}}"):
            output = self.image
        elif args[0] == "inspect":
            output = str(self.inspections if self.crash_recovers else 0)
            self.inspections += 1
        return RunResult(0, output, self.logs / "fake.log")


class FakeGuard:
    def __init__(self, url: str) -> None:
        assert url.startswith("http://127.0.0.1:")
        assert 0 < int(url.rsplit(":", 1)[1]) < 65536

    def request(self, path: str) -> Any:
        return [{"seq": 1, "nonce": 100}]


def install_fakes(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeDocker.calls = []
    FakeDocker.crash_recovers = True
    monkeypatch.setattr(container, "Docker", FakeDocker)

    def crash(argv: list[str], **kwargs: Any) -> RunResult:
        assert argv[:3] == ["sudo", "-n", "python3"]
        assert argv[-2:] == ["12002", "a" * 64]
        return RunResult(0, "", kwargs["log"])

    monkeypatch.setattr(container, "run", crash)
    monkeypatch.setattr(container, "LocalGuard", FakeGuard)
    monkeypatch.setattr(container, "_ready", lambda *a, **kw: {"started_at_ms": 1})
    monkeypatch.setattr(container, "round_trip", lambda *a: [Decision(100, 1, "allow", "allowed")])


@pytest.mark.parametrize("change", ["", "version", "account", "journal"])
def test_fresh_candidate_requires_runtime_identity_before_restart_and_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    install_fakes(monkeypatch)
    state: dict[str, Any] = dict(
        started_at_ms=1, version="1.2.3", account="0x" + "1" * 40, journal={"ok": True}
    )
    if change:
        state[change] = "different" if change != "journal" else {"ok": False}
    monkeypatch.setattr(container, "_ready", lambda *a, **k: state)
    work = tmp_path / "fresh"
    image = "sha256:" + "a" * 64
    if change:
        with pytest.raises(PaperError, match="release/account/journal"):
            container.lifecycle(image, "0x" + "1" * 40, work=work, version="1.2.3")
        assert not (work / "receipt.json").exists()
        assert not any(args[0] == "restart" for args, _ in FakeDocker.calls)
    else:
        container.lifecycle(image, "0x" + "1" * 40, work=work, version="1.2.3")
        record = json.loads((work / "receipt.json").read_bytes())
        assert record["scenario"] == "fresh" and record["initial_image"] == image
        assert record["initial_version"] == "1.2.3"
        assert "fresh-candidate-paper" in record["checks"] and "upgrade" not in record["checks"]
        first = next(args for args, _ in FakeDocker.calls if "init" in args)
        assert image in first


def test_paper_lifecycle_has_no_key_and_cleans_only_owned_objects(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    install_fakes(monkeypatch)
    work = tmp_path / "run"
    container.lifecycle("sha256:" + "a" * 64, "0x" + "1" * 40, work=work)
    init = next(args for args, _ in FakeDocker.calls if "init" in args and "--no-key" in args)
    assert init[init.index("--network") + 1] == "paper"
    assert init[init.index("--account-network") + 1] == "testnet"
    pair = next(
        (args, sensitive) for args, sensitive in FakeDocker.calls if args[-2:] == ("pair", "--json")
    )
    assert pair[1] is True
    launch = next(args for args, _ in FakeDocker.calls if "--restart" in args)
    assert launch[-3:] == ("run", "--network", "paper")
    published = launch[launch.index("--publish") + 1]
    assert published.startswith("127.0.0.1:") and published.endswith(":8547")
    assert 0 < int(published.split(":")[1]) < 65536
    assert "--read-only" in launch and "--cap-drop" in launch
    name = launch[launch.index("--name") + 1]
    assert FakeDocker.calls[-2][0] == ("rm", "--force", name)
    assert FakeDocker.calls[-1][0] == ("volume", "rm", name + "-data")
    receipt = (work / "receipt.json").read_text()
    assert "client_key" not in receipt and "2" * 64 not in receipt
    assert json.loads(receipt)["mode"] == "paper"
    completed(
        json.loads(receipt),
        DOCKER_PAPER - {"upgrade", "upgrade-journal", "upgrade-pairing"}
        | {"fresh-candidate-paper"},
        mode="paper",
    )


def test_crash_without_restart_never_gets_a_passing_receipt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    install_fakes(monkeypatch)
    FakeDocker.crash_recovers = False
    with pytest.raises(PaperError, match="recover"):
        container.lifecycle("sha256:" + "a" * 64, "0x" + "1" * 40, work=tmp_path / "run")
    assert not (tmp_path / "run/receipt.json").exists()
    assert FakeDocker.calls[-1][0][:2] == ("volume", "rm")


@pytest.mark.parametrize("failure", ["", "image", "journal", "pairing", "reinstall-pairing"])
def test_upgrade_keeps_state_and_client_and_refuses_incomplete_upgrade(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failure: str,
) -> None:
    install_fakes(monkeypatch)
    old, new = "sha256:" + "a" * 64, "sha256:" + "b" * 64
    original = FakeDocker.command
    trips = 0

    def command(self: FakeDocker, *args: str, sensitive: bool = False) -> RunResult:
        result = original(self, *args, sensitive=sensitive)
        if args[:3] == ("inspect", "--format", "{{.Config.Image}}") and failure == "image":
            return RunResult(0, old, result.log)
        return result

    def round_trip(guard: Any, pair: Any) -> list[Decision]:
        nonlocal trips
        trips += 1
        if (trips == 2 and failure == "pairing") or (trips == 3 and failure == "reinstall-pairing"):
            raise PaperError("retained pairing refused")
        assert pair.key == "0x" + "2" * 64
        return [Decision(100, 1, "allow", "allowed")]

    monkeypatch.setattr(FakeDocker, "command", command)
    monkeypatch.setattr(container, "round_trip", round_trip)
    if failure == "journal":
        monkeypatch.setattr(FakeGuard, "request", lambda *args: [])
    work = tmp_path / "run"
    if failure:
        with pytest.raises(PaperError):
            container.lifecycle(new, "0x" + "1" * 40, work=work, previous_image=old)
        assert not (work / "receipt.json").exists()
    else:
        container.lifecycle(new, "0x" + "1" * 40, work=work, previous_image=old)
        receipt = json.loads((work / "receipt.json").read_bytes())
        completed(receipt, DOCKER_PAPER, mode="paper")
        assert receipt["previous_image"] == old and receipt["image"] == new
        assert {"upgrade", "upgrade-journal", "upgrade-pairing"} <= set(receipt["checks"])
        assert {"reinstall-pairing", "cleanup"} <= set(receipt["checks"])
        assert receipt["result"] == "passed" and receipt["cleanup_complete"] is True
        assert trips == 3
    init = [args for args, _ in FakeDocker.calls if "init" in args]
    pair = [args for args, _ in FakeDocker.calls if args[-2:] == ("pair", "--json")]
    assert len(init) == len(pair) == 1 and old in init[0] and old in pair[0]
    launches = [args for args, _ in FakeDocker.calls if "--publish" in args]
    assert launches[0][-4] == old and all(args[-4] == new for args in launches[1:])
    mounts = [args[args.index("--mount") + 1] for args in launches]
    assert len(set(mounts)) == 1
    assert FakeDocker.calls[-1][0][:2] == ("volume", "rm")


@pytest.mark.parametrize(
    "old", ["latest", "sha256:" + "a" * 64, "ghcr.io/zunderlabs/zunder-guard@sha256:" + "a" * 64]
)
def test_upgrade_refuses_mutable_or_identical_previous_image(old: str, tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="previous image"):
        container.lifecycle(
            "sha256:" + "a" * 64, "0x" + "1" * 40, work=tmp_path / "run", previous_image=old
        )
    assert not (tmp_path / "run").exists()


@pytest.mark.parametrize(
    "image", ["latest", "ghcr.io/zunderlabs/zunder-guard:v1.0.0", "sha256:short"]
)
def test_mutable_or_invalid_image_refused_before_docker(image: str, tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="immutable"):
        container.lifecycle(image, "0x" + "1" * 40, work=tmp_path / "run")
    assert not (tmp_path / "run").exists()


@pytest.mark.parametrize("failed", [("volume", "create"), ("rm", "--force")])
def test_unknown_create_and_cleanup_failures_never_leave_passing_receipt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failed: tuple[str, str]
) -> None:
    install_fakes(monkeypatch)
    original = FakeDocker.command

    def broken(self: FakeDocker, *args: str, sensitive: bool = False) -> RunResult:
        result = original(self, *args, sensitive=sensitive)
        if args[:2] == failed:
            raise RuntimeError("injected ambiguous outcome")
        return result

    monkeypatch.setattr(FakeDocker, "command", broken)
    with pytest.raises((RuntimeError, ExceptionGroup)) as caught:
        container.lifecycle("sha256:" + "a" * 64, "0x" + "1" * 40, work=tmp_path / "run")
    error = caught.value
    errors = error.exceptions if isinstance(error, ExceptionGroup) else (error,)
    assert len(errors) == (2 if failed == ("rm", "--force") else 1)
    assert all(isinstance(item, RuntimeError) and "ambiguous" in str(item) for item in errors)
    assert FakeDocker.calls[-1][0][:2] == ("volume", "rm")
    assert not (tmp_path / "run/receipt.json").exists()


def test_unexpected_binding_is_refused_before_signing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    install_fakes(monkeypatch)
    original = FakeDocker.command

    def wrong_port(self: FakeDocker, *args: str, sensitive: bool = False) -> RunResult:
        result = original(self, *args, sensitive=sensitive)
        if args[0] == "port":
            return RunResult(0, "0.0.0.0:18547\n", result.log)
        return result

    def no_signing(*args: Any) -> Any:
        pytest.fail("unexpected binding reached paper signing")

    monkeypatch.setattr(FakeDocker, "command", wrong_port)
    monkeypatch.setattr(container, "round_trip", no_signing)
    with pytest.raises(PaperError, match="loopback"):
        container.lifecycle("sha256:" + "a" * 64, "0x" + "1" * 40, work=tmp_path / "run")
    assert FakeDocker.calls[-1][0][:2] == ("volume", "rm")
    assert not (tmp_path / "run/receipt.json").exists()


@pytest.mark.parametrize(
    "processes",
    [
        "PID COMMAND\n1 zunder-guard\n",
        "PID COMMAND\n12002 other\n",
        "PID COMMAND\n12002 zunder-guard\n12003 zunder-guard\n",
    ],
)
def test_unknown_process_refused_before_crash(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, processes: str
) -> None:
    install_fakes(monkeypatch)
    original = FakeDocker.command

    def top(self: FakeDocker, *args: str, sensitive: bool = False) -> RunResult:
        result = original(self, *args, sensitive=sensitive)
        return RunResult(0, processes, result.log) if args[0] == "top" else result

    def no_kill(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("unconfirmed process reached crash injection")

    monkeypatch.setattr(FakeDocker, "command", top)
    monkeypatch.setattr(container, "run", no_kill)
    with pytest.raises(PaperError, match="process"):
        container.lifecycle("sha256:" + "a" * 64, "0x" + "1" * 40, work=tmp_path / "run")
    assert not (tmp_path / "run/receipt.json").exists()


def test_readiness_retries_connection_reset(monkeypatch: pytest.MonkeyPatch) -> None:
    class ResetGuard(LocalGuard):
        count = 0

        def request(self, path: str, body: dict[str, Any] | None = None) -> dict[str, object]:
            self.count += 1
            if self.count == 1:
                raise ConnectionResetError
            return {"mode": "paper", "started_at_ms": 2, "last_sync_ms": 3}

    monkeypatch.setattr(time, "sleep", lambda _: None)
    assert container._ready(ResetGuard("http://127.0.0.1:8547"), after=1)["started_at_ms"] == 2


def test_compose_uses_distribution_service_and_owned_cleanup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[tuple[tuple[str, ...], bool, dict[str, str]]] = []

    def recorded(self: container.Docker, *args: str, sensitive: bool = False) -> RunResult:
        calls.append((args, sensitive, self.extra_env))
        return RunResult(0, "", self.logs / "command.log")

    monkeypatch.setattr(container.Docker, "command", recorded)
    image = "sha256:" + "a" * 64
    source = Path(__file__).resolve().parents[2] / "compose.yaml"
    compose = container.Compose(tmp_path, source, image, "owned-project", "owned-volume", 18547)
    compose.command("run", "--rm", image, "pair", "--json", sensitive=True)
    compose.command("run", "-d", image, "run", "--network", "paper")
    compose.remove("owned-project")
    prefix = ("compose", "--file", str(tmp_path / "compose.yaml"))
    assert calls == [
        (
            prefix + ("run", "--rm", "--no-deps", "guard", "pair", "--json"),
            True,
            {"ZUNDER_GUARD_IMAGE": image},
        ),
        (
            prefix + ("up", "--detach", "--no-build", "--pull", "never", "guard"),
            False,
            {"ZUNDER_GUARD_IMAGE": image},
        ),
        (prefix + ("down", "--remove-orphans"), False, {"ZUNDER_GUARD_IMAGE": image}),
    ]
    text = compose.config.read_text()
    assert '"127.0.0.1:18547:8547"' in text
    assert "external: true\n    name: owned-volume" in text
    assert "container_name: owned-project" in text
    assert "read_only: true" in text and "init: true" in text


def test_changed_compose_layout_is_refused(tmp_path: Path) -> None:
    source = tmp_path / "source.yaml"
    source.write_text("services: {}\n")
    with pytest.raises(PaperError, match="layout"):
        container.Compose(tmp_path, source, "sha256:" + "a" * 64, "owned", "owned-data", 18547)


@pytest.mark.parametrize("lost_at", [2, 3])
def test_lost_journal_after_crash_or_reinstall_refuses_receipt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, lost_at: int
) -> None:
    install_fakes(monkeypatch)

    class LostGuard(FakeGuard):
        reads = 0

        def request(self, path: str) -> Any:
            self.reads += 1
            return [] if self.reads == lost_at else [{"seq": 1, "nonce": 100}]

    monkeypatch.setattr(container, "LocalGuard", LostGuard)
    with pytest.raises(PaperError, match="journal"):
        container.lifecycle("sha256:" + "a" * 64, "0x" + "1" * 40, work=tmp_path / "run")
    assert not (tmp_path / "run/receipt.json").exists()
    launches = [args for args, _ in FakeDocker.calls if "--restart" in args]
    assert len(launches) == lost_at - 1
    if lost_at == 3:
        assert launches[0] == launches[1]
    assert FakeDocker.calls[-1][0][:2] == ("volume", "rm")


def test_init_and_cleanup_failures_are_retained_and_volume_cleanup_still_runs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    install_fakes(monkeypatch)
    original = FakeDocker.command

    def fail(self: FakeDocker, *args: str, sensitive: bool = False) -> RunResult:
        result = original(self, *args, sensitive=sensitive)
        if "init" in args:
            raise PaperError("initial setup refused")
        if args[0] == "logs":
            raise PaperError("container logs unavailable")
        if args[0] == "rm":
            raise PaperError("container removal unconfirmed")
        return result

    monkeypatch.setattr(FakeDocker, "command", fail)
    with pytest.raises(ExceptionGroup) as caught:
        container.lifecycle("sha256:" + "a" * 64, "0x" + "1" * 40, work=tmp_path / "run")
    assert [str(error) for error in caught.value.exceptions] == [
        "initial setup refused",
        "container logs unavailable",
        "container removal unconfirmed",
    ]
    assert FakeDocker.calls[-1][0][:2] == ("volume", "rm")
    assert not (tmp_path / "run/receipt.json").exists()


def test_final_cleanup_failure_alone_refuses_passing_receipt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    install_fakes(monkeypatch)
    original = FakeDocker.command

    def fail(self: FakeDocker, *args: str, sensitive: bool = False) -> RunResult:
        result = original(self, *args, sensitive=sensitive)
        if args[:2] == ("volume", "rm"):
            raise PaperError("owned volume removal unconfirmed")
        return result

    monkeypatch.setattr(FakeDocker, "command", fail)
    with pytest.raises(PaperError, match="owned volume removal"):
        container.lifecycle("sha256:" + "a" * 64, "0x" + "1" * 40, work=tmp_path / "run")
    assert not (tmp_path / "run/receipt.json").exists()
