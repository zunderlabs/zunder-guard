import json
import time
from pathlib import Path
from typing import Any

import pytest

import guard_harness.docker_paper as container
from guard_harness.paper_bot import Decision, LocalGuard, PaperError
from guard_harness.runner import RunResult


class FakeDocker:
    calls: list[tuple[tuple[str, ...], bool]] = []
    crash_recovers = True

    def __init__(self, logs: Path) -> None:
        self.logs = logs
        self.inspections = 0
        self.address = ""

    def remove(self, name: str) -> None:
        self.command("rm", "--force", name)

    def command(self, *args: str, sensitive: bool = False) -> RunResult:
        self.calls.append((args, sensitive))
        output = ""
        if "--publish" in args:
            self.address = args[args.index("--publish") + 1].rsplit(":", 1)[0]
        if args[-2:] == ("pair", "--json"):
            output = json.dumps({"client_address": "0x" + "1" * 40, "client_key": "0x" + "2" * 64})
        elif args[0] == "port":
            output = self.address + "\n"
        elif args[0] == "top":
            output = "PID COMMAND\n12001 docker-init\n12002 zunder-guard\n"
        elif args[:3] == ("inspect", "--format", "{{.Id}}"):
            output = "a" * 64
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


def test_crash_without_restart_never_gets_a_passing_receipt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    install_fakes(monkeypatch)
    FakeDocker.crash_recovers = False
    with pytest.raises(PaperError, match="recover"):
        container.lifecycle("sha256:" + "a" * 64, "0x" + "1" * 40, work=tmp_path / "run")
    assert not (tmp_path / "run/receipt.json").exists()
    assert FakeDocker.calls[-1][0][:2] == ("volume", "rm")


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
    with pytest.raises(RuntimeError, match="ambiguous"):
        container.lifecycle("sha256:" + "a" * 64, "0x" + "1" * 40, work=tmp_path / "run")
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
