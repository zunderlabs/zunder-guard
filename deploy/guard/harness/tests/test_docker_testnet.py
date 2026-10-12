import hashlib
import io
import json
import tarfile
import tempfile
from pathlib import Path
from typing import Any

import pytest
from eth_account import Account

from guard_harness import docker_testnet as subject
from guard_harness.install_evidence import DOCKER_TESTNET, completed
from guard_harness.paper_bot import PaperError
from guard_harness.runner import RunError, RunResult
from guard_harness.testnet_run import ROOT

KEY = ("0" * 63 + "1\n").encode()
WALLET = Account.from_key(KEY.decode().strip()).address
ACCOUNT = "0x" + "a" * 40
CLIENT = "0x" + "b" * 40
IMAGE = "ghcr.io/zunderlabs/zunder-guard@sha256:" + "a" * 64
PREVIOUS = IMAGE.replace("a" * 64, "b" * 64)


@pytest.mark.parametrize(
    "message,category",
    [
        ("the rules code is refused: private-body", "rules"),
        ("the account's equity could not be read: private-account", "account"),
        ("the venue could not be asked: private-response", "venue-role"),
        (
            ACCOUNT + " is not an API wallet of " + WALLET + " (the venue says: private)",
            "venue-role",
        ),
        ("service refused: supervised key frame ended before newline", "key-frame"),
        ("protected key check requires explicit testnet, private-suffix", "policy"),
        ("Permission denied (os error 13): /private/file", "filesystem"),
        ("service refused: could not disable service core dumps", "process-custody"),
        ("unknown-private-body", "unknown"),
    ],
)
def test_init_classifier_retains_only_finite_label(message: str, category: str) -> None:
    assert subject.init_failure_category("zunder-guard: " + message + "\n") == category


@pytest.mark.parametrize(
    "output",
    [
        "private-body the rules code is refused: payload",
        "zunder-guard: fragment the rules code is refused: payload",
        "zunder-guard: the rules code is refused: one\n"
        "zunder-guard: the rules code is refused: two",
        "zunder-guard: the rules code is refused: one\nzunder-guard: input ended",
        "zunder-guard: input ended\n" + "x" * 65536,
    ],
)
def test_unknown_fragment_ambiguous_or_oversized_init_output_stays_withheld(output: str) -> None:
    assert subject.init_failure_category(output) == "unknown"


def test_actual_runner_withholds_key_bearing_init_failure_and_never_classifies_pair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import subprocess

    def process(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        assert kwargs["input"] == KEY
        if "pair" in argv:
            return subprocess.CompletedProcess(argv, 0, b"private-pair-output", b"")
        return subprocess.CompletedProcess(
            argv,
            2,
            KEY + b"private-body",
            (b"zunder-guard: the venue could not be asked: private-path " + ACCOUNT.encode()),
        )

    monkeypatch.setattr("guard_harness.runner.subprocess.run", process)
    docker = subject.TestnetDocker(tmp_path)
    with pytest.raises(RunError, match="category: venue-role") as error:
        docker.command("run", "-i", IMAGE, "init", "--key-stdin", stdin=KEY)
    assert str(error.value) == "command failed with exit 2; failure category: venue-role"
    assert (tmp_path / "docker-1.log").read_text() == (
        "[sensitive command output withheld]\nfailure category: venue-role\n"
    )
    docker.command("run", IMAGE, "pair", "--json", stdin=KEY)
    assert (tmp_path / "docker-2.log").read_text() == "[sensitive command output withheld]\n"


def journal(kinds: list[str]) -> bytes:
    result = b""
    prev = ""
    for seq, kind in enumerate(kinds, 1):
        fields = dict(seq=seq, kind=kind)
        if kind == "started":
            fields["mode"] = "testnet"
        event = json.dumps(fields, separators=(",", ":"))
        check = hashlib.sha3_256((prev + event).encode()).hexdigest()
        result += (
            '{"check":"' + check + '","prev":"' + prev + '","event":' + event + "}\n"
        ).encode()
        prev = check
    return result


def archive(
    *,
    kinds: list[str] | None = None,
    key: bool = True,
    mode: int = 0o600,
    link: bool = False,
    tamper: bool = False,
    journal_body: bytes | None = None,
    emergency: bool = False,
) -> bytes:
    config = (
        f'mode="testnet"\nnetwork="testnet"\naccount="{ACCOUNT}"\n'
        f'api_wallet="{WALLET}"\n[auth]\nclients=["{CLIENT}"]\n'
    ).encode()
    files = {
        "guard.toml": config,
        "risk.jsonl": b"risk\n",
        "decisions.jsonl": journal(kinds or ["started", "stopped"]),
    }
    if key:
        files["api-wallet-key"] = KEY
    if journal_body is not None:
        files["decisions.jsonl"] = journal_body
    if emergency:
        files["emergency/attempt"] = b"unknown protective attempt"
    if tamper:
        files["decisions.jsonl"] = files["decisions.jsonl"].replace(b'"started"', b'"error"')
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as tar:
        for name, value in files.items():
            member = tarfile.TarInfo(name)
            member.size, member.uid, member.gid, member.mode = len(value), 65532, 65532, mode
            if link and name == "api-wallet-key":
                member.type, member.linkname = tarfile.SYMTYPE, "/private/key"
            tar.addfile(member, io.BytesIO(value))
    return output.getvalue()


def inspect(body: bytes, *, volume_key: bool = True) -> dict[str, bytes]:
    return subject.archive_state(
        body, account=ACCOUNT, wallet=WALLET, client=CLIENT, volume_key=volume_key
    )


@pytest.mark.parametrize(
    "kind", ["decision", "intent", "sent", "recovered", "protect", "flatten", "unknown", "error"]
)
def test_complete_journal_refuses_exchange_events(kind: str) -> None:
    with pytest.raises(PaperError, match="action-bearing"):
        inspect(archive(kinds=["started"] * 200 + [kind]))


def test_chain_and_custody() -> None:
    assert inspect(archive())["api-wallet-key"] == KEY
    assert "api-wallet-key" not in inspect(archive(key=False), volume_key=False)
    for body in (archive(mode=0o644), archive(link=True), archive(tamper=True)):
        with pytest.raises(PaperError):
            inspect(body)
    with pytest.raises(PaperError, match="credential"):
        inspect(archive(key=False))
    with pytest.raises(PaperError):
        inspect(archive(), volume_key=False)


@pytest.mark.parametrize("failure", ["missing-start", "truncated", "sequence", "emergency"])
def test_journal_uncertainty_never_authorizes_same_run_controls(failure: str) -> None:
    body = journal(["started", "stopped"])
    if failure == "missing-start":
        body = journal(["stopped"])
    elif failure == "truncated":
        body = body.rstrip(b"\n")
    elif failure == "sequence":
        body = body.replace(b'"seq":2', b'"seq":3')
    with pytest.raises(PaperError):
        inspect(archive(journal_body=body, emergency=failure == "emergency"))


def test_retained_requires_config_and_journal_prefix() -> None:
    old = inspect(archive())
    subject.retained(old, dict(old, **{"risk.jsonl": b"risk\nappend\n"}))
    for changed in (
        {"guard.toml": b"changed"},
        {"risk.jsonl": b"replaced"},
        {"api-wallet-key": b"changed"},
    ):
        with pytest.raises(PaperError):
            subject.retained(old, old | changed)


def test_compose_secret_configuration_stays_private(tmp_path: Path) -> None:
    logs, credentials = tmp_path / "artifact", tmp_path / "private"
    logs.mkdir()
    credentials.mkdir()
    secret = credentials / "hl-api-wallet-key"
    docker = subject.TestnetCompose(
        logs, ROOT / "compose.yaml", IMAGE, "owned", "owned-data", 23456, secret
    )
    assert docker.config.parent == credentials
    assert not (logs / "compose.yaml").exists()
    text = docker.config.read_text()
    assert "ZUNDER_GUARD_NETWORK: testnet" in text
    assert str(secret) in text and "secrets: [hl-api-wallet-key]" in text
    assert docker.config.stat().st_mode & 0o777 == 0o600


def test_preflight_prevents_any_credential_or_docker_setup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    tmp_path.chmod(0o700)

    def forbidden(*args: Any, **kwargs: Any) -> None:
        pytest.fail("Docker or credentials before flat scan")

    monkeypatch.setenv("GUARD_C6_SERIALIZED", "1")
    monkeypatch.setattr(subject.TestnetDocker, "command", forbidden)
    monkeypatch.setattr(tempfile, "mkdtemp", forbidden)

    def nonflat(*args: Any) -> None:
        raise PaperError("not flat")

    monkeypatch.setattr(subject, "flat_scan", nonflat)
    with pytest.raises(PaperError, match="not flat"):
        subject.lifecycle(
            IMAGE,
            ACCOUNT,
            api_wallet=WALLET,
            key=KEY,
            work=tmp_path / "run",
            previous_image=PREVIOUS,
            version="1.0.0",
            previous_version="0.9.0",
            compose=ROOT / "compose.yaml",
            previous_compose=ROOT / "compose.yaml",
        )


def test_missing_serialization_and_key_identity_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("GUARD_C6_SERIALIZED", raising=False)
    for serialized, wallet, reason in [(False, WALLET, "serialization"), (True, ACCOUNT, "wallet")]:
        if serialized:
            monkeypatch.setenv("GUARD_C6_SERIALIZED", "1")
        with pytest.raises(PaperError, match=reason):
            subject.lifecycle(
                IMAGE,
                ACCOUNT,
                api_wallet=wallet,
                key=KEY,
                work=tmp_path / "run",
                previous_image=PREVIOUS,
                version="1.0.0",
                previous_version="0.9.0",
            )
    assert not (tmp_path / "run").exists()


def test_real_command_key_enters_stdin_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("E2E_TESTNET_API_WALLET_KEY", KEY.decode())

    def runner(argv: list[str], **kw: Any) -> RunResult:
        assert KEY.decode().strip() not in str(argv)
        assert "E2E_TESTNET_API_WALLET_KEY" not in kw["env"]
        assert kw["stdin"] == KEY and kw["sensitive_output"] is True
        return RunResult(0, "", kw["log"])

    monkeypatch.setattr(subject, "run", runner)
    subject.TestnetDocker(tmp_path).command("run", "-i", IMAGE, "init", "--key-stdin", stdin=KEY)


@pytest.mark.parametrize("scenario", ["fresh", "upgrade"])
@pytest.mark.parametrize("failure", ["", "start", "nonflat-cleanup", "history"])
def test_lifecycle_receipt_requires_all_actual_observations(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: str, scenario: str
) -> None:
    tmp_path.chmod(0o700)
    monkeypatch.setenv("GUARD_C6_SERIALIZED", "1")
    calls: list[tuple[str, ...]] = []
    resources: dict[str, Any] = {
        "name": "",
        "volume": "",
        "running": False,
        "image": "",
        "restart": 0,
    }
    snapshots = 0
    scans = 0

    def scan(*args: Any) -> dict[str, Any]:
        nonlocal scans
        scans += 1
        if failure == "nonflat-cleanup" and resources["running"]:
            raise PaperError("not flat")
        return {"observations": [], "network": "testnet"}

    def command(self: Any, *args: str, **kwargs: Any) -> RunResult:
        calls.append(args)
        result = ""
        if args[:2] == ("volume", "create"):
            resources["volume"] = args[2]
        elif args[:2] == ("volume", "rm"):
            resources["volume"] = ""
        elif args[:2] == ("volume", "ls"):
            result = str(resources["volume"])
        elif args[0] == "create":
            resources["name"] = args[args.index("--name") + 1]
        elif args[0] == "rm":
            resources["name"] = ""
        elif args[0] == "ps":
            result = str(resources["name"])
        elif args[:2] == ("run", "-d"):
            assert scans > 0
            resources["name"] = args[args.index("--name") + 1]
            resources["running"] = True
            resources["image"] = next(arg for arg in args if arg in {IMAGE, PREVIOUS})
            if failure == "start":
                raise PaperError("unknown start outcome")
        elif args[0] == "run" and "init" in args:
            assert kwargs["stdin"] == KEY
            assert "--key-stdin" in args and "--network" in args
            assert args[args.index("--equity-cap") + 1] == "40"
            assert args[args.index("--ip-share") + 1] == "0.1"
        elif args[0] == "run" and "pair" in args:
            result = json.dumps(dict(client_address=CLIENT, client_key="0x" + "c" * 64))
        elif args[0] == "port":
            launched = next(call for call in reversed(calls) if call[:2] == ("run", "-d"))
            result = launched[launched.index("--publish") + 1].removesuffix(":8547")
        elif args[0] == "inspect":
            result = {
                "{{.Config.Image}}": str(resources["image"]),
                "{{.Id}}": "d" * 64,
                "{{.RestartCount}}": str(resources["restart"]),
            }[args[2]]
        elif args[0] == "top":
            result = "PID COMMAND\n234 zunder-guard\n"
        elif args[0] == "stop":
            resources["running"] = False
        return RunResult(0, result, tmp_path / "withheld.log")

    def snap(*args: Any, **kwargs: Any) -> dict[str, bytes]:
        nonlocal snapshots
        snapshots += 1
        if failure == "history" and snapshots == 3:
            return inspect(archive()) | {"guard.toml": b"changed"}
        return inspect(archive()) | {"risk.jsonl": b"risk\n" + b"append\n" * snapshots}

    def crash(argv: list[str], **kwargs: Any) -> RunResult:
        assert argv[:3] == ["sudo", "-n", "python3"]
        assert argv[-2:] == ["234", "d" * 64]
        resources["restart"] = int(resources["restart"]) + 1
        return RunResult(0, "", kwargs["log"])

    def read(payload: dict[str, Any]) -> object:
        assert payload["type"] == "userFillsByTime"
        return []

    monkeypatch.setattr(subject, "flat_scan", scan)
    monkeypatch.setattr(subject.TestnetDocker, "command", command)
    monkeypatch.setattr(subject, "snapshot", snap)
    monkeypatch.setattr(subject, "run", crash)
    monkeypatch.setattr(subject, "ready", lambda *args, after=0, **kwargs: after + 1)
    work = tmp_path / "run"
    if failure:
        with pytest.raises((PaperError, BaseExceptionGroup)):
            subject.lifecycle(
                IMAGE,
                ACCOUNT,
                api_wallet=WALLET,
                key=KEY,
                work=work,
                previous_image=PREVIOUS,
                version="1.0.0",
                previous_version="0.9.0",
                read=read,
                scenario=scenario,
            )
        assert not (work / "receipt.json").exists()
        if failure == "nonflat-cleanup":
            assert resources["running"] and resources["volume"]
            assert json.loads((work / "recovery.json").read_text())["cleanup_complete"] is False
        else:
            assert not resources["running"] and not resources["volume"]
    else:
        subject.lifecycle(
            IMAGE,
            ACCOUNT,
            api_wallet=WALLET,
            key=KEY,
            work=work,
            previous_image=PREVIOUS,
            version="1.0.0",
            previous_version="0.9.0",
            read=read,
            scenario=scenario,
        )
        receipt = json.loads((work / "receipt.json").read_text())
        required = (
            DOCKER_TESTNET
            if scenario == "upgrade"
            else (DOCKER_TESTNET - {"upgrade"} | {"fresh-candidate-testnet"})
        )
        completed(receipt, required, mode="testnet")
        assert receipt["result"] == "passed" and receipt["no_exchange"] is True
        assert receipt["custody"] == "documented-volume"
        assert receipt["cleanup_complete"] is True and not resources["volume"]
        assert [
            call[call.index("--network") + 1] for call in calls if call[:2] == ("run", "-d")
        ] == ["testnet"] * (3 if scenario == "upgrade" else 2)
        assert snapshots == (5 if scenario == "upgrade" else 4)
        assert scans == (8 if scenario == "upgrade" else 6)
        assert receipt["scenario"] == scenario
        initial = IMAGE if scenario == "fresh" else PREVIOUS
        assert receipt["initial_image"] == initial
        first_init = next(call for call in calls if "init" in call)
        assert initial in first_init
        first_run = next(call for call in calls if call[:2] == ("run", "-d"))
        assert initial in first_run
        assert ("upgrade" in receipt["coverage"]) == (scenario == "upgrade")
        assert len(receipt["decision_journal_sha256"]) == 64


def test_compose_uses_signed_service_and_private_stdin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    logs, credentials = tmp_path / "artifact", tmp_path / "private"
    logs.mkdir()
    credentials.mkdir()
    docker = subject.TestnetCompose(
        logs,
        ROOT / "compose.yaml",
        IMAGE,
        "owned",
        "owned-data",
        23456,
        credentials / "hl-api-wallet-key",
    )
    calls: list[list[str]] = []

    def runner(argv: list[str], **kw: Any) -> RunResult:
        calls.append(argv)
        assert kw["env"].get("ZUNDER_GUARD_IMAGE") == IMAGE
        assert "KEY" not in kw["env"]
        assert kw["sensitive_output"] is True
        if "init" in argv:
            assert kw["stdin"] == KEY
            assert "-T" in argv and "--service-key-check" in argv and "--no-key" in argv
        return RunResult(0, "", kw["log"])

    monkeypatch.setattr(subject, "run", runner)
    monkeypatch.setenv("KEY", KEY.decode())
    docker.command(
        "run", "--rm", IMAGE, "init", "--key-stdin", "--no-key", "--service-key-check", stdin=KEY
    )
    docker.command("run", "-d", IMAGE, "run", "--network", "testnet")
    assert calls[0][:2] == ["docker", "compose"]
    assert calls[1][-6:] == ["up", "--detach", "--no-build", "--pull", "never", "guard"]


def test_failed_secret_preparation_removes_private_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    tmp_path.chmod(0o700)
    parent = tmp_path / "artifact"
    parent.mkdir(mode=0o700)
    monkeypatch.setenv("GUARD_C6_SERIALIZED", "1")
    monkeypatch.setattr(subject, "flat_scan", lambda *args: {})

    def failed_owner(*args: Any, **kwargs: Any) -> None:
        raise PaperError("owner setup failed")

    monkeypatch.setattr(subject, "run", failed_owner)
    with pytest.raises(PaperError, match="owner setup"):
        subject.lifecycle(
            IMAGE,
            ACCOUNT,
            api_wallet=WALLET,
            key=KEY,
            work=parent / "run",
            previous_image=PREVIOUS,
            version="1.0.0",
            previous_version="0.9.0",
            compose=ROOT / "compose.yaml",
            previous_compose=ROOT / "compose.yaml",
        )
    assert not list(tmp_path.glob(".guard-testnet-credentials-*"))
    assert not list(parent.rglob("hl-api-wallet-key"))


def test_status_health_identity_and_journal(monkeypatch: pytest.MonkeyPatch) -> None:
    class Guard:
        def request(self, path: str) -> object:
            if path == "/healthz":
                return {"status": "ok"}
            assert path == "/guard/status"
            return {
                "mode": "testnet",
                "network": "testnet",
                "account": ACCOUNT,
                "version": "1.0.0",
                "started_at_ms": 42,
                "last_sync_ms": 43,
                "journal": {"ok": True},
            }

    assert subject.ready(Guard(), account=ACCOUNT, version="1.0.0", after=41) == 42  # type: ignore[arg-type]
