"""Docker paper lifecycle on one immutable image; release admission stays with the caller."""

import json
import os
import re
import socket
import time
import uuid
from collections.abc import Sequence
from pathlib import Path

from guard_harness import crash_process
from guard_harness.cli import PAIR_SCHEMA, Pair, decode_json
from guard_harness.paper_bot import Decision, LocalGuard, PaperError
from guard_harness.paper_roundtrip import round_trip
from guard_harness.runner import RunResult, run
from guard_harness.testnet_run import ROOT


class Docker:
    def __init__(self, logs: Path) -> None:
        self.logs, self.sequence = logs, 0
        self.secrets: tuple[str, ...] = ()
        self.extra_env: dict[str, str] = {}

    def command(self, *args: str, sensitive: bool = False) -> RunResult:
        self.sequence += 1
        env = {name: os.environ[name] for name in ("PATH", "HOME") if name in os.environ}
        return run(
            ["docker", *args],
            log=self.logs / f"docker-{self.sequence}.log",
            timeout=90,
            env=env | self.extra_env,
            stdin=b"",
            sensitive_output=sensitive,
            secrets=self.secrets,
        )

    def remove(self, name: str) -> None:
        self.command("rm", "--force", name)


class Compose(Docker):
    """Use the distribution Compose service for setup/start, Docker for observations."""

    def __init__(
        self, logs: Path, source: Path, image: str, name: str, volume: str, port: int
    ) -> None:
        super().__init__(logs)
        text = source.read_text()
        replacements = {
            "name: zunder-guard\n": f"name: {name}\n",
            "  guard:\n": f"  guard:\n    container_name: {name}\n",
            '"127.0.0.1:8547:8547"': f'"127.0.0.1:{port}:8547"',
            "  guard-data:\n": f"  guard-data:\n    external: true\n    name: {volume}\n",
        }
        for old, new in replacements.items():
            if text.count(old) != 1:
                raise PaperError("distribution Compose layout unconfirmed")
            text = text.replace(old, new)
        self.config = logs / "compose.yaml"
        self.config.write_text(text)
        self.image = image
        self.extra_env = {"ZUNDER_GUARD_IMAGE": image}

    def command(self, *args: str, sensitive: bool = False) -> RunResult:
        if args[0] != "run":
            return super().command(*args, sensitive=sensitive)
        command = args[args.index(self.image) + 1 :]
        prefix = ("compose", "--file", str(self.config))
        if "-d" in args:
            return super().command(
                *prefix, "up", "--detach", "--no-build", "--pull", "never", "guard"
            )
        return super().command(
            *prefix, "run", "--rm", "--no-deps", "guard", *command, sensitive=sensitive
        )

    def remove(self, name: str) -> None:
        self.command("compose", "--file", str(self.config), "down", "--remove-orphans")


def _ready(guard: LocalGuard, *, after: int | None = None) -> dict[str, object]:
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            state = guard.request("/guard/status")
            if state.get("mode") != "paper":
                raise PaperError("container runtime is not paper")
            started = state.get("started_at_ms")
            if (
                type(started) is int
                and state.get("last_sync_ms")
                and (after is None or started > after)
            ):
                return dict(state)
        except (PaperError, OSError):
            pass
        time.sleep(0.5)
    raise PaperError("container paper readiness/restart unconfirmed")


def _journal(guard: LocalGuard, decisions: Sequence[Decision]) -> None:
    events = guard.request("/guard/events?since=0")
    if not isinstance(events, list) or not all(
        any(
            isinstance(e, dict) and e.get("seq") == d.seq and e.get("nonce") == d.nonce
            for e in events
        )
        for d in decisions
    ):
        raise PaperError("container lifecycle lost paper decision journal")


def lifecycle(
    image: str,
    account: str,
    *,
    work: Path,
    compose: Path | None = None,
    previous_image: str | None = None,
    previous_compose: Path | None = None,
    version: str | None = None,
    previous_version: str | None = None,
) -> None:
    """No venue key. A caller must verify release/cosign binding before E2E admission."""
    if not re.fullmatch(r"(?:ghcr\.io/zunderlabs/zunder-guard@)?sha256:[0-9a-f]{64}", image):
        raise ValueError("immutable image identity required")
    if previous_image is not None and (
        not re.fullmatch(
            r"(?:ghcr\.io/zunderlabs/zunder-guard@)?sha256:[0-9a-f]{64}", previous_image
        )
        or previous_image.split("@")[-1] == image.split("@")[-1]
    ):
        raise ValueError("distinct immutable previous image required")
    if (previous_compose is not None) != (compose is not None and previous_image is not None):
        raise ValueError("previous Compose subject required only for a Compose upgrade")
    if not re.fullmatch(r"0x[0-9a-fA-F]{40}", account) or work.exists():
        raise ValueError("public read account and fresh workspace required")
    work.mkdir(mode=0o700)
    name = f"guard-paper-{uuid.uuid4().hex}"
    volume = name + "-data"
    mounted = ("--mount", f"type=volume,source={volume},target=/data")
    # Docker reallocates an empty HostPort after restart. An explicit loopback port
    # persists; a competing bind makes launch fail before any signing.
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        host_port = reservation.getsockname()[1]
    expected_address = f"127.0.0.1:{host_port}"
    initial_image = previous_image or image
    initial_compose = previous_compose or compose
    docker = (
        Docker(work)
        if initial_compose is None
        else Compose(work, initial_compose, initial_image, name, volume, host_port)
    )
    expected_version = previous_version if previous_image else version
    running_image = initial_image

    def ready(guard: LocalGuard, *, after: int | None = None) -> dict[str, object]:
        state = _ready(guard, after=after)
        if version is not None:
            journal = state.get("journal")
            if (
                state.get("version") != expected_version
                or str(state.get("account", "")).lower() != account.lower()
                or not isinstance(journal, dict)
                or journal.get("ok") is not True
            ):
                raise PaperError("paper runtime release/account/journal differs")
            if (
                docker.command("inspect", "--format", "{{.Config.Image}}", name).output.strip()
                != running_image
            ):
                raise PaperError("paper runtime immutable image differs")
        return state

    failures: list[BaseException] = []
    try:
        docker.command("volume", "create", volume)
        rules = json.loads((ROOT / "rules/vectors.json").read_bytes())["valid"][0]["canonical"]
        docker.command(
            "run",
            "--rm",
            *mounted,
            initial_image,
            "init",
            "--non-interactive",
            "--network",
            "paper",
            "--account-network",
            "testnet",
            "--account",
            account,
            "--no-key",
            "--rules",
            rules,
            sensitive=True,
        )
        paired = docker.command(
            "run", "--rm", *mounted, initial_image, "pair", "--json", sensitive=True
        )
        value = decode_json(paired.output, PAIR_SCHEMA)
        pair = Pair(value["client_address"], value["client_key"])
        docker.secrets = (pair.key, account)
        launch: tuple[str, ...] = (
            "run",
            "-d",
            "--name",
            name,
            "--restart",
            "unless-stopped",
            "--init",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--tmpfs",
            "/tmp",
            *mounted,
            "--publish",
            f"{expected_address}:8547",
            "--env",
            "ZUNDER_GUARD_LISTEN=0.0.0.0:8547",
            initial_image,
            "run",
            "--network",
            "paper",
        )
        docker.command(*launch)
        address = docker.command("port", name, "8547/tcp").output.strip()
        if address != expected_address:
            raise PaperError("container loopback port refused")
        guard = LocalGuard("http://" + address)
        first = ready(guard)
        decisions = round_trip(guard, pair)
        if previous_image is not None:
            # Stop the old version before switching images. Retain its state volume,
            # pairing and config; neither init nor pair is repeated by the candidate.
            docker.command("logs", name)
            docker.remove(name)
            upgrade_logs = work / "upgrade"
            upgrade_logs.mkdir(mode=0o700)
            docker = (
                Docker(upgrade_logs)
                if compose is None
                else Compose(upgrade_logs, compose, image, name, volume, host_port)
            )
            docker.secrets = (pair.key, account)
            launch = tuple(image if arg == initial_image else arg for arg in launch)
            docker.command(*launch)
            if docker.command("port", name, "8547/tcp").output.strip() != expected_address:
                raise PaperError("upgraded container loopback port refused")
            if (
                docker.command("inspect", "--format", "{{.Config.Image}}", name).output.strip()
                != image
            ):
                raise PaperError("upgraded container image differs from candidate")
            expected_version, running_image = version, image
            first = ready(guard, after=int(str(first["started_at_ms"])))
            _journal(guard, decisions)
            # The old client must still sign successfully using retained config;
            # journal presence alone cannot prove pairing survived the upgrade.
            decisions = [*decisions, *round_trip(guard, pair)]
        last_seq = decisions[-1].seq
        docker.command("restart", name)
        restarted = ready(guard, after=int(str(first["started_at_ms"])))
        _journal(guard, decisions)
        before = int(docker.command("inspect", "--format", "{{.RestartCount}}", name).output)
        # Docker's kill API is an operator stop and suppresses restart policy. On the
        # Linux runner, kill the sole Guard process reported by this owned container.
        processes = docker.command("top", name, "-eo", "pid,comm").output.splitlines()
        guards = [line.split() for line in processes[1:] if line.split()[-1:] == ["zunder-guard"]]
        if len(guards) != 1 or len(guards[0]) != 2 or not guards[0][0].isdigit():
            raise PaperError("owned container Guard process unconfirmed")
        pid = guards[0][0]
        if int(pid) <= 1:
            raise PaperError("unsafe container process identity")
        identity = docker.command("inspect", "--format", "{{.Id}}", name).output.strip()
        if not re.fullmatch(r"[0-9a-f]{64}", identity):
            raise PaperError("owned container identity unconfirmed")
        run(
            ["sudo", "-n", "python3", str(Path(crash_process.__file__).resolve()), pid, identity],
            log=work / "crash.log",
            timeout=10,
            stdin=b"",
        )
        recovered = ready(guard, after=int(str(restarted["started_at_ms"])))
        after = int(docker.command("inspect", "--format", "{{.RestartCount}}", name).output)
        if after <= before:
            raise PaperError("Docker did not recover the crashed paper container")
        _journal(guard, decisions)
        # Reinstall the same immutable release while retaining documented data. Retain
        # the old container's logs before removal; final cleanup keeps the new logs too.
        docker.command("logs", name)
        docker.remove(name)
        docker.command(*launch)
        if docker.command("port", name, "8547/tcp").output.strip() != expected_address:
            raise PaperError("reinstalled container loopback port refused")
        ready(guard, after=int(str(recovered["started_at_ms"])))
        _journal(guard, decisions)
        # A reused volume alone cannot prove the old client still authenticates.
        _journal(guard, round_trip(guard, pair))
    except BaseException as error:
        failures.append(error)
    finally:
        # Attempt every owned cleanup even when an earlier step failed. Preserve the
        # lifecycle failure alongside cleanup diagnostics instead of replacing its cause.
        for cleanup in (
            lambda: docker.command("logs", name),
            lambda: docker.remove(name),
            lambda: docker.command("volume", "rm", volume),
        ):
            try:
                cleanup()
            except BaseException as error:
                failures.append(error)
    if len(failures) == 1:
        raise failures[0]
    if failures:
        raise BaseExceptionGroup("paper lifecycle and cleanup failures", failures)

    (work / "receipt.json").write_text(
        json.dumps(
            {
                "schema": 1,
                "result": "passed",
                "cleanup_complete": True,
                "state_preserved": True,
                "pairing_preserved": True,
                "journal_preserved": True,
                "mode": "paper",
                "scenario": "upgrade" if previous_image else "fresh",
                "initial_image": initial_image,
                "initial_version": previous_version if previous_image else version,
                "version": version,
                "channel": "docker" if compose is None else "compose",
                "image": image,
                "previous_image": previous_image,
                "checks": (
                    ["upgrade", "upgrade-journal", "upgrade-pairing"]
                    if previous_image
                    else ["fresh-candidate-paper"]
                )
                + [
                    "init",
                    "pair",
                    "health",
                    "veto",
                    "allow",
                    "resize",
                    "restart",
                    "journal",
                    "crash-recovery",
                    "crash-journal",
                    "reinstall",
                    "reinstall-journal",
                    "reinstall-pairing",
                    "cleanup",
                ],
                "last_decision_seq": last_seq,
            }
        )
        + "\n"
    )
