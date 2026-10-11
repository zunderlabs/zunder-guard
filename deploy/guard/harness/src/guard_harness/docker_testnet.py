"""Released Docker/Compose Testnet custody and lifecycle; no exchange requests."""

import hashlib
import io
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import tarfile
import tempfile
import time
import tomllib
import uuid
from pathlib import Path, PurePosixPath
from typing import Any

from eth_account import Account

from guard_harness import crash_process
from guard_harness.cli import PAIR_SCHEMA, decode_json
from guard_harness.docker_paper import Compose, Docker
from guard_harness.paper_bot import LocalGuard, PaperError
from guard_harness.runner import RunResult, run
from guard_harness.staged_subjects import _private
from guard_harness.testnet_run import ROOT
from guard_harness.testnet_scan import Read, TestnetReads, flat_scan

IMAGE = r"ghcr\.io/zunderlabs/zunder-guard@sha256:[0-9a-f]{64}"
MAX_ARCHIVE = 32 * 1024 * 1024


def require(value: bool, reason: str) -> None:
    if not value:
        raise PaperError(reason)


class TestnetDocker(Docker):
    def command(self, *args: str, sensitive: bool = True, stdin: bytes = b"") -> RunResult:
        self.sequence += 1
        env = {name: os.environ[name] for name in ("PATH", "HOME") if name in os.environ}
        return run(
            ["docker", *args],
            log=self.logs / f"docker-{self.sequence}.log",
            timeout=120,
            env=env | self.extra_env,
            stdin=stdin,
            secrets=self.secrets,
            sensitive_output=True,
        )

    def remove(self, name: str) -> None:
        if self.command(
            "ps", "-a", "--filter", "name=^" + name + "$", "--format", "{{.Names}}"
        ).output.strip():
            self.command("rm", "--force", name)


class TestnetCompose(TestnetDocker):
    def __init__(
        self,
        logs: Path,
        source: Path,
        image: str,
        name: str,
        volume: str,
        port: int,
        credential: Path,
    ) -> None:
        super().__init__(logs)
        original = Compose(logs, source, image, name, volume, port)
        self.config, self.image = original.config, image
        text = self.config.read_text()
        replacements = {
            "      # ZUNDER_GUARD_NETWORK: testnet\n": "      ZUNDER_GUARD_NETWORK: testnet\n",
            "      # ZUNDER_GUARD_KEY_FILE: /run/secrets/hl-api-wallet-key\n": (
                "      ZUNDER_GUARD_KEY_FILE: /run/secrets/hl-api-wallet-key\n"
            ),
            "    # secrets: [hl-api-wallet-key]\n": "    secrets: [hl-api-wallet-key]\n",
            (
                "# secrets:\n#   hl-api-wallet-key:\n"
                "#     file: ./hl-api-wallet-key    # chmod 600; never commit it\n"
            ): "secrets:\n  hl-api-wallet-key:\n    file: " + json.dumps(str(credential)) + "\n",
        }
        for old, new in replacements.items():
            require(text.count(old) == 1, "signed Compose Testnet secret layout differs")
            text = text.replace(old, new)
        self.config.unlink()
        self.config = credential.parent / (logs.name + "-compose.yaml")
        self.config.write_text(text)
        self.config.chmod(0o600)
        self.extra_env = {"ZUNDER_GUARD_IMAGE": image}

    def command(self, *args: str, sensitive: bool = True, stdin: bytes = b"") -> RunResult:
        if args[0] != "run":
            return super().command(*args, stdin=stdin)
        prefix = ("compose", "--file", str(self.config))
        if "-d" in args:
            return super().command(
                *prefix, "up", "--detach", "--no-build", "--pull", "never", "guard"
            )
        command = args[args.index(self.image) + 1 :]
        return super().command(
            *prefix, "run", "--rm", "--no-deps", "-T", "guard", *command, stdin=stdin
        )

    def remove(self, name: str) -> None:
        self.command("compose", "--file", str(self.config), "down", "--remove-orphans")
        super().remove(name)


def ready(guard: LocalGuard, *, account: str, version: str, after: int = 0) -> int:
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            value = guard.request("/guard/status")
            require(isinstance(value, dict), "Testnet status shape differs")
            require(
                value.get("mode") == value.get("network") == "testnet"
                and value.get("account", "").lower() == account.lower()
                and value.get("version") == version,
                "Testnet runtime identity differs",
            )
            started = value.get("started_at_ms")
            if type(started) is int and started > after and value.get("last_sync_ms"):
                require(
                    value.get("journal", {}).get("ok") is True,
                    "Testnet decision journal is not healthy",
                )
                require(
                    guard.request("/healthz") == {"status": "ok"}, "Testnet health/recovery differs"
                )
                return int(started)
        except (PaperError, OSError):
            pass
        time.sleep(1)
    raise PaperError("Testnet container readiness deadline")


def archive_state(
    body: bytes, *, account: str, wallet: str, client: str, volume_key: bool, initial: bool = False
) -> dict[str, bytes]:
    require(0 < len(body) <= MAX_ARCHIVE, "Testnet state archive size differs")
    files: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(body), mode="r:*") as source:
        for member in source:
            parts = PurePosixPath(member.name).parts
            require(
                not member.name.startswith("/") and ".." not in parts,
                "Testnet state archive path differs",
            )
            if member.isdir():
                continue
            if len(parts) == 2 and parts[0] == "data":
                parts = parts[1:]
            require(
                len(parts) == 1 and member.isfile() and member.size <= 8 * 1024 * 1024,
                "Testnet state archive member differs",
            )
            name = parts[0]
            require(name not in files, "duplicate Testnet state archive member")
            stream = source.extractfile(member)
            require(stream is not None, "Testnet state archive member missing")
            assert stream is not None
            with stream:
                files[name] = stream.read()
            if name == "api-wallet-key":
                require(
                    volume_key
                    and member.uid == member.gid == 65532
                    and member.mode & 0o777 == 0o600,
                    "documented Testnet volume key custody differs",
                )
    require(
        bool(files.get("guard.toml"))
        and bool(files.get("risk.jsonl"))
        and (initial or "decisions.jsonl" in files),
        "Testnet config/journals missing",
    )
    require(("api-wallet-key" in files) == volume_key, "Testnet credential source differs")
    config = tomllib.loads(files["guard.toml"].decode())
    require(
        config.get("mode") == config.get("network") == "testnet"
        and config.get("account", "").lower() == account.lower()
        and config.get("api_wallet", "").lower() == wallet.lower()
        and config.get("allow_mainnet", False) is False
        and client in config.get("auth", {}).get("clients", []),
        "Testnet config/account/pairing custody differs",
    )
    if initial:
        files.setdefault("decisions.jsonl", b"")
    for name in ("risk.jsonl", "decisions.jsonl"):
        files[name] = files[name].rstrip(b"\x00")
    # Check the complete persisted journal, not the endpoint's bounded recent window.
    previous_check = ""
    for line in files["decisions.jsonl"].splitlines():
        text = line.decode()
        record = json.loads(text)
        match = re.search(r'"event"\s*:\s*', text)
        require(match is not None, "Testnet journal event missing")
        assert match is not None
        event, end = json.JSONDecoder().raw_decode(text, match.end())
        check = hashlib.sha3_256((previous_check + text[match.end() : end]).encode()).hexdigest()
        require(
            record.get("prev") == previous_check and record.get("check") == check,
            "Testnet complete journal chain differs",
        )
        previous_check = check
        require(
            isinstance(event, dict) and isinstance(event.get("kind"), str),
            "Testnet decision journal event differs",
        )
        require(
            event["kind"] not in {"decision", "intent", "sent", "recovered", "protect", "flatten"},
            "unexpected Testnet exchange intent/event",
        )
    return files


def snapshot(docker: TestnetDocker, name: str, **scope: Any) -> dict[str, bytes]:
    env = {key: os.environ[key] for key in ("PATH", "HOME") if key in os.environ}
    result = subprocess.run(
        ["docker", "cp", name + ":/data/.", "-"],
        input=b"",
        capture_output=True,
        timeout=60,
        check=False,
        env=env,
    )
    require(result.returncode == 0, "owned Testnet volume snapshot failed; output withheld")
    return archive_state(result.stdout, **scope)


def retained(old: dict[str, bytes], new: dict[str, bytes]) -> None:
    require(set(old) <= set(new), "Testnet upgrade lost persistent files")
    for name, original in old.items():
        require(
            new[name].startswith(original)
            if name in {"risk.jsonl", "decisions.jsonl"}
            else new[name] == original,
            "Testnet upgrade changed config/key or journal prefix",
        )


def no_exchange(read: Read, account: str, started_ms: int) -> None:
    fills = read({"type": "userFillsByTime", "user": account, "startTime": started_ms})
    require(isinstance(fills, list) and not fills, "unexpected Testnet fills; no empty fallback")


def lifecycle(
    image: str,
    account: str,
    *,
    api_wallet: str,
    key: bytes,
    work: Path,
    previous_image: str,
    version: str,
    previous_version: str,
    compose: Path | None = None,
    previous_compose: Path | None = None,
    read: Read | None = None,
) -> None:
    require(os.environ.get("GUARD_C6_SERIALIZED") == "1", "shared C6 serialization required")
    require(
        bool(re.fullmatch(IMAGE, image))
        and bool(re.fullmatch(IMAGE, previous_image))
        and image != previous_image,
        "distinct authenticated Testnet images required",
    )
    require(
        bool(re.fullmatch(r"0x[0-9a-fA-F]{40}", account))
        and bool(re.fullmatch(r"0x[0-9a-fA-F]{40}", api_wallet)),
        "explicit Testnet identities required",
    )
    require(bool(re.fullmatch(rb"[0-9a-fA-F]{64}\n", key)), "private framed Testnet key required")
    require(
        Account.from_key(key.decode().strip()).address.lower() == api_wallet.lower(),
        "Testnet API wallet differs from framed key",
    )
    require(
        (compose is None) == (previous_compose is None), "both signed Compose releases required"
    )
    _private(work.parent, directory=True)
    require(not work.exists() and not work.is_symlink(), "fresh Testnet workspace required")
    work.mkdir(mode=0o700)
    reads = read or TestnetReads()
    started_ms = int(time.time() * 1000)
    # No volume, credential, container or signing process before this complete scan.
    preflight = flat_scan(reads, account)
    name = "guard-testnet-" + uuid.uuid4().hex
    volume = name + "-data"
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    credential_dir: Path | None = None
    credential: Path | None = None
    docker: TestnetDocker = TestnetDocker(work)
    try:
        if compose is not None:
            _private(work.parent.parent, directory=True)
            credential_dir = Path(
                tempfile.mkdtemp(prefix=".guard-testnet-credentials-", dir=work.parent.parent)
            )
            credential = credential_dir / "hl-api-wallet-key"
            with credential.open("xb") as stream:
                credential.chmod(0o600)
                stream.write(key)
            run(
                ["sudo", "-n", "chown", "65532:65532", str(credential)],
                log=work / "credential-owner.log",
                timeout=10,
                stdin=b"",
                sensitive_output=True,
            )
            info = credential.stat()
            require(
                info.st_uid == 65532
                and info.st_gid == 65532
                and stat.S_IMODE(info.st_mode) == 0o600,
                "documented Compose secret ownership/mode differs",
            )
        if previous_compose is not None:
            assert credential is not None
            docker = TestnetCompose(
                work,
                previous_compose,
                previous_image,
                name,
                volume,
                port,
                credential,
            )
        docker.secrets = (key.decode().strip(),)
    except BaseException:
        if credential_dir is not None:
            shutil.rmtree(credential_dir)
        raise
    active = False
    created = False
    failures: list[BaseException] = []
    safe_cleanup = True
    scope: dict[str, Any] = dict(
        account=account, wallet=api_wallet, client="", volume_key=compose is None
    )
    try:
        created = True  # A failed create request can still have created the volume.
        docker.command("volume", "create", volume)
        mounted = ("--mount", f"type=volume,source={volume},target=/data")
        rules = json.loads((ROOT / "rules/vectors.json").read_bytes())["valid"][0]["canonical"]
        init = [
            "init",
            "--non-interactive",
            "--network",
            "testnet",
            "--account",
            account,
            "--rules",
            rules,
            "--equity-cap",
            "40",
            "--ip-share",
            "0.1",
            "--key-stdin",
        ]
        if compose is not None:
            init.extend(["--no-key", "--service-key-check"])
        docker.command("run", "--rm", "-i", *mounted, previous_image, *init, stdin=key)
        pair = decode_json(
            docker.command("run", "--rm", *mounted, previous_image, "pair", "--json").output,
            PAIR_SCHEMA,
        )
        scope["client"] = pair["client_address"]
        docker.secrets += (pair["client_key"],)
        docker.command(
            "create", "--name", name, *mounted, previous_image, "run", "--network", "testnet"
        )
        previous: dict[str, bytes] = snapshot(docker, name, initial=True, **scope)
        docker.command("rm", name)
        if compose is None:
            require(
                previous["api-wallet-key"].strip() == key.strip(), "volume key readback differs"
            )
        guard = LocalGuard(f"http://127.0.0.1:{port}")
        last_start = 0
        for stage, released_image, released_version, subject in (
            ("previous", previous_image, previous_version, previous_compose),
            ("upgrade", image, version, compose),
            ("reinstall", image, version, compose),
        ):
            if stage != "previous":
                docker.remove(name)
                directory = work / stage
                directory.mkdir(mode=0o700)
                if subject is None:
                    docker = TestnetDocker(directory)
                else:
                    assert credential is not None
                    docker = TestnetCompose(
                        directory,
                        subject,
                        released_image,
                        name,
                        volume,
                        port,
                        credential,
                    )
                docker.secrets = (key.decode().strip(), pair["client_key"])
            if isinstance(reads, TestnetReads):
                reads.start_phase(timeout=720)
            flat_scan(reads, account)
            active = True  # A failed request can still have started the signing process.
            docker.command(
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
                f"127.0.0.1:{port}:8547",
                "--env",
                "ZUNDER_GUARD_LISTEN=0.0.0.0:8547",
                released_image,
                "run",
                "--network",
                "testnet",
            )
            require(
                docker.command("port", name, "8547/tcp").output.strip() == f"127.0.0.1:{port}",
                "Testnet port escaped loopback",
            )
            require(
                docker.command("inspect", "--format", "{{.Config.Image}}", name).output.strip()
                == released_image,
                "Testnet container image differs",
            )
            last_start = ready(guard, account=account, version=released_version, after=last_start)
            if stage == "previous":
                flat_scan(reads, account)
                docker.command("restart", name)
                last_start = ready(
                    guard, account=account, version=released_version, after=last_start
                )
                before = int(
                    docker.command("inspect", "--format", "{{.RestartCount}}", name).output
                )
                process = docker.command("top", name, "-eo", "pid,comm").output.splitlines()
                guards = [
                    line.split() for line in process[1:] if line.split()[-1:] == ["zunder-guard"]
                ]
                require(
                    len(guards) == 1
                    and len(guards[0]) == 2
                    and guards[0][0].isdigit()
                    and int(guards[0][0]) > 1,
                    "owned Testnet crash process differs",
                )
                identity = docker.command("inspect", "--format", "{{.Id}}", name).output.strip()
                require(
                    bool(re.fullmatch(r"[0-9a-f]{64}", identity)),
                    "owned Testnet container identity differs",
                )
                run(
                    [
                        "sudo",
                        "-n",
                        "python3",
                        str(Path(crash_process.__file__).resolve()),
                        guards[0][0],
                        identity,
                    ],
                    log=work / "crash.log",
                    timeout=10,
                    stdin=b"",
                    sensitive_output=True,
                )
                last_start = ready(
                    guard, account=account, version=released_version, after=last_start
                )
                require(
                    int(docker.command("inspect", "--format", "{{.RestartCount}}", name).output)
                    > before,
                    "Testnet crash restart unconfirmed",
                )
            flat_scan(reads, account)
            no_exchange(reads, account, started_ms)
            docker.command("stop", name)
            active = False
            observed = snapshot(docker, name, **scope)
            if previous is not None:
                retained(previous, observed)
            previous = observed
    except BaseException as error:
        failures.append(error)
    finally:
        if isinstance(reads, TestnetReads):
            reads.start_phase(timeout=720)
        if active:
            try:
                flat_scan(reads, account)
                docker.command("stop", name)
                active = False
            except BaseException as error:
                safe_cleanup = False
                failures.append(error)
        if safe_cleanup:
            for cleanup in (
                (lambda: docker.remove(name), lambda: docker.command("volume", "rm", volume))
                if created
                else ()
            ):
                try:
                    cleanup()
                except BaseException as error:
                    failures.append(error)
            if credential_dir is not None:
                try:
                    shutil.rmtree(credential_dir)
                    require(not credential_dir.exists(), "private Compose credential remains")
                except BaseException as error:
                    failures.append(error)
            try:
                require(
                    not docker.command(
                        "ps", "-a", "--filter", "name=^" + name + "$", "--format", "{{.Names}}"
                    ).output.strip(),
                    "owned Testnet container remains",
                )
                require(
                    volume
                    not in docker.command(
                        "volume", "ls", "--format", "{{.Name}}"
                    ).output.splitlines(),
                    "owned Testnet volume remains",
                )
                if compose is not None:
                    require(
                        not docker.command(
                            "network",
                            "ls",
                            "--filter",
                            "label=com.docker.compose.project=" + name,
                            "--format",
                            "{{.ID}}",
                        ).output.strip(),
                        "owned Testnet Compose network remains",
                    )
                postflight = flat_scan(reads, account)
                no_exchange(reads, account, started_ms)
            except BaseException as error:
                failures.append(error)
        else:
            # Names expose owned resources without exposing their credential or contents.
            (work / "recovery.json").write_text(
                json.dumps(dict(container=name, volume=volume, cleanup_complete=False)) + "\n"
            )
    if len(failures) == 1:
        raise failures[0]
    if failures:
        raise BaseExceptionGroup("Testnet container lifecycle/cleanup failures", failures)
    (work / "receipt.json").write_text(
        json.dumps(
            dict(
                schema=1,
                result="passed",
                mode="testnet",
                channel="docker" if compose is None else "compose",
                image=image,
                previous_image=previous_image,
                custody="documented-volume" if compose is None else "compose-secret",
                cleanup_complete=True,
                state_preserved=True,
                pairing_preserved=True,
                journal_preserved=True,
                no_exchange=True,
                preflight=preflight,
                postflight=postflight,
                decision_journal_sha256=hashlib.sha256(previous["decisions.jsonl"]).hexdigest()
                if previous
                else None,
                coverage=[
                    "init",
                    "custody-readback",
                    "health",
                    "restart",
                    "crash-recovery",
                    "journal-history",
                    "upgrade",
                    "reinstall",
                    "pairing-retained",
                    "uninstall",
                    "cleanup",
                    "no-exchange",
                ],
            )
        )
        + "\n"
    )
