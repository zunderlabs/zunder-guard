"""SSM-side paper lifecycle on the actual signed stack binary; emits no client keys."""

import argparse
import base64
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

from guard_harness.cli import PAIR_SCHEMA, Pair, decode_json
from guard_harness.paper_bot import LocalGuard, PaperError
from guard_harness.paper_roundtrip import round_trip
from guard_harness.runner import run

HOME = Path("/var/lib/zunder-guard")
BINARY = Path("/usr/local/bin/zunder-guard")
BASE = Path("/opt/guard-install-e2e")
MAINNET_HOME = Path("/var/lib/zunder-guard-mainnet")
MAINNET_CREDENTIAL = Path("/etc/credstore.encrypted/zunder-guard-mainnet.hl-api-wallet-key")
MAINNET_UNIT = Path("/etc/systemd/system/zunder-guard-mainnet.service")
MAINNET_BINARY = Path("/opt/zunder-guard-mainnet/bin/zunder-guard")


def command(words: list[str], name: str) -> str:
    return run(words, log=BASE / f"{name}.log", timeout=300, sensitive_output=True).output.strip()


def health(version: str) -> None:
    guard = LocalGuard("http://127.0.0.1:8547")
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            status = guard.request("/guard/status")
            if status.get("last_sync_ms") and status.get("version") == version:
                expected = json.loads((BASE / "expected.json").read_bytes())["account"]
                if status.get("account", "").lower() != expected.lower():
                    raise RuntimeError("stack paper account differs from explicit read account")
                if status.get("mode") != "paper":
                    raise RuntimeError("stack runtime is not paper; signed bot refused")
                return
        except PaperError:
            pass
        time.sleep(1)
    raise RuntimeError("stack paper sync deadline")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def image(expected: str) -> None:
    if sha(BINARY) != expected:
        raise RuntimeError("stack executable differs from released subject")


def preserve(value: dict[str, Any]) -> None:
    for name, captured in value["files"].items():
        original = base64.b64decode(captured)
        actual = (HOME / name).read_bytes()
        if (name == "guard.toml" and original != actual) or (
            name != "guard.toml" and not actual.startswith(original)
        ):
            raise RuntimeError("stack lifecycle changed config/pairing/journal history")


def before(
    version: str, candidate_digest: str, previous: str, previous_digest: str
) -> dict[str, object]:
    image(candidate_digest)
    health(version)
    command(["systemctl", "stop", "zunder-guard"], "stop-bootstrap")
    command(["sh", str(BASE / "previous-i"), "--install-only"], "previous-install")
    image(previous_digest)
    command(["systemctl", "start", "zunder-guard"], "start-previous")
    health(previous)
    output = command(
        ["sudo", "-u", "zunder-guard", str(BINARY), "--home", str(HOME), "pair", "--json"], "pair"
    )
    value = decode_json(output, PAIR_SCHEMA)
    pair = Pair(value["client_address"], value["client_key"])
    command(["systemctl", "restart", "zunder-guard"], "pair-restart")
    health(previous)
    decisions = round_trip(LocalGuard("http://127.0.0.1:8547"), pair)
    if [value.verdict for value in decisions] != ["veto", "allow", "resize"]:
        raise RuntimeError("paper decision outcomes differ")
    old_pid = command(
        ["systemctl", "show", "--property", "MainPID", "--value", "zunder-guard"],
        "before-crash-pid",
    )
    command(["systemctl", "kill", "--kill-who=main", "--signal=KILL", "zunder-guard"], "crash")
    for _ in range(60):
        pid = command(
            ["systemctl", "show", "--property", "MainPID", "--value", "zunder-guard"],
            "recovered-pid",
        )
        if pid.isdigit() and int(pid) > 0 and pid != old_pid:
            break
        time.sleep(1)
    else:
        raise RuntimeError("systemd did not recover a distinct owned process after crash")
    health(previous)
    files = {}
    for name in ("guard.toml", "risk-paper.jsonl", "decisions-paper.jsonl"):
        body = (HOME / name).read_bytes()
        # Journal writers consume their zero-filled reserve when appending.
        # Retain every populated byte; configuration must remain byte-exact.
        if name.endswith(".jsonl"):
            body = body.rstrip(b"\x00")
        files[name] = base64.b64encode(body).decode()
    state: dict[str, Any] = {
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "client_address": pair.address,
        "client_key": pair.key,
        "files": files,
    }
    path = BASE / "private-state.json"
    with path.open("x") as state_output:
        path.chmod(0o600)
        json.dump(state, state_output)
    return {
        "stage": "before-reboot",
        "boot_id_sha256": hashlib.sha256(state["boot_id"].encode()).hexdigest(),
    }


def after(version: str, candidate_digest: str, previous: str) -> dict[str, object]:
    path = BASE / "private-state.json"
    if path.is_symlink() or path.stat().st_uid != 0 or path.stat().st_mode & 0o077:
        raise RuntimeError("paper pairing state is not private/root-owned")
    state = json.loads(path.read_bytes())
    if state["boot_id"] == Path("/proc/sys/kernel/random/boot_id").read_text().strip():
        raise RuntimeError("instance did not actually reboot")
    health(previous)
    preserve(state)
    pair = Pair(state["client_address"], state["client_key"])
    for step in ("upgrade", "reinstall"):
        command(["systemctl", "stop", "zunder-guard"], f"{step}-stop")
        command(["sh", str(BASE / "candidate-i"), "--install-only"], f"{step}-install")
        image(candidate_digest)
        preserve(state)
        command(["systemctl", "start", "zunder-guard"], f"{step}-start")
        health(version)
        round_trip(LocalGuard("http://127.0.0.1:8547"), pair)
        preserve(state)
    command(["sh", str(BASE / "candidate-i"), "--uninstall"], "uninstall")
    if BINARY.exists() or Path("/etc/systemd/system/zunder-guard.service").exists():
        raise RuntimeError("stack native uninstall retained registration/binary")
    preserve(state)
    path.unlink()
    return {
        "stage": "passed",
        "mode": "paper",
        "coverage": [
            "signed-template-url",
            "signed-release",
            "stack-bootstrap",
            "paper-allow-resize-veto",
            "pairing",
            "restart",
            "crash-recovery",
            "instance-reboot",
            "previous-release-upgrade",
            "reinstall",
            "journal-prefix",
            "client-signature-survives",
            "uninstall",
            "data-retained",
        ],
    }


def mainnet(candidate_digest: str) -> dict[str, object]:
    """A fresh protected profile refuses before storing a generated unapproved wallet."""
    from guard_harness.mainnet_terminal import TerminalError, refusal

    expected = json.loads((BASE / "expected.json").read_bytes())
    guarded = (MAINNET_HOME / "guard.toml", MAINNET_CREDENTIAL, MAINNET_UNIT)
    if any(path.exists() for path in guarded):
        raise TerminalError("disposable stack mainnet profile already exists")
    log = BASE / "mainnet-refusal.log"
    text, code = refusal(
        [
            "/bin/sh",
            str(BASE / "candidate-i"),
            "--network",
            "mainnet",
            "--service-instance",
            "mainnet",
            "--account",
            expected["account"],
            "--rules",
            expected["rules"],
            "--equity-cap",
            "100",
            "--ip-share",
            "0.1",
            "--listen",
            "127.0.0.1:18549",
        ],
        expected["account"],
        log=log,
    )
    if MAINNET_BINARY.is_symlink() or sha(MAINNET_BINARY) != candidate_digest:
        raise TerminalError("refused stack activation used a different executable")
    if any(path.exists() for path in guarded):
        raise TerminalError("refused stack activation wrote mainnet state or registration")
    return {
        "stage": "refused",
        "exit_code": code,
        "log": text,
        "config_written": False,
        "credential_written": False,
        "service_enabled": False,
        "service_started": False,
        "binary_sha256": candidate_digest,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("before", "after", "mainnet"), required=True)
    for name in ("version", "previous-version", "binary-sha256", "previous-binary-sha256"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or BASE.is_symlink():
        raise RuntimeError("disposable stack controller requires its protected root workspace")
    value = (
        mainnet(args.binary_sha256)
        if args.phase == "mainnet"
        else (
            before(
                args.version, args.binary_sha256, args.previous_version, args.previous_binary_sha256
            )
            if args.phase == "before"
            else after(args.version, args.binary_sha256, args.previous_version)
        )
    )
    print(json.dumps(value))


if __name__ == "__main__":
    main()
