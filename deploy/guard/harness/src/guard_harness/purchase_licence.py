"""Install an emailed staging licence on authenticated released bytes, paper only."""

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from guard_harness.cli import GuardCLI
from guard_harness.runner import RunError, run
from guard_harness.staged_subjects import _private
from guard_harness.testnet_run import ROOT, signed_binary


def licensed_status(status: dict[str, Any], account: str) -> None:
    if (
        status["mode"] != "paper"
        or status["account"].lower() != account.lower()
        or status["licence"]["state"] != "valid"
        or status["licence"]["fee_free"] is not True
        or status["licence"]["source"] != "file"
        or status["journal"]["ok"] is not True
    ):
        raise ValueError("installed licence/status admission failed")


def install(
    assets: Path, work: Path, *, tag: str, commit: str, account: str, key: str, journey: str = "P1"
) -> None:
    if journey not in {"P1", "P2", "P3"}:
        raise ValueError("paid purchase journey required")
    _private(work, directory=True)
    if not re.fullmatch(r"0x[0-9a-fA-F]{40}", account):
        raise ValueError("licence account shape required")
    if not re.fullmatch(r"zgl1_[A-Za-z0-9_-]{1,16000}", key):
        raise ValueError("single emailed licence required")
    binary = work / "zunder-guard"
    _, manifest_digest = signed_binary(assets, binary, tag=tag, commit=commit)
    binary.chmod(0o700)
    home = work / "home"
    home.mkdir(mode=0o700)
    logs = work / "runtime-logs"
    rules = json.loads((ROOT / "rules/vectors.json").read_bytes())["valid"][0]["canonical"]
    environment = {"PATH": os.defpath, "HOME": str(home)}
    run(
        [
            str(binary),
            "--home",
            str(home),
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
        ],
        log=logs / "init.log",
        timeout=60,
        env=environment,
        sensitive_output=True,
    )
    cli = GuardCLI(binary, logs, home)
    cli.set_licence(key)
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    with (logs / "service.log").open("wb") as output:
        process = subprocess.Popen(
            [
                str(binary),
                "--home",
                str(home),
                "run",
                "--network",
                "paper",
                "--listen",
                f"127.0.0.1:{port}",
            ],
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=output,
        )
        try:
            deadline = time.monotonic() + 45
            while True:
                if process.poll() is not None:
                    raise ValueError("licensed paper service exited")
                try:
                    status = cli.status(url=f"http://127.0.0.1:{port}")
                    break
                except RunError:
                    if time.monotonic() >= deadline:
                        raise ValueError("licensed paper status deadline") from None
                    time.sleep(0.5)
            licensed_status(status, account)
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    receipt = {
        "schema": 1,
        "journey": journey,
        "commit": commit,
        "manifest_sha256": manifest_digest,
        "licensed": True,
        "fee_free": True,
        "mode": "paper",
        "service_stopped": True,
    }
    path = work / "licence-receipt.json"
    with path.open("x") as stream:
        path.chmod(0o600)
        stream.write(json.dumps(receipt) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--account", required=True)
    parser.add_argument("--journey", choices=["P1", "P2", "P3"], default="P1")
    args = parser.parse_args()
    # This subprocess needs no checkout, inbox, payer or publishing credentials.
    environment = {"PATH": os.environ.get("PATH", os.defpath), "HOME": str(args.work)}
    os.environ.clear()
    os.environ.update(environment)
    try:
        key = sys.stdin.buffer.read(16007).decode().strip()
        install(
            args.assets,
            args.work,
            tag=args.tag,
            commit=args.commit,
            account=args.account,
            key=key,
            journey=args.journey,
        )
        print("Released-byte licence accepted; fee-free paper status; service stopped")
        return 0
    except Exception:
        print(
            "Released-byte licence verification failed; private diagnostics withheld",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
