"""Install an emailed staging licence on authenticated released bytes, paper only."""

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import time
import tomllib
from pathlib import Path
from typing import Any

from guard_harness.cli import GuardCLI
from guard_harness.runner import RunError, run
from guard_harness.staged_subjects import _private
from guard_harness.testnet_run import ROOT, signed_binary


def valid_licence_key(key: str) -> bool:
    # Complete bounded wire token, including signature. Rust verifies its contents.
    return re.fullmatch(r"zgl1_[A-Za-z0-9_-]{1,4004}\.[A-Za-z0-9_-]{86}", key) is not None


def licensed_status(status: dict[str, Any], account: str, *, source: str = "file") -> None:
    if (
        status["mode"] != "paper"
        or status["account"].lower() != account.lower()
        or status["licence"]["state"] != "valid"
        or status["licence"]["fee_free"] is not True
        or status["licence"]["source"] != source
        or status["journal"]["ok"] is not True
    ):
        raise ValueError("installed licence/status admission failed")


def validate_renewal(renewal: dict[str, str], old_key: str) -> None:
    if (
        set(renewal) != {"key", "token"}
        or not re.fullmatch(r"[A-Za-z0-9_-]{43}", renewal["token"])
        or not valid_licence_key(renewal["key"])
        or renewal["key"] == old_key
    ):
        raise ValueError("distinct emailed renewal key and token required")


def enable_renewal(path: Path, token: str) -> None:
    text = path.read_text()
    parsed = tomllib.loads(text)
    if parsed.get("licence_auto_update", False) or parsed.get("licence_renewal_token"):
        raise ValueError("fresh opt-in config required")
    # Insert top-level settings before tables; never alter expiry, clock or policy.
    text = re.sub(r"(?m)^licence_auto_update\s*=.*\n", "", text)
    path.write_text(f'licence_auto_update = true\nlicence_renewal_token = "{token}"\n' + text)
    path.chmod(0o600)


def verify_auto_update(
    binary: Path,
    home: Path,
    logs: Path,
    cli: GuardCLI,
    environment: dict[str, str],
    account: str,
    old_key: str,
    renewed_key: str,
    *,
    previous_expiry_ms: int,
) -> None:
    if type(previous_expiry_ms) is not int or previous_expiry_ms <= 0:
        raise ValueError("authenticated initial licence expiry required")
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    config = home / "guard.toml"
    with (logs / "renewal-service.log").open("wb") as output:
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
            deadline = time.monotonic() + 180
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise ValueError("renewal paper service exited")
                try:
                    status = cli.status(url=f"http://127.0.0.1:{port}")
                except RunError:
                    time.sleep(0.5)
                    continue
                licensed_status(status, account, source="auto_update")
                persisted = tomllib.loads(config.read_text()).get("licence")
                end = status["licence"].get("expires_at_ms")
                if persisted == old_key:
                    pass
                elif persisted == renewed_key and type(end) is int and end > previous_expiry_ms:
                    return
                elif persisted != renewed_key:
                    raise ValueError("unexpected auto-update key")
                time.sleep(0.5)
            raise ValueError("renewed key was not fetched, persisted and applied by Guard")
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def install(
    assets: Path,
    work: Path,
    *,
    tag: str,
    commit: str,
    account: str,
    key: str,
    journey: str = "P1",
    renewal: dict[str, str] | None = None,
) -> None:
    if journey not in {"P1", "P2", "P3", "P6"}:
        raise ValueError("paid purchase journey required")
    if (journey == "P6") != (renewal is not None):
        raise ValueError("P6 requires an emailed renewed key and token")
    if renewal is not None:
        validate_renewal(renewal, key)
    _private(work, directory=True)
    if not re.fullmatch(r"0x[0-9a-fA-F]{40}", account):
        raise ValueError("licence account shape required")
    if not valid_licence_key(key):
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
    if renewal is not None:
        # The authenticated binary derives this from the verified licence issuer.
        # Never give a staging token to an older production-only renewal client.
        if (
            cli.licence().get("renewal_origin")
            != "https://staging.zunderlabs.com/api/licence/renewal"
        ):
            raise ValueError("P6 requires released issuer-derived staging renewal origin")
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
            if renewal is not None:
                old_end = status["licence"].get("expires_at_ms")
                if (
                    type(old_end) is not int
                    or not 0 < old_end - int(time.time() * 1000) <= 14 * 86_400_000
                ):
                    raise ValueError("P6 requires actually due staging licence; no clock override")
                enable_renewal(home / "guard.toml", renewal["token"])
                # The initial process started with auto-update off; restart below for opt-in.
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    if renewal is not None:
        verify_auto_update(
            binary,
            home,
            logs,
            cli,
            environment,
            account,
            key,
            renewal["key"],
            previous_expiry_ms=old_end,
        )
    receipt = {
        "schema": 1,
        "journey": journey,
        "commit": commit,
        "manifest_sha256": manifest_digest,
        "licensed": True,
        "fee_free": True,
        "mode": "paper",
        "service_stopped": True,
        **({"auto_updated": True} if renewal is not None else {}),
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
    parser.add_argument("--journey", choices=["P1", "P2", "P3", "P6"], default="P1")
    args = parser.parse_args()
    # This subprocess needs no checkout, inbox, payer or publishing credentials.
    environment = {"PATH": os.environ.get("PATH", os.defpath), "HOME": str(args.work)}
    os.environ.clear()
    os.environ.update(environment)
    try:
        captured = sys.stdin.buffer.read(33000).decode().strip()
        renewal = None
        if args.journey == "P6":
            payload = json.loads(captured)
            key = payload["old_key"]
            renewal = {"key": payload["new_key"], "token": payload["token"]}
        else:
            key = captured
        install(
            args.assets,
            args.work,
            tag=args.tag,
            commit=args.commit,
            account=args.account,
            key=key,
            journey=args.journey,
            renewal=renewal,
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
