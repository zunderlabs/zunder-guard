"""Opt-in released-byte setup refusals: no venue key, service or exchange request."""

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

import pytest


@pytest.mark.parametrize("case", ["no-consent", "other-account", "no-cap"])
def test_mainnet_init_refuses_before_creating_state(tmp_path: Path, case: str) -> None:
    binary_value = os.environ.get("GUARD_TEST_BINARY")
    digest = os.environ.get("GUARD_TEST_BINARY_SHA256")
    account = os.environ.get("GUARD_PAPER_READ_ACCOUNT")
    if not binary_value or not digest or not account:
        pytest.skip("requires an authenticated release binary, its digest and a read-only account")
    assert re.fullmatch(r"[0-9a-f]{64}", digest), "authenticated SHA256 required"
    assert re.fullmatch(r"0x[0-9a-fA-F]{40}", account), "account shape required"
    binary = Path(binary_value).resolve()
    with binary.open("rb") as stream:
        assert hashlib.file_digest(stream, "sha256").hexdigest() == digest
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    rules_file = Path(__file__).resolve().parents[2] / "rules/vectors.json"
    rules = json.loads(rules_file.read_bytes())["valid"][0]["canonical"]
    command = [
        str(binary),
        "--home",
        str(home),
        "init",
        "--non-interactive",
        "--network",
        "mainnet",
        "--no-key",
        "--rules",
        rules,
        "--account",
        account,
    ]
    expected = "mainnet needs --confirm-mainnet"
    if case == "other-account":
        other = account[:-1] + ("1" if account[-1] == "0" else "0")
        command.extend(["--confirm-mainnet", other])
        expected = "the confirmation does not name the account"
    elif case == "no-cap":
        command.extend(["--confirm-mainnet", account])
        expected = "mainnet needs --equity-cap"
    # No inherited wallet/key/consent settings; stdin is closed. This test never starts Guard.
    result = subprocess.run(
        command,
        env={"PATH": os.defpath, "HOME": str(home)},
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=15,
        check=False,
    )
    (tmp_path / "refusal.log").write_bytes(result.stdout + result.stderr)
    assert result.returncode != 0, "mainnet setup unexpectedly accepted"
    assert expected.encode() in result.stdout + result.stderr, "expected setup refusal missing"
    assert not list(home.iterdir()), "refused setup left configuration, keys or journals"
