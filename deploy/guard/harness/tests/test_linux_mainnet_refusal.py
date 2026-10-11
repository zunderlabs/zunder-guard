"""Safety checks exercise a local terminal fixture, never treat it as released proof."""

import sys
from pathlib import Path

import pytest

from guard_harness.linux_lifecycle import LifecycleError
from guard_harness.linux_mainnet_refusal import terminal_refusal


def script(tmp_path: Path, *, echo: bool, success: bool = False) -> list[str]:
    code = """
import sys,termios
print('Keep these? [Y/edit]',flush=True);input()
print('Type the account address again to confirm:',flush=True);input()
if DISABLE:
    attrs=termios.tcgetattr(0);attrs[3]&=~termios.ECHO;termios.tcsetattr(0,termios.TCSANOW,attrs)
print('API wallet private key (not shown while typing):',flush=True)
key=input()
print(key)
print('is not an API wallet of account',flush=True)
raise SystemExit(EXIT)
""".replace("DISABLE", str(not echo)).replace("EXIT", "0" if success else "1")
    target = tmp_path / "terminal.py"
    target.write_text(code)
    return [sys.executable, str(target)]


def test_terminal_redacts_throwaway_private_key(tmp_path: Path) -> None:
    output = terminal_refusal(script(tmp_path, echo=False), "0x" + "1" * 40, timeout=5)
    assert "[REDACTED]" in output.output
    assert output.exit_code == 1
    assert "0x" + "1" * 40 not in output.output
    assert "is not an API wallet" in output.output


def test_terminal_never_sends_key_with_echo_enabled(tmp_path: Path) -> None:
    with pytest.raises(LifecycleError, match="disable terminal echo"):
        terminal_refusal(script(tmp_path, echo=True), "0x" + "1" * 40, timeout=5)


def test_zero_exit_is_not_refusal_proof(tmp_path: Path) -> None:
    with pytest.raises(LifecycleError, match="unexpectedly passed"):
        terminal_refusal(script(tmp_path, echo=False, success=True), "0x" + "1" * 40, timeout=5)


def test_unresponsive_terminal_is_bounded() -> None:
    with pytest.raises(LifecycleError, match="deadline"):
        terminal_refusal(
            [sys.executable, "-c", "import time;time.sleep(30)"], "0x" + "1" * 40, timeout=0.1
        )


def test_fresh_container_create_consent_and_account_log_redaction(tmp_path: Path) -> None:
    account = "0x" + "1" * 40
    argv = script(tmp_path, echo=False)
    target = Path(argv[1])
    code = target.read_text().replace(
        "print('Keep these?",
        "print('Type CREATE guard-refusal-fixture to create this NEW persistent volume:',"
        "flush=True);input()\nprint('Keep these?",
    )
    target.write_text(code)
    log = tmp_path / "refusal.log"
    result = terminal_refusal(argv, account, timeout=5, log=log, volume="guard-refusal-fixture")
    assert result.exit_code == 1
    assert account not in log.read_text()
    assert "[ACCOUNT]" in log.read_text()
    assert result.output == log.read_bytes().decode()
