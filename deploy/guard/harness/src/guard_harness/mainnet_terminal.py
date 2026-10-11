"""Actual hidden terminal setup with an ephemeral unapproved wallet; no order client."""

import errno
import os
import re
import secrets
import select
import time
from pathlib import Path


class TerminalError(RuntimeError):
    """Mainnet setup did not reach the expected read-only venue refusal."""


KEY_PROMPTS = (
    "API wallet private key (not shown while typing):",
    "API wallet key (hidden, checked for service setup):",
)


def refusal(
    argv: list[str], account: str, *, log: Path, windows: bool = False, timeout: float = 900
) -> tuple[str, int]:
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
    ):
        raise TerminalError("throwaway mainnet setup is hosted disposable only")
    key = secrets.token_hex(32)
    clean = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith("ZUNDER_") and "WALLET" not in name and "TOKEN" not in name
    }
    text, sent, key_sent, status = "", set(), False, None
    descriptor = -1
    pid = 0
    child = None
    if windows:
        from winpty import Backend, PtyProcess

        child = PtyProcess.spawn(argv, env=clean, backend=Backend.ConPTY)
    else:
        import pty

        pid, descriptor = pty.fork()
        if pid == 0:
            os.execve(argv[0], argv, clean)
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            channel = child.fileobj if child is not None else descriptor
            readable, _, _ = select.select([channel], [], [], 0.2)
            if readable:
                try:
                    chunk = (
                        child.read(65536)
                        if child is not None
                        else os.read(descriptor, 65536).decode(errors="replace")
                    )
                except EOFError:
                    chunk = ""
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    chunk = ""
                text += chunk
                if key in text:
                    raise TerminalError("terminal echoed the disposable wallet input")
                if len(text) > 262144:
                    raise TerminalError("protected setup exceeded bounded diagnostic output")
                visible = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", text)
                prompts = [
                    ("Keep these? [Y/edit]", ""),
                    ("Type the account address again to confirm:", account),
                ]
                prompts += [(prompt, key) for prompt in KEY_PROMPTS]
                for prompt, reply in prompts:
                    if prompt in visible and prompt not in sent:
                        if reply == key:
                            if key_sent:
                                raise TerminalError("unexpected second hidden wallet prompt")
                            if child is None:
                                import termios

                                if termios.tcgetattr(descriptor)[3] & termios.ECHO:
                                    raise TerminalError(
                                        "wallet prompt did not disable terminal echo"
                                    )
                            key_sent = True
                        if child is not None:
                            child.write(reply + "\r\n")
                        else:
                            os.write(descriptor, (reply + "\n").encode())
                        sent.add(prompt)
            if status is None:
                if child is not None:
                    if not child.isalive():
                        status = child.exitstatus
                else:
                    waited, raw = os.waitpid(pid, os.WNOHANG)
                    if waited:
                        status = os.waitstatus_to_exitcode(raw)
            if status is not None and (not readable or not chunk):
                break
        if status is None or status == 0 or not key_sent or "is not an API wallet of" not in text:
            raise TerminalError("protected setup did not refuse the throwaway wallet at userRole")
        if key in text:
            raise TerminalError("terminal echoed the disposable wallet input")
        return text.replace(account, "[ACCOUNT]"), status
    finally:
        log.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        log.write_text(text.replace(key, "[REDACTED]").replace(account, "[ACCOUNT]"))
        if child is not None:
            child.close(force=True)
        else:
            if status is None:
                import signal

                os.killpg(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            os.close(descriptor)
