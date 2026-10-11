"""One bounded subprocess runner; retain sanitised output on success and failure."""

import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class RunResult:
    returncode: int
    output: str = field(repr=False)
    log: Path


class RunError(RuntimeError):
    """Command failed; its sanitised diagnostic output is in the retained log."""


def run(
    argv: Sequence[str],
    *,
    log: Path,
    timeout: float,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    secrets: Sequence[str] = (),
    sensitive_output: bool = False,
    sensitive_stdout: bool = False,
    stdin: bytes | None = None,
) -> RunResult:
    """Execute without a shell. Secrets must enter through stdin/env, never argv.

    The caller supplies every sensitive output value in `secrets`. No arguments or
    environment are logged. Use a distinct log path for each lifecycle step.
    """
    if timeout <= 0 or not argv:
        raise ValueError("a command and a positive timeout are required")
    if any(secret and secret in arg for secret in secrets for arg in argv):
        raise ValueError("secret in command arguments")
    log.parent.mkdir(parents=True, exist_ok=True)
    try:
        completed = subprocess.run(
            list(argv),
            cwd=cwd,
            env=env,
            timeout=timeout,
            capture_output=True,
            check=False,
            input=stdin,
        )
        output = completed.stdout
        diagnostic_output = (
            b"[sensitive stdout withheld]\n" + completed.stderr
            if sensitive_stdout
            else completed.stdout + completed.stderr
        )
        returncode = completed.returncode
    except subprocess.TimeoutExpired as error:
        output = (error.stdout or b"") + (error.stderr or b"") + b"\ncommand timed out\n"
        diagnostic_output = (
            b"[sensitive stdout withheld]\n" + (error.stderr or b"") + b"\ncommand timed out\n"
            if sensitive_stdout
            else output
        )
        returncode = 124
    text = output.decode("utf-8", errors="replace")
    diagnostic_text = diagnostic_output.decode("utf-8", errors="replace")
    for secret in sorted(set(secrets), key=len, reverse=True):
        if secret:
            text = text.replace(secret, "[REDACTED]")
            diagnostic_text = diagnostic_text.replace(secret, "[REDACTED]")
    if sensitive_stdout:
        diagnostic_text = diagnostic_text[-65536:]
    # pair --json creates a key unknown before invocation. Retaining that output
    # would leak it into CI artifacts; keep only a marker for sensitive commands.
    logged = "[sensitive command output withheld]\n" if sensitive_output else diagnostic_text
    log.write_text(logged, encoding="utf-8")
    if returncode:
        raise RunError(f"command failed with exit {returncode}; diagnostics: {log}")
    return RunResult(returncode, text, log)
