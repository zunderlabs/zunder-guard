"""One bounded subprocess runner; retain sanitised output on success and failure."""

import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class RunResult:
    returncode: int
    output: str = field(repr=False)
    log: Path


class RunError(RuntimeError):
    """Command failed; its sanitised diagnostic output is in the retained log."""


FAILURE_CATEGORIES = frozenset(
    {
        "rules",
        "account",
        "venue-role",
        "key-frame",
        "policy",
        "filesystem",
        "process-custody",
        "native-prerequisite",
        "native-listener",
        "native-key-frame",
        "native-key-refused",
        "native-credential-encryption",
        "native-readiness",
        "container-image-signature",
        "container-image-pull",
        "container-guard-setup",
        "container-supervisor",
        "container-readiness",
        "container-readiness-health-transport",
        "container-readiness-health-http",
        "container-readiness-status-transport",
        "container-readiness-status-http",
        "container-readiness-status-json",
        "container-readiness-account-mode",
        "container-readiness-risk",
        "container-readiness-fee",
        "container-readiness-licence",
        "container-readiness-builder-approval",
        "unknown",
    }
)


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
    failure_classifier: Callable[[str], str] | None = None,
) -> RunResult:
    """Execute without a shell. Secrets must enter through stdin/env, never argv.

    The caller supplies every sensitive output value in `secrets`. No arguments or
    environment are logged. Use a distinct log path for each lifecycle step.
    """
    if timeout <= 0 or not argv:
        raise ValueError("a command and a positive timeout are required")
    if failure_classifier is not None and not sensitive_output:
        raise ValueError("failure classification requires complete output withholding")
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
        failure_output = completed.stderr
        diagnostic_output = (
            b"[sensitive stdout withheld]\n" + completed.stderr
            if sensitive_stdout
            else completed.stdout + completed.stderr
        )
        returncode = completed.returncode
    except subprocess.TimeoutExpired as error:
        failure_output = error.stderr or b""
        output = (error.stdout or b"") + (error.stderr or b"") + b"\ncommand timed out\n"
        diagnostic_output = (
            b"[sensitive stdout withheld]\n" + (error.stderr or b"") + b"\ncommand timed out\n"
            if sensitive_stdout
            else output
        )
        returncode = 124
    text = output.decode("utf-8", errors="replace")
    diagnostic_text = diagnostic_output.decode("utf-8", errors="replace")
    failure_text = failure_output.decode("utf-8", errors="replace")
    for secret in sorted(set(secrets), key=len, reverse=True):
        if secret:
            text = text.replace(secret, "[REDACTED]")
            diagnostic_text = diagnostic_text.replace(secret, "[REDACTED]")
            failure_text = failure_text.replace(secret, "[REDACTED]")
    if sensitive_stdout:
        diagnostic_text = diagnostic_text[-65536:]
    # pair --json creates a key unknown before invocation. Retaining that output
    # would leak it into CI artifacts; keep only a marker for sensitive commands.
    logged = "[sensitive command output withheld]\n" if sensitive_output else diagnostic_text
    category = None
    if returncode and failure_classifier is not None:
        category = "unknown"
        try:
            # Guard reports failures on stderr; pairing/setup stdout may
            # contain private material or end without a newline.
            selected = failure_classifier(failure_text) if returncode != 124 else "unknown"
            if type(selected) is str and selected in FAILURE_CATEGORIES:
                category = selected
        except Exception:
            pass  # Classifier exception messages can contain private diagnostic input.
        logged += f"failure category: {category}\n"
    log.write_text(logged, encoding="utf-8")
    if returncode:
        if category is not None:
            raise RunError(f"command failed with exit {returncode}; failure category: {category}")
        raise RunError(f"command failed with exit {returncode}; diagnostics: {log}")
    return RunResult(returncode, text, log)
