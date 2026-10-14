"""Finite Windows lifecycle failure observations; never receipts or raw output."""

import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from guard_harness.runner import RunError

STEPS = frozenset(
    {
        "per-user-lifecycle",
        "per-user-readiness",
        "per-user-shutdown",
        "per-user-journal-audit",
        "crash-policy-prepare",
        "scm-install",
    }
)
REFUSALS = {
    "stored-key per-user runtime exited": "per-user-runtime-exited",
    "per-user testnet identity mismatch": "per-user-identity-mismatch",
    "per-user testnet readiness deadline": "per-user-readiness-deadline",
    "candidate crash-policy refusal probe did not complete": "crash-policy-probe-incomplete",
    "candidate did not emit the exact crash-policy refusal": "crash-policy-refusal-mismatch",
    "cannot read hosted Windows crash policy": "crash-policy-unreadable",
    "cannot remove hosted Windows crash policy": "crash-policy-removal-failed",
    "hosted crash-policy removal did not confirm four absent keys": "crash-policy-still-present",
}


def reason(error: Exception) -> str:
    if isinstance(error, ModuleNotFoundError) and error.name == "pwd":
        return "posix-pwd-unavailable"
    if isinstance(error, subprocess.TimeoutExpired):
        return "command-timeout"
    if isinstance(error, RunError):
        return "command-failed"
    # Return only a literal from this table; exception details never enter artifacts.
    return REFUSALS.get(str(error), "unknown")


@contextmanager
def observe(work: Path, step: str) -> Iterator[None]:
    step = step if step in STEPS else "unknown"
    try:
        yield
    except Exception as error:
        work.mkdir(parents=True, exist_ok=True)
        (work / f"windows-{step}-failure.log").write_text(
            f"Windows lifecycle failure step: {step}\nfailure reason: {reason(error)}\n"
        )
        raise
