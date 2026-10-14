"""Retain only fixed guest refusal failure reasons, never arbitrary subprocess output."""

import json
from pathlib import Path

REASONS = frozenset(
    {
        "private key prompt did not disable terminal echo",
        "unapproved setup unexpectedly passed",
        "protected setup refusal deadline exceeded",
        "not all consent and hidden-key prompts were reached",
        "venue unapproved-wallet refusal was not observed",
        "protected route already exists",
        "refused protected service is not positively absent and inactive",
        "installer digest differs",
        "installer must be a regular file",
        "refusal wrote Guard volume config",
    }
)
PREFIX = "guard_harness.linux_lifecycle.LifecycleError: "


def guest_failure(output: Path, target: Path) -> None:
    reason = "unclassified guest failure"
    logs = list(output.glob("host-*.log"))
    if len(logs) <= 64:
        observed: set[str] = set()
        for path in logs:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
                continue
            for line in path.read_text(errors="replace").splitlines():
                if line.startswith(PREFIX) and line[len(PREFIX) :] in REASONS:
                    observed.add(line[len(PREFIX) :])
        if len(observed) == 1:
            reason = observed.pop()
    target.write_text(
        json.dumps(
            dict(schema=1, diagnostic=True, gate_eligible=False, result="failed", reason=reason)
        )
        + "\n"
    )
