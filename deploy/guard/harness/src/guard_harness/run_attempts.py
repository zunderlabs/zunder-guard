"""Select one job's artifact from the latest attempt of the same workflow run.

`gh run rerun --failed` reruns only failed jobs and their dependents; the jobs that
passed keep their earlier attempt's artifacts. An artifact named
`<prefix>-<run>-<attempt>` is a measurement of that attempt. A consumer in attempt N
admits, for each producer, only its highest attempt k <= N of the same run; lower
attempts are superseded and never merged or used as a fallback. The artifact name
selects; the caller's signature check must still bind the selected attempt.
"""

import argparse
import re
from dataclasses import dataclass
from pathlib import Path

from guard_harness.attestation import AttestationError

POSITIVE = re.compile(r"[1-9][0-9]*")
PREFIX = re.compile(r"[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*")
ATTEMPT_SUFFIX = re.compile(r"([1-9][0-9]*)-([1-9][0-9]*)")


class AttemptError(AttestationError):
    """Artifact names do not select exactly one admissible attempt."""


@dataclass(frozen=True)
class Selected:
    path: Path
    attempt: str


def _positive(value: str, what: str) -> int:
    if not isinstance(value, str) or POSITIVE.fullmatch(value) is None:
        raise AttemptError(f"{what} must be a canonical positive integer")
    return int(value)


def attempts(directory: Path, prefix: str, run_id: str) -> dict[int, Path]:
    """Every attempt of `prefix` in `run_id`; refuse anything ambiguous in its namespace.

    The namespace is every entry named `<prefix>-<digit>...`. Other names (for example
    `T1-early-failure-...` beside `T1-<run>-<k>`) belong to other artifacts and are
    ignored. Inside the namespace a malformed suffix, another run id or anything but a
    real directory is refused, never skipped.
    """
    if not isinstance(prefix, str) or PREFIX.fullmatch(prefix) is None:
        raise AttemptError("artifact prefix refused")
    _positive(run_id, "workflow run id")
    if directory.is_symlink() or not directory.is_dir():
        raise AttemptError("artifact download directory missing")
    found: dict[int, Path] = {}
    lead = prefix + "-"
    for entry in sorted(directory.iterdir()):
        name = entry.name
        rest = name[len(lead) :]
        if not name.startswith(lead) or not rest or rest[0] not in "0123456789":
            continue
        match = ATTEMPT_SUFFIX.fullmatch(rest)
        if match is None:
            raise AttemptError(f"malformed {prefix} artifact name")
        if match.group(1) != run_id:
            raise AttemptError(f"{prefix} artifact belongs to another workflow run")
        if entry.is_symlink() or not entry.is_dir():
            raise AttemptError(f"{prefix} artifact must be a real directory")
        attempt = int(match.group(2))
        if attempt in found:
            raise AttemptError(f"ambiguous {prefix} artifact attempt")
        found[attempt] = entry
    return found


def latest(directory: Path, prefix: str, run_id: str, attempt: str) -> Selected:
    """The highest attempt <= `attempt` of `prefix` in `run_id`, or refuse.

    Attempts above the consumer's own attempt did not exist when it ran (or follow it
    when a later consumer replays it) and are never admitted.
    """
    ceiling = _positive(attempt, "consumer attempt")
    admissible = {
        k: path for k, path in attempts(directory, prefix, run_id).items() if k <= ceiling
    }
    if not admissible:
        raise AttemptError(f"{prefix} has no artifact of this run at or before this attempt")
    selected = max(admissible)
    return Selected(admissible[selected], str(selected))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--prefix", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--attempt", required=True)
    parser.add_argument("--move-to", type=Path, required=True)
    args = parser.parse_args()
    selected = latest(args.directory, args.prefix, args.run_id, args.attempt)
    if args.move_to.exists() or args.move_to.is_symlink():
        raise AttemptError("selected artifact target already exists")
    selected.path.rename(args.move_to)
    print(f"{args.prefix}: attempt {selected.attempt} of run {args.run_id}")


if __name__ == "__main__":
    main()
