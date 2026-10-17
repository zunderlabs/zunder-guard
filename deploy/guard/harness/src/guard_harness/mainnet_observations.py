"""Gather M1/M2 platform observations, each producer at its latest attempt of this run.

`gh run rerun --failed` reruns only failed jobs; jobs that passed keep their earlier
attempt's artifacts. Each producer therefore uploads `<prefix>-<run>-<attempt>`, and
the admission job downloads every artifact of its run, one directory per artifact (a
download matching a single artifact is extracted flat by the pinned download-artifact
v8.0.1 and loses its name). Every producer named here must contribute its highest
attempt at or before the admission's own (`run_attempts.latest`); an older attempt is
never merged beside a newer one, and no observation may be supplied twice.
"""

import argparse
import shutil
from pathlib import Path

from guard_harness.run_attempts import AttemptError, latest

M1_PRODUCERS = (
    "install-matrix-M1-linux-native",
    "install-matrix-M1-linux-container",
    "install-matrix-M1-macos",
    "install-matrix-M1-windows",
    # aws-stack's I7 artifact carries the aws-template route under mainnet/M1/.
    "I7",
)
M2_PRODUCERS = ("mainnet-setup-linux", "mainnet-setup-windows")
SUFFIXES = (".json", ".log")


def _sources(root: Path, pattern: str) -> list[Path]:
    found = sorted(root.glob(pattern))
    if any(path.is_symlink() for path in found):
        raise AttemptError("observation artifact contains a link")
    return [path for path in found if path.is_file() and path.suffix in SUFFIXES]


def gather(
    row: str,
    artifacts: Path,
    *,
    run_id: str,
    attempt: str,
    output: Path,
    macos: Path | None = None,
) -> dict[str, str]:
    """Copy the row's observations into fresh `output`; return each producer's attempt."""
    if output.exists() or output.is_symlink():
        raise AttemptError("observation output must be fresh")
    selected: dict[str, str] = {}
    sources: list[Path] = []
    if row == "M1":
        for prefix in M1_PRODUCERS:
            chosen = latest(artifacts, prefix, run_id, attempt)
            selected[prefix] = chosen.attempt
            pattern = "**/mainnet/M1/*" if prefix == "I7" else "**/*"
            sources += _sources(chosen.path, pattern)
    elif row == "M2":
        if macos is None or macos.is_symlink() or not macos.is_dir():
            raise AttemptError("M2 needs the macOS upgrade observations")
        for prefix in M2_PRODUCERS:
            chosen = latest(artifacts, prefix, run_id, attempt)
            selected[prefix] = chosen.attempt
            sources += _sources(chosen.path, "**/*")
        sources += _sources(macos, "**/mainnet/M2/*")
    else:
        raise AttemptError("mainnet observations are gathered for M1 or M2 only")
    output.mkdir(parents=True)
    for source in sources:
        destination = output / source.name
        if destination.exists():
            raise AttemptError("ambiguous platform observations")
        shutil.copyfile(source, destination)
    return selected


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--row", choices=("M1", "M2"), required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--attempt", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--macos", type=Path)
    args = parser.parse_args()
    selected = gather(
        args.row,
        args.artifacts,
        run_id=args.run_id,
        attempt=args.attempt,
        output=args.output,
        macos=args.macos,
    )
    for prefix, chosen in selected.items():
        print(f"{args.row} {prefix}: attempt {chosen} of run {args.run_id}")


if __name__ == "__main__":
    main()
