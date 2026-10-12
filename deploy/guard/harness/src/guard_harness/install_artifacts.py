"""Merge independently executed install scenarios without relabelling their receipts."""

import argparse
import shutil
from pathlib import Path

from guard_harness.native_evidence import VARIANTS
from guard_harness.testnet_process import ProcessError


def copy(source: Path, destination: Path) -> None:
    if (
        source.is_symlink()
        or not source.exists()
        or destination.exists()
        or destination.is_symlink()
    ):
        raise ProcessError("missing, linked or ambiguous scenario artifact")
    if source.is_dir():
        if any(
            path.is_symlink() or not (path.is_dir() or path.is_file()) for path in source.rglob("*")
        ):
            raise ProcessError("scenario artifact contains unsafe entry")
        shutil.copytree(source, destination)
    elif source.is_file():
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    else:
        raise ProcessError("regular scenario artifact required")


def merge(row: str, parts: Path, output: Path) -> None:
    if row not in {*VARIANTS, "I1", "I2", "I5", "I6"} or output.exists() or output.is_symlink():
        raise ProcessError("fresh supported scenario merge required")
    output.mkdir(mode=0o700)
    for scenario in ("fresh", "upgrade"):
        if row in VARIANTS:
            for variant in VARIANTS[row]:
                (output / variant).mkdir(exist_ok=True)
                copy(parts / f"install-matrix-{variant}-{scenario}", output / variant / scenario)
        elif row in {"I1", "I2", "I6"}:
            source = parts / f"install-matrix-{row}-{scenario}"
            for mode in ("paper", "testnet"):
                (output / mode).mkdir(exist_ok=True)
                copy(source / mode / scenario, output / mode / scenario)
            if scenario == "fresh" and row in {"I1", "I2"}:
                copy(source / "channels", output / "channels")
        else:
            for channel in ("docker", "compose"):
                source = parts / f"install-matrix-I5-{scenario}-{channel}"
                copy(source / "receipt.json", output / scenario / channel / "receipt.json")
                for mode in ("paper", "testnet"):
                    (output / mode / scenario).mkdir(parents=True, exist_ok=True)
                    copy(source / mode / scenario / channel, output / mode / scenario / channel)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--row", choices=(*VARIANTS, "I1", "I2", "I5", "I6"), required=True)
    parser.add_argument("--parts", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    merge(args.row, args.parts, args.output)


if __name__ == "__main__":
    main()
