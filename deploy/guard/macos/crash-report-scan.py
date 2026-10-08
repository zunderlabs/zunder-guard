#!/usr/bin/env python3
"""Synthetic native CI report checks. Never prints report contents or filenames.

The CLI is restricted to disposable hosted macOS Actions runners. Unit tests call
pure file-scanning functions against temporary fixture files, never OS reports.
"""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

SCALAR = "0123456789012345678901234567890123456789012345678901234567890123"
MARKERS = ("SYNTHETIC-CRASH-MARKER-NOT-A-WALLET-KEY",
           "synthetic-keychain-fixture-not-a-wallet-key", "public-synthetic-ci-marker")
MAX_REPORT = 16 * 1024 * 1024
HEADER_BYTES = 64 * 1024
REPORT_ROOTS = (
    Path("/Library/Logs/DiagnosticReports"),
    Path("/private/var/root/Library/Logs/DiagnosticReports"),
    Path("/private/var/empty/Library/Logs/DiagnosticReports"),
    Path("/Users/runner/Library/Logs/DiagnosticReports"),
    Path("/Users/runneradmin/Library/Logs/DiagnosticReports"),
)
FIXTURE_ROOT = Path("/Library/Application Support/Zunder Guard Native CI")


def reports(roots):
    """Only ordinary .ips/.crash files; never follow directory/file symlinks."""
    for root in roots:
        if not root.exists():
            continue
        if root.is_symlink() or not root.is_dir():
            raise ValueError("unsafe diagnostic report root")
        for directory, subdirs, names in os.walk(root, followlinks=False):
            subdirs[:] = [name for name in subdirs
                          if not (Path(directory) / name).is_symlink()]
            for name in names:
                path = Path(directory) / name
                if path.suffix not in (".ips", ".crash"):
                    continue
                metadata = path.lstat()
                if stat.S_ISREG(metadata.st_mode):
                    yield path, metadata


def snapshot(roots):
    return {str(path): [metadata.st_dev, metadata.st_ino]
            for path, metadata in reports(roots)}


def fixture_process(header, executables):
    """Read only the report's process-path field, not a stack-frame mention."""
    text = header.decode("utf-8", errors="replace")
    for match in re.finditer(r'"procPath"\s*:\s*("(?:\\.|[^"\\])*")', text):
        try:
            if json.loads(match.group(1)) in executables:
                return True
        except json.JSONDecodeError:
            return False
    match = re.search(r"^Path:\s*(.+?)\s*$", text, re.MULTILINE)
    return bool(match and match.group(1) in executables)


def contains_marker(data):
    needles = [bytes.fromhex(SCALAR)]
    for text in (SCALAR, SCALAR.upper(), "0x" + SCALAR, *MARKERS):
        needles.extend((text.encode(), text.encode("utf-16-le"), text.encode("utf-16-be")))
    # Some diagnostics render an ASCII buffer itself as a hex dump.
    needles += [needle.hex().encode() for needle in list(needles)]
    if any(needle in data for needle in needles):
        return True
    # Apple diagnostic hex dumps can separate byte pairs by whitespace.
    compact = re.sub(rb"[\t\r\n ]+", b"", data).lower()
    return any(needle.lower() in compact for needle in needles)


def inspect(roots, baseline, executables):
    result = {"new_reports": 0, "fixture_reports": 0, "matching_reports": 0,
              "unreadable_reports": 0, "unscoped_reports": 0}
    for path, metadata in reports(roots):
        if baseline.get(str(path)) == [metadata.st_dev, metadata.st_ino]:
            continue
        result["new_reports"] += 1
        try:
            # O_NOFOLLOW closes the discovery/open symlink race. A report still
            # being written is rescanned throughout the bounded observation window.
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as report:
                opened = os.fstat(report.fileno())
                if not stat.S_ISREG(opened.st_mode):
                    raise ValueError("report is not ordinary")
                header = report.read(HEADER_BYTES)
                if not fixture_process(header, executables):
                    result["unscoped_reports"] += 1
                    continue
                result["fixture_reports"] += 1
                if opened.st_size > MAX_REPORT:
                    raise ValueError("report exceeds scan bound")
                report.seek(0)
                data = report.read(MAX_REPORT + 1)
                if len(data) > MAX_REPORT:
                    raise ValueError("report exceeds scan bound")
                if contains_marker(data):
                    result["matching_reports"] += 1
        except (OSError, ValueError):
            result["unreadable_reports"] += 1
    return result


def assessment(counts):
    if counts["matching_reports"]:
        return "synthetic-credential-found"
    if counts["unreadable_reports"]:
        return "incomplete-scan"
    if not counts["fixture_reports"]:
        return "no-fixture-reports-observed"
    return "observed-fixture-reports-clear"


def native_guard(base):
    if not (sys.platform == "darwin" and os.geteuid() == 0
            and os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_OS") == "macOS"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"):
        raise ValueError("disposable hosted macOS CI only")
    if (base.parent != FIXTURE_ROOT
            or not re.fullmatch(r"ci-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", base.name)
            or base.resolve(strict=True) != base or base.stat().st_uid != 0):
        raise ValueError("unique protected fixture directory required")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("baseline", "scan"))
    parser.add_argument("--fixture-base", type=Path, required=True)
    parser.add_argument("--result", type=Path)
    parser.add_argument("--wait-seconds", type=int, default=20)
    args = parser.parse_args()
    native_guard(args.fixture_base)
    baseline_path = args.fixture_base / "crash-baseline.json"
    if args.operation == "baseline":
        # Exclusive creation; never replace an earlier run's baseline.
        with baseline_path.open("x") as output:
            os.chmod(baseline_path, 0o600)
            json.dump(snapshot(REPORT_ROOTS), output)
        return 0
    if args.result is None or not 0 <= args.wait_seconds <= 30:
        raise ValueError("result path and bounded observation window required")
    baseline = json.loads(baseline_path.read_text())
    executables = {str(args.fixture_base / version / "broker") for version in ("a", "b", "deny")}
    deadline = time.monotonic() + args.wait_seconds
    high_water = {key: 0 for key in inspect(REPORT_ROOTS, baseline, executables)}
    while True:
        counts = inspect(REPORT_ROOTS, baseline, executables)
        for key, value in counts.items():
            high_water[key] = max(high_water[key], value)
        if high_water["matching_reports"] or time.monotonic() >= deadline:
            break
        time.sleep(min(1, max(0, deadline - time.monotonic())))
    status = assessment(high_water)
    result = {**high_water, "status": status,
              "observation_seconds": args.wait_seconds,
              "credential_safety_proven": False,
              "scope": "new ips/crash reports with an exact fixture process path",
              "limit": "No-report observation is not proof; late, unavailable, unscoped or uninspected report formats remain outside this bounded check."}
    # Only aggregate counts/status/limitations; no report text, path or match bytes.
    args.result.write_text(json.dumps(result, indent=2) + "\n")
    print("Crash-report scan: " + status)
    return 1 if status in ("synthetic-credential-found", "incomplete-scan") else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError):
        print("Crash-report scan refused or incomplete; report contents suppressed.", file=sys.stderr)
        raise SystemExit(2)
