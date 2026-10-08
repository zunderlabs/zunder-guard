#!/usr/bin/env python3
"""Refuse missing, ambiguous or unreviewed libtest selections before a flow shard."""
import subprocess
import sys

FLOW_TESTS = (
    "the_generator_reaches_every_path",
    "the_implementation_is_the_reference",
    "the_implementation_is_the_reference_when_told_in_time",
    "the_order_of_the_reports_does_not_matter",
)


def validate_listing(name, stdout):
    if name not in FLOW_TESTS or len(stdout.encode()) > 4096:
        raise ValueError("Unreviewed flow selection or oversized test listing")
    entries = [line for line in stdout.splitlines() if line.strip()]
    if entries != [name + ": test", "1 test, 0 benchmarks"]:
        raise ValueError("The exact filter must select one non-benchmark flow test")


def check(name):
    if name not in FLOW_TESTS:
        raise ValueError("Unreviewed flow selection")
    result = subprocess.run(
        ["cargo", "test", "--locked", "-p", "zunder-venue", "--test", "flows_model",
         name, "--", "--exact", "--list"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, text=True,
        check=True, timeout=900,
    )
    validate_listing(name, result.stdout)
    print("Verified exact flow selection: " + name)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Expected one reviewed flow test name")
    check(sys.argv[1])
