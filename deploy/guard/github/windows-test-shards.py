#!/usr/bin/env python3
"""Plan the native Windows test shards: disjoint, complete and fail-closed.

The shards replace one `cargo test` over six packages. Every shard selects the same six
packages, so Cargo resolves features exactly as that one command did (zunder-guard's
dev-dependency on itself turns on test-hooks in zunder-guard-core too); the shards differ
only in target selection. Integration tests are grouped by target name; the `rest` shard
takes every library and binary unit test, every doc test, every example build and every
integration test that no other shard names, so a new test file runs there by construction.
The libtest arguments are the original ones in every invocation.

`plan SHARD --out FILE` reads `cargo metadata`, refuses unreviewed target kinds, flags and
missing named tests, prints the whole partition and writes SHARD's Cargo invocations as JSON.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

PACKAGES = (
    "zunder-venue",
    "zunder-venue-types",
    "zunder-guard-core",
    "zunder-guard-mcp",
    "zunder-guard-rules",
    "zunder-guard",
)
# The four flow properties run in their own leaves (check-flow-selection.py).
FLOW_TESTS = (
    "the_generator_reaches_every_path",
    "the_implementation_is_the_reference",
    "the_implementation_is_the_reference_when_told_in_time",
    "the_order_of_the_reports_does_not_matter",
)
LIBTEST = ("--exact",) + tuple(value for name in FLOW_TESTS for value in ("--skip", name))
# Integration test names per shard, by measured native Windows run time (pilot about 14
# minutes; end_to_end, journal and stream about 8 together). Everything else is `rest`.
NAMED = {
    "pilot": ("pilot",),
    "io": ("end_to_end", "journal", "stream"),
}
REST = "rest"
SHARDS = tuple(NAMED) + (REST,)
NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_-]{0,63}")
# Target kinds and the Cargo defaults this plan relies on; anything else is unreviewed.
DEFAULTS = {
    "lib": {"test": True, "doctest": True},
    "bin": {"test": True},
    "test": {"test": True},
    "example": {"test": False},
    "custom-build": {},
}
MAX_METADATA = 64 * 1024 * 1024


class PlanError(ValueError):
    pass


def targets(metadata):
    """Return {kind: set of names} over the six packages, refusing anything unreviewed."""
    members = set(metadata.get("workspace_members", []))
    found = {}
    for package in metadata.get("packages", []):
        if package.get("name") in PACKAGES and package.get("id") in members:
            if package["name"] in found:
                raise PlanError(f"package {package['name']} appears twice in the workspace")
            found[package["name"]] = package
    missing = [name for name in PACKAGES if name not in found]
    if missing:
        raise PlanError("packages missing from the workspace: " + ", ".join(missing))
    kinds = {kind: set() for kind in DEFAULTS}
    for name in PACKAGES:
        package = found[name]
        libs = 0
        for target in package.get("targets", []):
            kind = target.get("kind")
            if not isinstance(kind, list) or len(kind) != 1 or kind[0] not in DEFAULTS:
                raise PlanError(f"{name}: unreviewed target kind {kind!r}")
            kind = kind[0]
            label = f"{name}: {kind} {target.get('name')!r}"
            if not isinstance(target.get("name"), str) or not NAME.fullmatch(target["name"]):
                raise PlanError(label + ": unreviewed target name")
            if target.get("required-features"):
                raise PlanError(label + ": required-features are unreviewed")
            if kind == "lib":
                libs += 1
                if target.get("crate_types") != ["lib"]:
                    raise PlanError(label + ": unreviewed crate type")
            for flag, value in DEFAULTS[kind].items():
                if target.get(flag) is not value:
                    raise PlanError(f"{label}: {flag} = {target.get(flag)!r} is not Cargo's default")
            kinds[kind].add(target["name"])
        if libs != 1:
            raise PlanError(f"{name}: expected exactly one library target")
    return kinds


def partition(metadata):
    """Return {shard: sorted integration test names}; disjoint and complete by construction."""
    tests = targets(metadata)["test"]
    named = [name for names in NAMED.values() for name in names]
    if len(named) != len(set(named)):
        raise PlanError("an integration test is named in two shards")
    absent = sorted(set(named) - tests)
    if absent:
        raise PlanError("named integration tests not in the workspace: " + ", ".join(absent))
    shards = {shard: sorted(names) for shard, names in NAMED.items()}
    shards[REST] = sorted(tests - set(named))
    return shards


def invocations(metadata, shard):
    """Cargo argument lists (after `cargo`) for one shard."""
    if shard not in SHARDS:
        raise PlanError(f"unknown shard {shard!r}; expected one of {', '.join(SHARDS)}")
    tests = partition(metadata)[shard]
    packages = [value for name in PACKAGES for value in ("-p", name)]
    head = ["test", "--no-fail-fast", "--locked", *packages]
    selected = [value for name in tests for value in ("--test", name)]
    if shard != REST:
        return [[*head, *selected, "--", *LIBTEST]]
    return [
        [*head, "--lib", "--bins", *selected, "--", *LIBTEST],
        [*head, "--doc", "--", *LIBTEST],
        # `cargo test` without target flags builds the examples to check that they compile,
        # in the test profile; so does this, once.
        ["build", "--locked", "--profile", "test", *packages, "--examples"],
    ]


def read_metadata(path):
    if path is not None:
        text = Path(path).read_text()
    else:
        text = subprocess.run(
            ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, text=True, check=True, timeout=600,
        ).stdout
    if len(text.encode()) > MAX_METADATA:
        raise PlanError("oversized cargo metadata")
    return json.loads(text)


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    plan = sub.add_parser("plan", help="validate the partition and write one shard's invocations")
    plan.add_argument("shard", choices=SHARDS)
    plan.add_argument("--out", required=True, type=Path)
    plan.add_argument("--metadata", help="read this cargo metadata JSON instead of running cargo")
    args = parser.parse_args(argv)
    metadata = read_metadata(args.metadata)
    for shard, tests in partition(metadata).items():
        print(f"{shard}: " + (" ".join(tests) if tests else "(no integration tests)") +
              (" + every library, binary and doc test and the example builds" if shard == REST else ""))
    runs = invocations(metadata, args.shard)
    args.out.write_text(json.dumps(runs) + "\n")
    for run in runs:
        print(f"{args.shard}: cargo " + " ".join(run))


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except PlanError as error:
        raise SystemExit(f"windows-test-shards: {error}")
