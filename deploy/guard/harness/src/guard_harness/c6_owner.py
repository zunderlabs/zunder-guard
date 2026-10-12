"""Network-free admission of the exact caller's whole-run C6 ownership topology.

GitHub context is supplied by step expressions, never release/source input. The
checked-out workflow source can differ from nightly's authenticated binary source.
This admits scheduling ownership only; every runtime scan and custody check remains.
"""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Callable
from typing import Any, cast

import yaml

GROUP = "guard-e2e-testnet"
LOCK = {"group": GROUP, "cancel-in-progress": False, "queue": "max"}
INSTALL_LOCK = {
    "group": "${{ contains(github.workflow_ref, '/.github/workflows/install-matrix.yml@') "
    "&& 'guard-e2e-testnet' || format('guard-c6-install-inner-{0}', github.run_id) }}",
    "cancel-in-progress": False,
    "queue": "max",
}
CALLS = {
    "verify.yml": {
        "install-matrix": "./.github/workflows/install-matrix.yml",
        "journeys": "./.github/workflows/journey.yml",
        "promote": "./.github/workflows/promote.yml",
    },
    "nightly.yml": {
        "installs": "./.github/workflows/install-matrix.yml",
        "purchase": "./.github/workflows/journey.yml",
    },
}
JOBS = {
    "verify.yml": {
        "stable-template",
        "staging",
        "install-matrix",
        "journeys",
        "gate",
        "promote",
        "completion",
    },
    "nightly.yml": {"promoted", "properties", "installs", "purchase", "nightly"},
    "install-matrix.yml": {
        "subjects",
        "linux-amd64",
        "linux-container",
        "linux-arm64",
        "native",
        "docker",
        "linux-container-admission",
        "native-admission",
        "aws-stack",
        "linux-mainnet",
        "native-mainnet",
        "mainnet-setup",
        "mainnet-admission",
    },
    "journey.yml": {
        "testnet-foreground",
        "testnet-systemd",
        "purchase",
        "signing-subjects",
        "signing-contract",
        "signing-gate",
        "testnet-failure-alert",
        "checkout-diagnostic",
    },
}
SHA = re.compile(r"[0-9a-f]{40}\Z")
REF = re.compile(
    r"refs/(?:heads/(?:main|preview/[a-z0-9-]+)|tags/v\d+\.\d+\.\d+(?:-rc\.[1-9]\d*)?)\Z"
)
READERS = ("linux-amd64", "linux-arm64", "linux-container", "native", "docker")


class OwnerError(ValueError):
    """No caller ownership is inferred on unknown or ambiguous workflow state."""


class UniqueLoader(yaml.SafeLoader):
    """Reject duplicate keys at every depth instead of last-key-wins admission."""

    def construct_mapping(self, node: yaml.nodes.MappingNode, deep: bool = False) -> dict[Any, Any]:
        if not isinstance(node, yaml.nodes.MappingNode):
            raise OwnerError("C6 workflow mapping differs")
        result: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            construct = cast(Callable[..., Any], self.construct_object)
            key = construct(key_node, deep=deep)
            try:
                duplicate = key in result
            except TypeError:
                raise OwnerError("C6 workflow key differs") from None
            if duplicate or key == "<<":
                raise OwnerError("C6 workflow duplicate or merged key")
            result[key] = construct(value_node, deep=deep)
        return result


def document(source: str) -> dict[str, Any]:
    try:
        value = yaml.load(source, Loader=UniqueLoader)
    except (yaml.YAMLError, RecursionError):
        raise OwnerError("C6 workflow parse failed") from None
    if not isinstance(value, dict) or any(not isinstance(key, (str, bool)) for key in value):
        raise OwnerError("C6 workflow document differs")
    # YAML 1.1 treats the ordinary Actions `on` key as True. Nothing relies on
    # event-name input granting ownership; preserve the exact scheduling graph.
    return value


def _mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise OwnerError("C6 workflow structure differs")
    return value


def _lock(value: Any, expected: dict[str, Any]) -> None:
    actual = _mapping(value)
    if actual != expected or actual.get("cancel-in-progress") is not False:
        raise OwnerError("C6 whole-run lock differs")


def _job(jobs: dict[str, Any], name: str) -> dict[str, Any]:
    return _mapping(jobs.get(name))


def _leaves(doc: dict[str, Any], workflow: str) -> dict[str, Any]:
    jobs = _mapping(doc.get("jobs"))
    if set(jobs) != JOBS[workflow] or any("uses" in _mapping(job) for job in jobs.values()):
        raise OwnerError("C6 callee job set or reusable call differs")
    return jobs


def _singular(job: dict[str, Any]) -> None:
    if "strategy" in job or job.get("continue-on-error", False) is not False:
        raise OwnerError("C6 trader or reusable call must be singular and fail closed")


def validate(caller: str, source: str, install: str, journey: str) -> None:
    """Validate immutable caller and same-commit relative callees as one graph."""
    if caller not in CALLS:
        raise OwnerError("C6 caller differs")
    owner = document(source)
    _lock(owner.get("concurrency"), LOCK)
    jobs = _mapping(owner.get("jobs"))
    if set(jobs) != JOBS[caller]:
        raise OwnerError("C6 caller job set differs")
    calls = {
        name: _mapping(job).get("uses") for name, job in jobs.items() if "uses" in _mapping(job)
    }
    if calls != CALLS[caller]:
        raise OwnerError("C6 same-commit reusable calls differ")
    for name in calls:
        _singular(_job(jobs, name))
    if caller == "verify.yml":
        readers = _job(jobs, "install-matrix")
        if readers.get("needs") != ["staging", "journeys"] or readers.get("if") != (
            "${{ !cancelled() && needs.staging.result == 'success' "
            "&& needs.journeys.result == 'success' }}"
        ):
            raise OwnerError("C6 readers require completed journeys")
        traders = _job(jobs, "journeys")
        if traders.get("needs") != "staging" or traders.get("if") != (
            "${{ !cancelled() && needs.staging.result == 'success' }}"
        ):
            raise OwnerError("C6 journey admission differs")
        for name in ("install-matrix", "journeys"):
            inputs = _mapping(_job(jobs, name).get("with"))
            if inputs.get("profile", "all") != "all":
                raise OwnerError("C6 verify profile differs")
    else:
        for name in ("installs", "purchase"):
            job = _job(jobs, name)
            if (
                job.get("needs") != "promoted"
                or job.get("if") != ("needs.promoted.outputs.promoted == 'true'")
                or _mapping(job.get("with")).get("profile") != "nightly"
            ):
                raise OwnerError("C6 nightly admission differs")
    _readers(install)
    trading = document(journey)
    if "concurrency" in trading:
        raise OwnerError("C6 journey holds an inner account lock")
    trades = _leaves(trading, "journey.yml")
    for name in ("testnet-foreground", "testnet-systemd"):
        job = _job(trades, name)
        _singular(job)
        if "concurrency" in job or job.get("if") != "${{ inputs.profile == 'all' }}":
            raise OwnerError("C6 trading admission differs")
    if _job(trades, "testnet-systemd").get("needs") != "testnet-foreground":
        raise OwnerError("C6 T2 must follow successful T1")


def _readers(source: str) -> None:
    matrix = document(source)
    _lock(matrix.get("concurrency"), INSTALL_LOCK)
    leaves = _leaves(matrix, "install-matrix.yml")
    for name in READERS:
        if "concurrency" in _job(leaves, name):
            raise OwnerError("C6 reader holds an inner account lock")
        strategy = _mapping(_job(leaves, name).get("strategy"))
        if strategy.get("fail-fast") is not False:
            raise OwnerError("C6 reader cancellation differs")


def _git(*args: str) -> str:
    try:
        result = subprocess.run(
            ["git", *args], check=True, capture_output=True, text=True, timeout=15
        )
    except (OSError, subprocess.SubprocessError, UnicodeError):
        raise OwnerError("C6 immutable workflow snapshot unavailable") from None
    if len(result.stdout) > 2_000_000:
        raise OwnerError("C6 workflow snapshot exceeds bound")
    return result.stdout


def admit(context: dict[str, str], *, callee: str, profile: str) -> None:
    """Trusted step context, not workflow inputs or an unauthenticated file claim."""
    workflow_ref = context.get("WORKFLOW_REF", "")
    sha = context.get("WORKFLOW_SHA", "")
    github_sha = context.get("CALLER_SHA", "")
    github_ref = context.get("CALLER_REF", "")
    prefix = "zunderlabs/zunder-guard/.github/workflows/"
    if (
        context.get("CALLER_REPOSITORY") != "zunderlabs/zunder-guard"
        or not workflow_ref.startswith(prefix)
        or not SHA.fullmatch(sha)
        or github_sha != sha
        or not REF.fullmatch(github_ref)
        or _git("rev-parse", "HEAD").strip() != sha
        or callee not in ("install-matrix.yml", "journey.yml")
    ):
        raise OwnerError("C6 trusted caller context differs")
    suffix = workflow_ref[len(prefix) :]
    if suffix.count("@") != 1:
        raise OwnerError("C6 caller reference differs")
    caller, ref = suffix.split("@")
    if ref != github_ref:
        raise OwnerError("C6 caller reference differs")

    def show(name: str) -> str:
        return _git("show", f"{sha}:.github/workflows/{name}")

    if caller == "install-matrix.yml":
        if (
            callee != caller
            or profile != "all"
            or context.get("CALLER_EVENT") != "workflow_dispatch"
            or context.get("DIAGNOSTIC") != "true"
        ):
            raise OwnerError("C6 standalone profile differs")
        _readers(show(caller))
        return
    if caller not in CALLS or profile != ("all" if caller == "verify.yml" else "nightly"):
        raise OwnerError("C6 caller profile differs")
    if callee == "journey.yml" and profile != "all":
        raise OwnerError("C6 nightly cannot admit a trading job")
    validate(caller, show(caller), show("install-matrix.yml"), show("journey.yml"))


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--callee", required=True, choices=("install-matrix.yml", "journey.yml"))
    parser.add_argument("--profile", required=True)
    args = parser.parse_args()
    try:
        admit(dict(os.environ), callee=args.callee, profile=args.profile)
    except OwnerError as error:
        raise SystemExit(str(error)) from None
    print("C6 exact whole-run owner admitted; runtime safety checks remain required")


if __name__ == "__main__":
    main()
