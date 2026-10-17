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
        "wallet-restore",
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
        "operator-recovery",
        "testnet-foreground",
        "testnet-systemd",
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
        "payment-diagnostic",
    },
}
SHA = re.compile(r"[0-9a-f]{40}\Z")
REF = re.compile(
    r"refs/(?:heads/(?:main|preview/[a-z0-9-]+)|tags/v\d+\.\d+\.\d+(?:-rc\.[1-9]\d*)?)\Z"
)
READERS = ("linux-amd64", "linux-arm64", "linux-container", "native", "docker")
# Every install-matrix job that reads the E2E account's API wallet key, and no other.
CUSTODY = (*READERS, "operator-recovery", "testnet-foreground", "testnet-systemd")
RECOVERY_IF = (
    "${{ inputs.target == 'operator-recovery' && inputs.diagnostic == true "
    "&& inputs.profile == 'all' && inputs.scenario == 'fresh' "
    "&& contains(github.workflow_ref, '/.github/workflows/install-matrix.yml@') "
    "&& github.event_name == 'workflow_dispatch' }}"
)
FOREGROUND_IF = RECOVERY_IF.replace("'operator-recovery'", "'testnet-foreground'")
SYSTEMD_IF = RECOVERY_IF.replace("'operator-recovery'", "'testnet-systemd'")
# W18: verify's one transfer job (staging merchant -> payers). It holds no account custody,
# starts only after every trading and install row of the run finished, and holds only its
# network's purchase lock beneath verify's whole-run account lock.
CLEANUP_IF = (
    "${{ !cancelled() && needs.staging.result == 'success' "
    "&& (needs.journeys.result == 'success' || needs.journeys.result == 'failure') "
    "&& (needs.install-matrix.result == 'success' || needs.install-matrix.result == 'failure' "
    "|| needs.install-matrix.result == 'skipped') }}"
)
CLEANUP = {
    "name": "Restore staging USDC (${{ matrix.network }})",
    "needs": ["staging", "journeys", "install-matrix"],
    "if": CLEANUP_IF,
    "runs-on": "ubuntu-24.04",
    "timeout-minutes": 30,
    "environment": "e2e",
    "permissions": {"contents": "read", "actions": "read"},
    "concurrency": {
        "group": "guard-e2e-purchase-${{ matrix.network }}",
        "cancel-in-progress": False,
        "queue": "max",
    },
    "strategy": {"fail-fast": False, "matrix": {"network": ["hyperliquid", "arbitrum", "base"]}},
}
CLEANUP_SECRETS = {"E2E_ACCESS_CLIENT_ID", "E2E_ACCESS_CLIENT_SECRET", "E2E_MERCHANT_TESTNET_KEY"}


class OwnerError(ValueError):
    """No caller ownership is inferred on unknown or ambiguous workflow state."""


def install_lock(job: str) -> dict[str, Any]:
    """The exact job-level account lock of one install-matrix custody job.

    install-matrix holds no workflow-level lock. Each job that takes the E2E account's
    custody holds the account group at job level, and only when install-matrix is the run's
    own workflow (a standalone diagnostic). Called from verify or nightly, which own the
    account for their whole run, the same key names a group unique to the run, job and
    matrix leg: the called jobs never queue behind their own caller (no nested global lock)
    and never serialise each other. Paper-only, refusal and admission jobs take no lock.
    """
    if job not in CUSTODY:
        raise OwnerError("C6 lock requested for a job without account custody")
    return {
        "group": "${{ contains(github.workflow_ref, '/.github/workflows/install-matrix.yml@') "
        f"&& 'guard-e2e-testnet' || format('guard-c6-install-inner-{{0}}-{job}-{{1}}', "
        "github.run_id, strategy.job-index) }}",
        "cancel-in-progress": False,
        "queue": "max",
    }


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
        _cleanup(_job(jobs, "wallet-restore"))
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


EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.S)
SECRET_WORD = re.compile(r"\bsecrets\b")
SECRET_NAME = re.compile(r"\bsecrets\.([A-Za-z_][A-Za-z0-9_]*)\b")


def secret_names(text: str) -> set[str]:
    """Every secret a workflow text's expressions name; any other use of `secrets` refuses.

    Inside `${{ }}`, `toJSON(secrets)`, `secrets[...]` or `secrets.*` would hand over secrets
    that a name allow-list cannot see, so only the plain `secrets.<NAME>` form is admitted.
    (Outside expressions the word is shell or Python text, such as Python's `secrets`.)
    """
    names: set[str] = set()
    for expression in EXPRESSION.findall(text):
        found = SECRET_NAME.findall(expression)
        if len(SECRET_WORD.findall(expression)) != len(found):
            raise OwnerError("C6 secrets must be named one by one as secrets.<NAME>")
        names.update(found)
    return names


def _cleanup(job: dict[str, Any]) -> None:
    """Admit verify's wallet restore: no account custody, no overlap with any C6 row.

    `needs` holds it until journeys (P8, T1, T2 and the purchases) and install-matrix have
    finished; the condition refuses a cancelled or still-unfinished dependency. Its only lock
    is the network's purchase group, never the account group verify already holds, so it
    cannot nest or deadlock, and no other run can use the account while it transfers.
    """
    if set(job) != {*CLEANUP, "steps"}:
        raise OwnerError("C6 cleanup job structure differs")
    for key, expected in CLEANUP.items():
        if job[key] != expected:
            raise OwnerError("C6 cleanup must follow every trading and install row")
    _lock(job["concurrency"], cast(dict[str, Any], CLEANUP["concurrency"]))
    steps = job["steps"]
    if not isinstance(steps, list) or any(not isinstance(step, dict) for step in steps):
        raise OwnerError("C6 cleanup job structure differs")
    text = yaml.safe_dump(steps)
    secrets = secret_names(text)
    if (
        not secrets <= CLEANUP_SECRETS
        or "E2E_TESTNET" in text
        or GROUP in text
        or "c6_owner" in text
        or any("continue-on-error" in step for step in steps)
    ):
        raise OwnerError("C6 cleanup must never hold the E2E account or its lock")


def _readers(source: str) -> None:
    matrix = document(source)
    if "concurrency" in matrix:
        raise OwnerError("C6 install-matrix holds a workflow-level lock")
    leaves = _leaves(matrix, "install-matrix.yml")
    for name, job in leaves.items():
        if name in CUSTODY:
            # Exactly its own standalone-only lock: never the literal global group (a nested
            # lock under verify/nightly), never a shared or missing one.
            if _mapping(job).get("concurrency") != install_lock(name):
                raise OwnerError("C6 custody job lock differs or holds an inner account lock")
            _lock(job["concurrency"], install_lock(name))
        elif "concurrency" in _mapping(job):
            raise OwnerError("C6 job without account custody holds a lock")
    recovery = _job(leaves, "operator-recovery")
    _singular(recovery)
    if (
        recovery.get("if") != RECOVERY_IF
        or recovery.get("needs") != "subjects"
        or recovery.get("runs-on") != "ubuntu-24.04"
        or recovery.get("environment") != "e2e"
        or recovery.get("timeout-minutes") != 120
    ):
        raise OwnerError("C6 operator recovery must be a bounded standalone diagnostic")
    foreground = _job(leaves, "testnet-foreground")
    _singular(foreground)
    if (
        foreground.get("if") != FOREGROUND_IF
        or foreground.get("needs") != "subjects"
        or foreground.get("runs-on") != "ubuntu-24.04"
        or foreground.get("environment") != "e2e"
        or foreground.get("timeout-minutes") != 120
        or foreground.get("permissions")
        != {"contents": "read", "actions": "read", "packages": "read"}
        or any("actions/attest" in str(step.get("uses", "")) for step in foreground["steps"])
    ):
        raise OwnerError(
            "C6 foreground must be a bounded standalone diagnostic without attestation"
        )
    systemd = _job(leaves, "testnet-systemd")
    _singular(systemd)
    if (
        systemd.get("if") != SYSTEMD_IF
        or systemd.get("needs") != "subjects"
        or systemd.get("runs-on") != "ubuntu-24.04"
        or systemd.get("environment") != "e2e"
        or systemd.get("timeout-minutes") != 120
        or systemd.get("permissions") != {"contents": "read", "actions": "read", "packages": "read"}
        or any("actions/attest" in str(step.get("uses", "")) for step in systemd["steps"])
    ):
        raise OwnerError("C6 systemd must be a bounded standalone diagnostic without attestation")
    for name in READERS:
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


def admit(context: dict[str, str], *, callee: str, profile: str, role: str = "reader") -> None:
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
    if role not in {"reader", "testnet-foreground", "testnet-systemd"} or (
        role in {"testnet-foreground", "testnet-systemd"}
        and (
            caller != "install-matrix.yml"
            or context.get("INSTALL_MATRIX_TARGET") != role
            or context.get("INSTALL_MATRIX_SCENARIO") != "fresh"
        )
    ):
        raise OwnerError("C6 testnet target requires standalone fresh diagnostic ownership")

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
    parser.add_argument(
        "--role", choices=("reader", "testnet-foreground", "testnet-systemd"), default="reader"
    )
    args = parser.parse_args()
    try:
        admit(dict(os.environ), callee=args.callee, profile=args.profile, role=args.role)
    except OwnerError as error:
        raise SystemExit(str(error)) from None
    print("C6 exact whole-run owner admitted; runtime safety checks remain required")


if __name__ == "__main__":
    main()
