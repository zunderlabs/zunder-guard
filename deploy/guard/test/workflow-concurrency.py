#!/usr/bin/env python3
"""Validate GitHub's queue extension while actionlint predates that valid key."""

import importlib.util
import sys
from pathlib import Path

import yaml


spec = importlib.util.spec_from_file_location(
    "guard_c6_queue_contract",
    Path(__file__).resolve().parents[1] / "harness/src/guard_harness/c6_owner.py",
)
assert spec and spec.loader
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)


def validate(paths):
    shared = []
    account = set()
    required = set()
    sources = {}
    for path in paths:
        name = Path(path).name
        if name in sources:
            raise ValueError("duplicate workflow source")
        sources[name] = Path(path).read_text()
        document = contract.document(sources[name])
        jobs = document.get("jobs", {})
        for name, job in jobs.items():
            # Identify exact custody leaves. The canonical graph binds them to
            # its whole-run owner; isolated fixtures require an explicit leaf lock.
            if "uses" in job:
                continue
            environments = [document.get("env", {}), job.get("env", {})]
            environments.extend(step.get("env", {}) for step in job.get("steps", []))
            for environment in environments:
                seconds = environment.get("JOB_TIMEOUT_SECONDS")
                if seconds is not None:
                    minutes = job.get("timeout-minutes")
                    if not isinstance(minutes, int) or str(seconds) != str(minutes * 60):
                        raise ValueError(f"{path}:{name}: deadline must match hosted timeout")
            custody = yaml.safe_dump({"workflow_env": document.get("env", {}), "job": job})
            # toJSON(secrets) or secrets[...] would hide a custody leaf from the name check.
            try:
                names = contract.secret_names(custody)
            except contract.OwnerError:
                raise ValueError(f"{path}:{name}: secrets must be named as secrets.<NAME>") from None
            if names & {"E2E_TESTNET_API_WALLET_KEY", "E2E_TESTNET_OWNER_KEY"}:
                required.add((Path(path).name, name))
        sections = [("workflow", document)] + list(jobs.items())
        for name, section in sections:
            concurrency = section.get("concurrency")
            if not isinstance(concurrency, dict):
                continue
            if "queue" in concurrency:
                if concurrency["queue"] not in ("single", "max"):
                    raise ValueError(f"{path}:{name}: unsupported concurrency queue")
                if concurrency["queue"] == "max" and concurrency.get("cancel-in-progress", False) is not False:
                    raise ValueError(f"{path}:{name}: queue max must never cancel active work")
            if "guard-e2e-testnet" in str(concurrency.get("group")):
                # Literal or standalone-only expression: every holder of the account group.
                account.add((Path(path).name, name))
            if concurrency.get("group") == "guard-e2e-testnet":
                if concurrency.get("queue") != "max" or concurrency.get("cancel-in-progress") is not False:
                    raise ValueError(f"{path}:{name}: shared account requires durable serial queue")
                shared.append((Path(path).name, name))
            if concurrency.get("group") == "guard-release-channel-mutation":
                if concurrency.get("queue") != "max" or concurrency.get("cancel-in-progress") is not False:
                    raise ValueError(f"{path}:{name}: channel mutation requires durable serial queue")
    canonical = {"verify.yml", "nightly.yml", "install-matrix.yml", "journey.yml"}
    if canonical.intersection(sources):
        if not canonical.issubset(sources):
            raise ValueError("complete run-wide C6 workflow graph required")
        for caller in ("verify.yml", "nightly.yml"):
            contract.validate(caller, sources[caller], sources["install-matrix.yml"], sources["journey.yml"])
        # contract.validate seals the standalone diagnostic condition and whole-run lock.
        covered = {("install-matrix.yml", job) for job in contract.READERS}
        covered.add(("install-matrix.yml", "operator-recovery"))
        covered.add(("install-matrix.yml", "testnet-foreground"))
        covered.add(("install-matrix.yml", "testnet-systemd"))
        covered.update(("journey.yml", job) for job in ("testnet-foreground", "testnet-systemd"))
        if required != covered or set(shared) != {("verify.yml", "workflow"), ("nightly.yml", "workflow")}:
            raise ValueError("complete run-wide C6 custody ownership required")
        # W23: install-matrix's standalone account lock sits on exactly its custody jobs.
        installs = {job for workflow, job in required if workflow == "install-matrix.yml"}
        if account != set(shared) | {("install-matrix.yml", job) for job in installs}:
            raise ValueError("account lock must cover exactly the install-matrix custody jobs")
    elif set(shared) != required:
        raise ValueError("complete shared-account lifecycle and trading locks required")


if __name__ == "__main__":
    validate(sys.argv[1:])
    print("workflow queues validated; shared testnet account remains serial")
