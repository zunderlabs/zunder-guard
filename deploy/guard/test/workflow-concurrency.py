#!/usr/bin/env python3
"""Validate GitHub's queue extension while actionlint predates that valid key."""

import sys
from pathlib import Path

import yaml


def validate(paths):
    shared = []
    required = set()
    for path in paths:
        document = yaml.safe_load(Path(path).read_text())
        jobs = document.get("jobs", {})
        for name, job in jobs.items():
            # Leaf jobs taking C6 custody must hold the same durable queue. Reusable
            # callers merely forward secrets and do not execute with custody.
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
            if any("secrets." + secret in custody for secret in
                   ("E2E_TESTNET_API_WALLET_KEY", "E2E_TESTNET_OWNER_KEY")):
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
            if concurrency.get("group") == "guard-e2e-testnet":
                if concurrency.get("queue") != "max" or concurrency.get("cancel-in-progress") is not False:
                    raise ValueError(f"{path}:{name}: shared account requires durable serial queue")
                shared.append((Path(path).name, name))
            if concurrency.get("group") == "guard-release-channel-mutation":
                if concurrency.get("queue") != "max" or concurrency.get("cancel-in-progress") is not False:
                    raise ValueError(f"{path}:{name}: channel mutation requires durable serial queue")
    if set(shared) != required:
        raise ValueError("complete shared-account lifecycle and trading locks required")


if __name__ == "__main__":
    validate(sys.argv[1:])
    print("workflow queues validated; shared testnet account remains serial")
