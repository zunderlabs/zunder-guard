#!/usr/bin/env python3
"""Validate GitHub's queue extension while actionlint predates that valid key."""

import sys
from pathlib import Path

import yaml


def validate(paths):
    shared = []
    for path in paths:
        document = yaml.safe_load(Path(path).read_text())
        sections = [("workflow", document)] + list(document.get("jobs", {}).items())
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
    required = {
        ("install-matrix.yml", name)
        for name in ("native", "linux-amd64", "linux-arm64", "linux-container", "docker")
    } | {("journey.yml", "testnet-foreground"), ("journey.yml", "testnet-systemd")}
    if set(shared) != required:
        raise ValueError("complete shared-account lifecycle and trading locks required")


if __name__ == "__main__":
    validate(sys.argv[1:])
    print("workflow queues validated; shared testnet account remains serial")
