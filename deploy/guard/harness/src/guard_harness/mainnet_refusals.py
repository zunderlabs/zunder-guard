"""Run literal no-key setup refusals on an authenticated released executable."""

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
from pathlib import Path
from typing import Any

from guard_harness.mainnet_evidence import MatrixError
from guard_harness.native_release import Release
from guard_harness.testnet_run import ROOT


def record(
    release: Release,
    *,
    case: str,
    route: str,
    target: str,
    work: Path,
    output: bytes,
    exit_code: int,
    literal: str,
    passed: bool,
    mechanism: str = "process",
    observed_mode: str | None = None,
) -> None:
    work.mkdir(mode=0o700, parents=True, exist_ok=True)
    (work / f"{case}.log").write_bytes(output)
    value = dict(
        schema=1,
        journey="M2",
        route=route,
        tag=release.tag,
        commit=release.commit,
        harness_commit=os.environ.get("GITHUB_SHA", ""),
        diagnostic=os.environ.get("DIAGNOSTIC") == "true",
        manifest_sha256=hashlib.sha256(release.asset("release-manifest.json")).hexdigest(),
        binary_sha256=hashlib.sha256(release.binary(target)).hexdigest(),
        result="passed" if passed else "failed",
        tier="e2e",
        coverage=[case],
        exchange_requests=0,
        exit_code=exit_code,
        expected_refusal=literal,
        log_sha256=hashlib.sha256(output).hexdigest(),
        mechanism=mechanism,
        observed_mode=observed_mode,
    )
    (work / f"{case}.json").write_text(json.dumps(value) + "\n")


def execute(
    release: Release,
    binary: Path,
    *,
    account: str,
    rules: str,
    work: Path,
    harness_commit: str,
    diagnostic: bool,
) -> list[str]:
    if not re.fullmatch(r"0x[0-9a-fA-F]{40}", account) or not re.fullmatch(
        r"zr1_[A-Za-z0-9_-]+", rules
    ):
        raise MatrixError("explicit account and canonical rules required")
    if not re.fullmatch(r"[0-9a-f]{40}", harness_commit):
        raise MatrixError("exact harness source identity required")
    system = platform.system()
    target = {"Linux": "linux-amd64", "Darwin": "darwin-arm64", "Windows": "windows-amd64"}[system]
    digest = hashlib.sha256(release.binary(target)).hexdigest()
    if (
        binary.is_symlink()
        or not binary.is_file()
        or hashlib.sha256(binary.read_bytes()).hexdigest() != digest
    ):
        raise MatrixError("refusal executable differs from authenticated released subject")
    other = account[:-1] + ("0" if account[-1] != "0" else "1")
    cases = [
        ("missing-consent", [], "mainnet needs --confirm-mainnet"),
        (
            "wrong-account-consent",
            ["--confirm-mainnet", other],
            "the confirmation does not name the account",
        ),
    ]
    route = "linux-systemd" if system == "Linux" else "homebrew-foreground"
    if system == "Windows":
        route = "windows-per-user"
        cases = [
            (
                "windows-per-user",
                ["--confirm-mainnet", account],
                "mainnet is not offered on Windows outside the protected machine service",
            )
        ]
    work.mkdir(mode=0o700, parents=True, exist_ok=True)
    checks = []
    for case, extra, literal in cases:
        home = work / (case + "-home")
        home.mkdir(mode=0o700)
        words = [
            str(binary),
            "--home",
            str(home),
            "init",
            "--non-interactive",
            "--network",
            "mainnet",
            "--no-key",
            "--rules",
            rules,
            "--account",
            account,
            "--equity-cap",
            "100",
            *extra,
        ]
        result = subprocess.run(
            words,
            env={
                "PATH": os.environ.get("PATH", os.defpath),
                "HOME": str(home),
                "USERPROFILE": str(home),
            },
            input=b"",
            capture_output=True,
            timeout=30,
            check=False,
        )
        body = (
            (result.stdout + result.stderr)
            .decode(errors="replace")
            .replace(account, "[ACCOUNT]")
            .replace(other, "[OTHER_ACCOUNT]")
            .encode()
        )
        (work / f"{case}.log").write_bytes(body)
        passed = result.returncode != 0 and literal.encode() in body and not list(home.iterdir())
        value: dict[str, Any] = dict(
            schema=1,
            journey="M2",
            route=route,
            tag=release.tag,
            commit=release.commit,
            harness_commit=harness_commit,
            diagnostic=diagnostic,
            manifest_sha256=hashlib.sha256(release.asset("release-manifest.json")).hexdigest(),
            binary_sha256=digest,
            result="passed" if passed else "failed",
            tier="e2e",
            coverage=[case],
            exchange_requests=0,
            exit_code=result.returncode,
            expected_refusal=literal,
            log_sha256=hashlib.sha256(body).hexdigest(),
        )
        (work / f"{case}.json").write_text(json.dumps(value) + "\n")
        if not passed:
            raise MatrixError("literal released-byte refusal missing or setup wrote state")
        checks.append(case)
    return checks


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("tag", "commit", "account", "harness-commit"):
        parser.add_argument("--" + name, required=True)
    for name in ("assets", "binary", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--diagnostic", action="store_true")
    args = parser.parse_args()
    rules = json.loads((ROOT / "rules/vectors.json").read_bytes())["valid"][0]["canonical"]
    execute(
        Release(args.tag, args.commit, args.assets),
        args.binary,
        account=args.account,
        rules=rules,
        work=args.output,
        harness_commit=args.harness_commit,
        diagnostic=args.diagnostic,
    )


if __name__ == "__main__":
    main()
