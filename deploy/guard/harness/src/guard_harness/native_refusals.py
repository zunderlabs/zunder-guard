"""Native mainnet setup refusals on an authenticated installed binary; no /exchange."""

import hashlib
import os
import subprocess
from collections.abc import Mapping
from pathlib import Path

from guard_harness.native_paper import LifecycleError


def refuse(
    binary: Path,
    home: Path,
    args: list[str],
    *,
    expected: str,
    log: Path,
    env: Mapping[str, str] | None = None,
) -> None:
    clean = {name: value for name, value in os.environ.items() if not name.startswith("ZUNDER_")}
    clean.update(env or {})
    result = subprocess.run(
        [str(binary), "--home", str(home), *args],
        env=clean,
        input=b"",
        capture_output=True,
        timeout=30,
        check=False,
    )
    output = (result.stdout + result.stderr).decode(errors="replace")
    log.write_text(output)
    if result.returncode == 0 or expected not in output:
        raise LifecycleError("expected native mainnet refusal was not observed")


def setup_refusals(
    binary: Path, *, sha256: str, account: str, rules: str, work: Path, windows: bool
) -> list[str]:
    if hashlib.sha256(binary.read_bytes()).hexdigest() != sha256:
        raise LifecycleError("mainnet refusal subject differs from released binary")
    work.mkdir(mode=0o700)
    checks: list[str] = []
    common = [
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
    ]
    cases = [
        ("missing-consent", [], "mainnet needs --confirm-mainnet"),
        (
            "wrong-account-consent",
            ["--confirm-mainnet", "0x" + "1" * 40],
            "the confirmation does not name the account",
        ),
    ]
    if windows:
        # The actual released per-user binary denies the entire mainnet route first.
        cases = [
            (
                "windows-per-user",
                ["--confirm-mainnet", account],
                "mainnet is not offered on Windows outside the protected machine service",
            )
        ]
    for name, extra, expected in cases:
        home = work / name
        home.mkdir(mode=0o700)
        refuse(binary, home, common + extra, expected=expected, log=work / f"{name}.log")
        if list(home.iterdir()):
            raise LifecycleError("refused setup wrote state or credentials")
        checks.append(name)
    return checks
