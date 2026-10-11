"""Execute the exported signing and custody contracts on the exact released source."""

import argparse
import hashlib
import json
import os
import platform
import re
from pathlib import Path

from guard_harness.native_release import Release
from guard_harness.runner import run

PLATFORMS = {"Linux": "linux", "Darwin": "macos", "Windows": "windows"}
CHECKS = ("hl-protocol.sdk-vectors", "guard-core.sign", "guard.keyread", "guard.framing")
BASE_COMMANDS = (
    ("zunder-hl-protocol", "--test", "sdk_vectors"),
    ("zunder-guard-core", "--lib", "sign::"),
    ("zunder-guard", "--lib", "keyread::"),
    ("zunder-guard", "--lib", "framing"),
)


def execute(release: Release, output: Path) -> None:
    system = PLATFORMS.get(platform.system())
    if system is None or output.exists() or not output.is_absolute():
        raise ValueError("fresh supported signing-contract workspace required")
    output.mkdir(mode=0o700)
    checkout = run(
        ["git", "rev-parse", "HEAD"], log=output / "checkout.log", timeout=30
    ).output.strip()
    if checkout != release.commit:
        raise ValueError("signing source differs from authenticated released source")
    manifest = release.asset("release-manifest.json")
    commands = list(BASE_COMMANDS)
    if system in {"macos", "windows"}:
        commands.append(("zunder-guard", "--lib", f"service::{system}::"))
    # No purpose-specific credential or account variables enter the Rust test process.
    safe = {
        key: value
        for key, value in os.environ.items()
        if key
        in {
            "PATH",
            "HOME",
            "USERPROFILE",
            "SYSTEMROOT",
            "SystemRoot",
            "TEMP",
            "TMP",
            "CARGO_HOME",
            "RUSTUP_HOME",
            "RUSTUP_TOOLCHAIN",
            "SSL_CERT_FILE",
            "LANG",
            "VCINSTALLDIR",
            "VCToolsInstallDir",
            "WindowsSdkDir",
            "INCLUDE",
            "LIB",
            "LIBPATH",
        }
    }
    safe.update(CARGO_BUILD_JOBS="2", CARGO_INCREMENTAL="0", CARGO_TERM_COLOR="never")
    checks = list(CHECKS)
    if system in {"macos", "windows"}:
        checks.append(f"guard.service.{system}")
    for index, command in enumerate(commands):
        argv = ["cargo", "test", "--locked", "-p", *command]
        result = run(argv, env=safe, log=output / f"contract-{index}.log", timeout=1800)
        counts = re.findall(r"test result: ok\. ([0-9]+) passed; 0 failed;", result.output)
        passed = sum(map(int, counts))
        if passed <= 0:
            raise ValueError("signing contract filter executed no passing tests")

    predicate = dict(
        schema=1,
        commit=release.commit,
        manifest_sha256=hashlib.sha256(manifest).hexdigest(),
        result="passed",
        platform=system,
        checks=checks,
        networks=["mainnet", "testnet"],
    )
    (output / "signing.predicate.json").write_text(json.dumps(predicate) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("tag", "commit"):
        parser.add_argument("--" + name, required=True)
    for name in ("assets", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    execute(Release(args.tag, args.commit, args.assets), args.output)


if __name__ == "__main__":
    main()
