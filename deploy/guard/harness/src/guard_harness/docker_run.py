"""Authenticate exact Docker/Compose release subjects, then run keyless paper lifecycles."""

import argparse
import hashlib
import json
import os
import re
from pathlib import Path

from guard_harness.docker_paper import lifecycle
from guard_harness.runner import run
from guard_harness.staged_subjects import _private
from guard_harness.testnet_run import ROOT, verified_asset


def subjects(assets: Path, *, tag: str, commit: str) -> tuple[str, bytes, str]:
    """Only after this invocation's real asset/image/provenance verifier succeeds."""
    descriptor, manifest_digest = verified_asset(
        assets, f"zunder-guard-{tag}.image.txt", tag=tag, commit=commit
    )
    compose, compose_manifest = verified_asset(assets, "compose.yaml", tag=tag, commit=commit)
    if compose_manifest != manifest_digest:
        raise ValueError("release metadata changed between subjects")
    reference = descriptor.decode("ascii").removesuffix("\n")
    if not re.fullmatch(r"ghcr\.io/zunderlabs/zunder-guard@sha256:[0-9a-f]{64}", reference):
        raise ValueError("signed immutable image reference required")
    captured_manifest = (assets / "release-manifest.json").read_bytes()
    if hashlib.sha256(captured_manifest).hexdigest() != manifest_digest:
        raise ValueError("release metadata changed before image binding")
    build = json.loads(captured_manifest)
    docker = build["distribution"]["docker"]
    if reference != docker["image"] + "@" + docker["digest"]:
        raise ValueError("signed image descriptor differs from C2")
    # The renderer pins the signed payload's default image to the same immutable subject.
    expected = "${ZUNDER_GUARD_IMAGE:-" + reference + "}"
    text = compose.decode("utf-8")
    if text.count("    image: " + expected + "\n") != 1:
        raise ValueError("signed Compose image differs from C2")
    return reference, compose, manifest_digest


def execute(*, tag: str, commit: str, account: str, work: Path) -> None:
    if (
        not re.fullmatch(r"v\d+\.\d+\.\d+(?:-rc\.[1-9]\d*)?", tag)
        or not re.fullmatch(r"[0-9a-f]{40}", commit)
        or not re.fullmatch(r"0x[0-9a-fA-F]{40}", account)
    ):
        raise ValueError("explicit release/public account identity required")
    _private(work.parent, directory=True)
    if not work.is_absolute() or work.exists() or work.is_symlink():
        raise ValueError("fresh private Docker workspace required")
    work.mkdir(mode=0o700)
    previous = os.umask(0o077)
    try:
        env = {
            name: os.environ[name]
            for name in ("PATH", "HOME", "GH_TOKEN", "GITHUB_TOKEN")
            if name in os.environ
        }
        env["GITHUB_REPOSITORY"] = "zunderlabs/zunder-guard"
        run(
            ["bash", str(ROOT / "github/verify-release-assets.sh"), tag, str(work / "assets")],
            env=env,
            log=work / "assets.log",
            timeout=600,
            stdin=b"",
            secrets=[env.get("GH_TOKEN", ""), env.get("GITHUB_TOKEN", "")],
        )
        image, payload, digest = subjects(work / "assets", tag=tag, commit=commit)
        compose = work / "subject-compose.yaml"
        with compose.open("xb") as stream:
            stream.write(payload)
        # Registry login is unnecessary for the public release image. No caller credential
        # or wallet key enters Docker; the verifier already authenticated this exact digest.
        runtime_env = {name: env[name] for name in ("PATH", "HOME") if name in env}
        run(
            ["docker", "pull", image],
            env=runtime_env,
            log=work / "pull.log",
            timeout=300,
            stdin=b"",
        )
        lifecycle(image, account, work=work / "docker-paper")
        lifecycle(image, account, work=work / "compose-paper", compose=compose)
        (work / "receipt.json").write_text(
            json.dumps(
                {
                    "tag": tag,
                    "commit": commit,
                    "manifest_sha256": digest,
                    "image": image,
                    "compose_sha256": hashlib.sha256(payload).hexdigest(),
                    "checks": ["signed-release", "docker-paper", "compose-paper"],
                    "release_ready": False,
                }
            )
            + "\n"
        )
    finally:
        os.umask(previous)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("tag", "commit", "account"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--work", type=Path, required=True)
    execute(**vars(parser.parse_args()))


if __name__ == "__main__":
    main()
