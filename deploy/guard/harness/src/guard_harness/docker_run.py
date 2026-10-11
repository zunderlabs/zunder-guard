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


def _version(tag: str) -> tuple[int, int, int, int, int]:
    match = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)(?:-rc\.([1-9]\d*))?", tag)
    if match is None:
        raise ValueError("release version required")
    # A final version follows every RC with the same numeric version.
    return int(match[1]), int(match[2]), int(match[3]), 0 if match[4] else 1, int(match[4] or 0)


def execute(
    *,
    tag: str,
    commit: str,
    account: str,
    work: Path,
    previous_tag: str | None = None,
    previous_commit: str | None = None,
) -> None:
    if (
        not re.fullmatch(r"v\d+\.\d+\.\d+(?:-rc\.[1-9]\d*)?", tag)
        or not re.fullmatch(r"[0-9a-f]{40}", commit)
        or not re.fullmatch(r"0x[0-9a-fA-F]{40}", account)
    ):
        raise ValueError("explicit release/public account identity required")
    if (previous_tag is None) != (previous_commit is None):
        raise ValueError("previous release tag and commit must be supplied together")
    if previous_tag is not None and (
        not re.fullmatch(r"[0-9a-f]{40}", previous_commit or "")
        or _version(previous_tag) >= _version(tag)
        or previous_commit == commit
    ):
        raise ValueError("previous release must precede the candidate on distinct source bytes")
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
        previous_image = None
        previous_digest = None
        previous_compose = None
        if previous_tag is not None and previous_commit is not None:
            run(
                [
                    "bash",
                    str(ROOT / "github/verify-release-assets.sh"),
                    previous_tag,
                    str(work / "previous-assets"),
                ],
                env=env,
                log=work / "previous-assets.log",
                timeout=600,
                stdin=b"",
                secrets=[env.get("GH_TOKEN", ""), env.get("GITHUB_TOKEN", "")],
            )
            previous_image, previous_payload, previous_digest = subjects(
                work / "previous-assets", tag=previous_tag, commit=previous_commit
            )
            if previous_image == image:
                raise ValueError("upgrade requires distinct authenticated images")
            previous_compose = work / "previous-compose.yaml"
            with previous_compose.open("xb") as stream:
                stream.write(previous_payload)
        # Registry login is unnecessary for the public release image. No caller credential
        # or wallet key enters Docker; the verifier already authenticated this exact digest.
        runtime_env = {name: env[name] for name in ("PATH", "HOME") if name in env}
        if previous_image is not None:
            run(
                ["docker", "pull", previous_image],
                env=runtime_env,
                log=work / "previous-pull.log",
                timeout=300,
                stdin=b"",
            )
        run(
            ["docker", "pull", image],
            env=runtime_env,
            log=work / "pull.log",
            timeout=300,
            stdin=b"",
        )
        if previous_image is None:
            lifecycle(image, account, work=work / "docker-paper")
            lifecycle(image, account, work=work / "compose-paper", compose=compose)
        else:
            lifecycle(image, account, work=work / "docker-paper", previous_image=previous_image)
            lifecycle(
                image,
                account,
                work=work / "compose-paper",
                compose=compose,
                previous_image=previous_image,
                previous_compose=previous_compose,
            )
        (work / "receipt.json").write_text(
            json.dumps(
                {
                    "tag": tag,
                    "commit": commit,
                    "manifest_sha256": digest,
                    "image": image,
                    "compose_sha256": hashlib.sha256(payload).hexdigest(),
                    "previous_release": None
                    if previous_image is None
                    else {
                        "tag": previous_tag,
                        "commit": previous_commit,
                        "manifest_sha256": previous_digest,
                        "image": previous_image,
                    },
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
    parser.add_argument("--previous-tag")
    parser.add_argument("--previous-commit")
    execute(**vars(parser.parse_args()))


if __name__ == "__main__":
    main()
