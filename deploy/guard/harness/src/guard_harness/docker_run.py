"""Authenticate exact Docker/Compose release subjects, then run keyless paper lifecycles."""

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

from guard_harness.docker_paper import lifecycle
from guard_harness.docker_testnet import lifecycle as testnet_lifecycle
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
    api_wallet: str | None = None,
    testnet_key: bytes | None = None,
    testnet_account: str | None = None,
    diagnostic: bool = False,
    scenario: str | None = None,
    channel: str = "both",
) -> None:
    if (
        not re.fullmatch(r"v\d+\.\d+\.\d+(?:-rc\.[1-9]\d*)?", tag)
        or not re.fullmatch(r"[0-9a-f]{40}", commit)
        or not re.fullmatch(r"0x[0-9a-fA-F]{40}", account)
    ):
        raise ValueError("explicit release/public account identity required")
    if scenario not in {None, "fresh", "upgrade"} or channel not in {"both", "docker", "compose"}:
        raise ValueError("explicit Docker scenario/channel required")
    if scenario == "upgrade" and previous_tag is None:
        raise ValueError("upgrade predecessor required")
    if (previous_tag is None) != (previous_commit is None):
        raise ValueError("previous release tag and commit must be supplied together")
    if previous_tag is not None and (
        not re.fullmatch(r"[0-9a-f]{40}", previous_commit or "")
        or _version(previous_tag) >= _version(tag)
        or previous_commit == commit
    ):
        raise ValueError("previous release must precede the candidate on distinct source bytes")
    if (api_wallet is None) != (testnet_key is None):
        raise ValueError("Testnet wallet and private stdin key required together")
    if testnet_key is not None and (
        previous_tag is None
        or testnet_account is None
        or not re.fullmatch(r"0x[0-9a-fA-F]{40}", testnet_account)
        or not re.fullmatch(rb"[0-9a-fA-F]{64}\n", testnet_key)
        or os.environ.get("GUARD_C6_SERIALIZED") != "1"
    ):
        raise ValueError("framed key, Testnet account, predecessor and C6 serialization required")
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
        selected = ("docker", "compose") if channel == "both" else (channel,)
        selected_scenario = scenario or ("upgrade" if previous_image else "fresh")
        for selected_channel in selected:
            source = compose if selected_channel == "compose" else None
            predecessor = previous_compose if selected_channel == "compose" else None
            paper_work = (
                work / (selected_channel + "-paper")
                if scenario is None
                else work / "paper" / selected_scenario / selected_channel
            )
            paper_work.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            paper_version = tag.removeprefix("v") if scenario is not None else None
            paper_previous_version = (
                previous_tag.removeprefix("v") if scenario is not None and previous_tag else None
            )
            if selected_scenario == "fresh":
                lifecycle(
                    image,
                    account,
                    work=paper_work,
                    compose=source,
                    version=paper_version,
                    previous_version=paper_previous_version,
                )
            else:
                lifecycle(
                    image,
                    account,
                    work=paper_work,
                    compose=source,
                    previous_image=previous_image,
                    previous_compose=predecessor,
                    version=paper_version,
                    previous_version=paper_previous_version,
                )
            if testnet_key is not None:
                assert api_wallet is not None and testnet_account is not None
                assert previous_image is not None and previous_tag is not None
                testnet_work = (
                    work / (selected_channel + "-testnet")
                    if scenario is None
                    else work / "testnet" / selected_scenario / selected_channel
                )
                testnet_work.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                testnet_lifecycle(
                    image,
                    testnet_account,
                    api_wallet=api_wallet,
                    key=testnet_key,
                    work=testnet_work,
                    previous_image=previous_image,
                    version=tag.removeprefix("v"),
                    previous_version=previous_tag.removeprefix("v"),
                    compose=source,
                    previous_compose=predecessor,
                    scenario=selected_scenario,
                )
        (work / "receipt.json").write_text(
            json.dumps(
                {
                    "harness_commit": os.environ.get("GITHUB_SHA"),
                    "scenario": selected_scenario,
                    "channel": channel,
                    "diagnostic": diagnostic or os.environ.get("GITHUB_SHA") != commit,
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
                    "checks": ["signed-release", *[name + "-paper" for name in selected]]
                    + ([name + "-testnet" for name in selected] if testnet_key is not None else []),
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
    parser.add_argument("--api-wallet")
    parser.add_argument("--testnet-account")
    parser.add_argument("--testnet-key-stdin", action="store_true")
    parser.add_argument("--diagnostic", action="store_true")
    parser.add_argument("--scenario", choices=("fresh", "upgrade"), required=True)
    parser.add_argument("--channel", choices=("docker", "compose"), required=True)
    args = vars(parser.parse_args())
    if args.pop("testnet_key_stdin"):
        key = sys.stdin.buffer.read(68)
        if key.startswith(b"0x"):
            key = key[2:]
        args["testnet_key"] = key
    execute(**args)


if __name__ == "__main__":
    main()
