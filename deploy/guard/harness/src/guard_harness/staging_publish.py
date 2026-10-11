"""Publish only an authenticated staged genesis to an empty installer-store head."""

import argparse
import json
import os
from pathlib import Path

from guard_harness.publication import prepare, publish
from guard_harness.staged_subjects import _private
from guard_harness.testnet_run import ROOT, _read, _receipt


def execute(*, tag: str, commit: str, work: Path, bundle: Path) -> None:
    # Verification subprocesses must never inherit the publication credential.
    token = os.environ.pop("INSTALLER_PUBLISH_TOKEN", "")
    if not token or any(character.isspace() for character in token):
        raise ValueError("publication credential missing or malformed")
    _private(work, directory=True)
    if (work / "publication.json").exists():
        raise ValueError("publication already has a receipt; do not replay")
    state = work / "staged.predicate.json"
    received = json.loads(_read(state, 65536))
    if (
        received.get("stage") != "staged"
        or received.get("revision") != 1
        or received.get("previous") is not None
    ):
        raise ValueError("initial staged genesis required")
    # The action produces a public bundle outside this private workspace. Capture
    # bounded bytes once; prepare verifies its signature against the captured state.
    with bundle.open("rb") as stream:
        captured = stream.read(2 * 1024 * 1024 + 1)
    if not captured or len(captured) > 2 * 1024 * 1024:
        raise ValueError("attestation bundle size refused")
    captured_bundle = work / "staged.sigstore.json"
    with captured_bundle.open("xb") as stream:
        captured_bundle.chmod(0o600)
        stream.write(captured)
    publication = prepare(
        work / "assets",
        state,
        captured_bundle,
        manifest_schema=ROOT / "release/manifest.schema.json",
        state_schema=ROOT / "release/state.schema.json",
        commit=commit,
        tag=tag,
        workflow="verify.yml",
        previous=None,
        expected=None,
        journeys={},
        logs=work / "publication-logs",
    )
    digest = publish(publication, token=token)
    # Receipt writes use the existing private atomic writer. A missing receipt
    # after any uncertain POST requires head reconciliation, never another POST.
    _receipt(work, {"tag": tag, "commit": commit, "state_sha256": digest, "stage": "staged"})
    (work / "receipt.json").rename(work / "publication.json")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("tag", "commit"):
        parser.add_argument("--" + name, required=True)
    for name in ("work", "bundle"):
        parser.add_argument("--" + name, type=Path, required=True)
    execute(**vars(parser.parse_args()))


if __name__ == "__main__":
    main()
