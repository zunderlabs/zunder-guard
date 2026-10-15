"""Reauthenticate the complete gate and atomically replace its staged head."""

import argparse
import hashlib
import os
from pathlib import Path

from guard_harness.gate_state import bundles
from guard_harness.publication import prepare, publish
from guard_harness.release_state import canonical_bytes
from guard_harness.state_verifier import authenticate_state
from guard_harness.testnet_run import ROOT, _receipt


def execute(
    *, work: Path, evidence: Path, bundle: Path, tag: str, commit: str, run_id: str, attempt: str
) -> None:
    token = os.environ.pop("INSTALLER_PUBLISH_TOKEN", "")
    if not token or any(character.isspace() for character in token):
        raise ValueError("publication credential missing or malformed")
    with bundle.open("rb") as source:
        captured = source.read(2 * 1024 * 1024 + 1)
    if not 0 < len(captured) <= 2 * 1024 * 1024:
        raise ValueError("attestation bundle size refused")
    snapshot = work / "gated.sigstore.json"
    with snapshot.open("xb") as stream:
        snapshot.chmod(0o600)
        stream.write(captured)
    previous = authenticate_state(
        work / "assets/release-manifest.json",
        work / "staged.predicate.json",
        work / "staged.sigstore.json",
        manifest_schema=ROOT / "release/manifest.schema.json",
        state_schema=ROOT / "release/state.schema.json",
        commit=commit,
        tag=tag,
        workflow="verify.yml",
        previous=None,
        verified_journeys=frozenset(),
        log=work / "gate-publication-logs/staged.log",
    )
    publication = prepare(
        work / "assets",
        work / "gated.predicate.json",
        snapshot,
        manifest_schema=ROOT / "release/manifest.schema.json",
        state_schema=ROOT / "release/state.schema.json",
        commit=commit,
        tag=tag,
        workflow="verify.yml",
        previous=previous,
        expected=hashlib.sha256(canonical_bytes(previous.predicate)).hexdigest(),
        journeys=bundles(evidence, run_id=run_id, attempt=attempt),
        logs=work / "gate-publication-logs",
        expected_run_id=run_id,
        expected_run_attempt=attempt,
    )
    digest = publish(publication, token=token)
    _receipt(work, {"tag": tag, "commit": commit, "state_sha256": digest, "stage": "gated"})
    (work / "receipt.json").rename(work / "gate-publication.json")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("work", "evidence", "bundle"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("tag", "commit", "run-id", "attempt"):
        parser.add_argument("--" + name, required=True)
    execute(**vars(parser.parse_args()))


if __name__ == "__main__":
    main()
