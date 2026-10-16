"""Stable promotion transaction: full gate admission, signed publication, bounded rollback."""

import argparse
import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from guard_harness.attestation import AttestationError, invocation_run, verify_predicate
from guard_harness.channel_head import read as read_head
from guard_harness.gate_state import bundles
from guard_harness.homebrew_stage import Tap
from guard_harness.journey_evidence import authenticate_gate
from guard_harness.native_release import Release, authenticate
from guard_harness.promotion_archive import gate_attempt, recover
from guard_harness.promotion_channels import Channels, public_get
from guard_harness.promotion_recovery import authenticate as authenticate_snapshot
from guard_harness.promotion_recovery import snapshot as make_snapshot
from guard_harness.promotion_registry import prepare_sentinel, sentinel
from guard_harness.promotion_state import capture, gate, stable, successor
from guard_harness.promotion_state import prepare as prepare_state
from guard_harness.publication import USER_AGENT, Publication, _NoRedirect, prepare, publish
from guard_harness.release_state import canonical_bytes, predicate_digest
from guard_harness.runner import RunError
from guard_harness.state_verifier import VerifiedState
from guard_harness.testnet_run import ROOT


def outputs(values: dict[str, str]) -> None:
    target = os.environ.get("GITHUB_OUTPUT")
    if target:
        with Path(target).open("a") as stream:
            for key, value in values.items():
                # A step output name; digits included (v1.0.0 promote: "manifest_sha256").
                if not re.fullmatch(r"[a-z][a-z0-9_]*", key) or "\n" in value or "\r" in value:
                    raise ValueError("workflow output refused")
                stream.write(f"{key}={value}\n")


def verification_run(state: dict[str, Any]) -> str:
    """The one verification run of a gated or promoted state's journey references.

    Each reference names its own row's attempt (decision of 15 Oct 2026); the gate's
    own attempt is recovered from its authenticated signature, never from a reference.
    """
    references = state.get("evidence")
    if not isinstance(references, dict) or not references:
        raise AttestationError("prior gate must identify its verification run")
    runs = set()
    for reference in references.values():
        if not isinstance(reference, str):
            raise AttestationError("prior verification run reference refused")
        runs.add(invocation_run(reference)[0])
    if len(runs) != 1:
        raise AttestationError("prior gate must identify one exact verification run")
    return runs.pop()


def prior(work: Path, digest: str | None, state: dict[str, Any] | None) -> Release | None:
    if digest is None or state is None or state.get("stage") == "withdrawn":
        return None
    if state.get("stage") != "promoted":
        raise AttestationError("canonical head must be promoted or withdrawn")
    stable(state["tag"], state["commit"])
    release = authenticate(state["tag"], state["commit"], work / "prior")
    response = public_get("https://zunderlabs.com/guard/release.json.sigstore")
    if response is None or response[1].get("x-zunder-state-sha256") != digest:
        raise AttestationError("prior canonical bundle snapshot raced")
    root = work / "prior"
    (root / "promoted.predicate.json").write_bytes(canonical_bytes(state))
    (root / "promoted.sigstore.json").write_bytes(response[0])
    run_id = verification_run(state)
    evidence = root / "evidence"
    attempt = recover(
        evidence,
        manifest=release.assets / "release-manifest.json",
        promoted=state,
        run_id=run_id,
        logs=root / "logs/archive",
    )
    previous = gate(release, evidence, run_id=run_id, attempt=attempt, logs=root / "logs/gate")
    verified = authenticate_gate(
        release.assets / "release-manifest.json",
        root / "promoted.predicate.json",
        root / "promoted.sigstore.json",
        bundles(evidence, run_id=run_id, attempt=attempt),
        manifest_schema=ROOT / "release/manifest.schema.json",
        state_schema=ROOT / "release/state.schema.json",
        commit=release.commit,
        tag=release.tag,
        workflow="promote.yml",
        previous=previous,
        logs=root / "logs/promotion",
    )
    if predicate_digest(verified.predicate) != digest:
        raise AttestationError("prior capsule digest differs from authenticated canonical head")
    return release


def admitted_canonical(work: Path) -> tuple[Release, Publication]:
    """Fresh full-gate cryptographic admission and exact four-endpoint readback.

    Refuses absent/withdrawn heads. Uses immutable attestation-store bundles rather
    than expiring workflow artifacts. This function performs no external writes.
    """
    from guard_harness.canonical_readback import check

    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    digest, state = read_head("canonical")
    release = prior(work, digest, state)
    if release is None or state is None:
        raise AttestationError("no promoted stable canonical release")
    run_id = verification_run(state)
    root = work / "prior"
    evidence = root / "evidence"
    attempt = gate_attempt(evidence, run_id)
    previous = gate(
        release, evidence, run_id=run_id, attempt=attempt, logs=root / "logs/readback-gate"
    )
    capsule = prepare(
        release.assets,
        root / "promoted.predicate.json",
        root / "promoted.sigstore.json",
        manifest_schema=ROOT / "release/manifest.schema.json",
        state_schema=ROOT / "release/state.schema.json",
        commit=release.commit,
        tag=release.tag,
        workflow="promote.yml",
        previous=previous,
        expected=None,
        journeys=bundles(evidence, run_id=run_id, attempt=attempt),
        logs=root / "logs/readback",
    )
    check(capsule)
    return release, capsule


def original(args: argparse.Namespace) -> tuple[str, str]:
    return (
        getattr(args, "source_run", "") or os.environ.get("GITHUB_RUN_ID", ""),
        getattr(args, "source_attempt", "") or os.environ.get("GITHUB_RUN_ATTEMPT", ""),
    )


def admitted_snapshot(args: argparse.Namespace) -> dict[str, Any]:
    source_run, source_attempt = original(args)
    return authenticate_snapshot(
        args.work,
        tag=args.tag,
        commit=args.commit,
        run_id=args.run_id,
        attempt=args.attempt,
        source_run=source_run,
        source_attempt=source_attempt,
    )


def admitted_prior(args: argparse.Namespace, transaction: dict[str, Any]) -> None:
    old = transaction["prior"]
    if old is None:
        return
    stable(old["tag"], old["commit"])
    root = args.work / "prior"
    release = Release(old["tag"], old["commit"], root / "assets")
    state = json.loads((root / "promoted.predicate.json").read_bytes())
    run_id = verification_run(state)
    evidence = root / "evidence"
    attempt = gate_attempt(evidence, run_id)
    previous = gate(
        release, evidence, run_id=run_id, attempt=attempt, logs=root / "logs/recovery-gate"
    )
    verified = authenticate_gate(
        release.assets / "release-manifest.json",
        root / "promoted.predicate.json",
        root / "promoted.sigstore.json",
        bundles(evidence, run_id=run_id, attempt=attempt),
        manifest_schema=ROOT / "release/manifest.schema.json",
        state_schema=ROOT / "release/state.schema.json",
        commit=release.commit,
        tag=release.tag,
        workflow="promote.yml",
        previous=previous,
        logs=root / "logs/recovery-promotion",
    )
    if predicate_digest(verified.predicate) != old["digest"]:
        raise AttestationError("authenticated prior capsule differs from signed snapshot")


def publication(args: argparse.Namespace, *, withdrawal: bool = False) -> Publication:
    release = Release(args.tag, args.commit, args.work / "candidate/assets")
    previous = gate(
        release,
        args.evidence,
        run_id=args.run_id,
        attempt=args.attempt,
        logs=args.work / "logs/gate-repeat",
    )
    journeys = bundles(args.evidence, run_id=args.run_id, attempt=args.attempt)
    if withdrawal:
        previous = authenticate_gate(
            release.assets / "release-manifest.json",
            args.work / "promoted.predicate.json",
            args.work / "promoted.sigstore.json",
            journeys,
            manifest_schema=ROOT / "release/manifest.schema.json",
            state_schema=ROOT / "release/state.schema.json",
            commit=args.commit,
            tag=args.tag,
            workflow="promote.yml",
            expected_run_id=original(args)[0],
            expected_run_attempt=original(args)[1],
            previous=previous,
            logs=args.work / "logs/promotion-repeat",
        )
    transaction = json.loads((args.work / "transaction.json").read_bytes())
    stage = "withdrawn" if withdrawal else "promoted"
    if not withdrawal:
        verify_predicate(
            release.assets / "release-manifest.json",
            args.work / "promoted.sigstore.json",
            workflow="promote.yml",
            commit=args.commit,
            tag=args.tag,
            predicate_type="https://zunderlabs.com/guard/release-state/v1",
            log=args.work / "logs/original-promotion-invocation.log",
            expected_run_id=original(args)[0],
            expected_run_attempt=original(args)[1],
        )
    return prepare(
        release.assets,
        args.work / f"{stage}.predicate.json",
        args.work / f"{stage}.sigstore.json",
        manifest_schema=ROOT / "release/manifest.schema.json",
        state_schema=ROOT / "release/state.schema.json",
        commit=args.commit,
        tag=args.tag,
        workflow="promote.yml",
        previous=previous,
        expected=predicate_digest(previous.predicate)
        if withdrawal
        else transaction["canonical_before"],
        journeys={} if withdrawal else journeys,
        logs=args.work / f"logs/{stage}-publication",
    )


def restore(expected: str, target: str, *, token: str) -> None:
    if any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in (expected, target)):
        raise AttestationError("restore requires exact captured capsule digests")
    request = urllib.request.Request(
        "https://zunderlabs.com/guard/restore",
        method="POST",
        headers={
            "User-Agent": USER_AGENT,
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
        },
        data=canonical_bytes({"expected": expected, "restore": target}),
    )
    try:
        with urllib.request.build_opener(_NoRedirect()).open(request, timeout=45) as response:
            if response.status != 201 or json.loads(response.read(4097)) != {"digest": target}:
                raise ValueError()
    except (OSError, urllib.error.URLError, ValueError):
        # Never repeat an uncertain POST; reconcile its exact durable result once.
        observed, _ = read_head("canonical")
        if observed == target:
            return
        raise AttestationError(
            "restore refused or outcome unknown; reconcile durable head"
        ) from None


def publish_once(proposal: Publication, *, token: str) -> None:
    """No blind replay on uncertain POST outcomes; reconcile one exact durable read."""
    try:
        publish(proposal, token=token)
    except AttestationError:
        channel = json.loads(proposal.body)["channel"]
        observed, _ = read_head(channel)
        if observed != proposal.digest:
            raise


def channels(args: argparse.Namespace, token: str) -> Channels:
    transaction = json.loads((args.work / "transaction.json").read_bytes())
    old = transaction["prior"]
    previous = (
        None if old is None else Release(old["tag"], old["commit"], args.work / "prior/assets")
    )
    return Channels(
        Release(args.tag, args.commit, args.work / "candidate/assets"),
        previous,
        args.work,
        Tap(token=token, logs=args.work / "logs/tap")
        if token and not any(char.isspace() for char in token)
        else None,
    )


def prepare_phase(args: argparse.Namespace, installer_token: str, tap_token: str) -> None:
    prepare_state(
        args.work,
        args.evidence,
        tag=args.tag,
        commit=args.commit,
        run_id=args.run_id,
        attempt=args.attempt,
    )
    digest, state = read_head("canonical")
    previous = prior(args.work, digest, state)
    if previous and tuple(map(int, args.tag[1:].split("."))) <= tuple(
        map(int, previous.tag[1:].split("."))
    ):
        raise AttestationError("promotion cannot downgrade the prior stable release")
    transaction = {
        "canonical_before": digest,
        "prior": None
        if previous is None
        else {"tag": previous.tag, "commit": previous.commit, "digest": digest},
    }
    (args.work / "transaction.json").write_bytes(canonical_bytes(transaction))
    client = channels(args, os.environ.get("GH_TOKEN", ""))
    client.save(client.snapshot())
    make_snapshot(
        args.work, tag=args.tag, commit=args.commit, run_id=args.run_id, attempt=args.attempt
    )
    outputs({"manifest_sha256": (args.work / "subject.sha256").read_text().strip()})


def publish_phase(args: argparse.Namespace, installer_token: str, tap_token: str) -> None:
    snapshot_target = args.work / "rollback-snapshot.sigstore.json"
    if snapshot_target.exists():
        if (
            snapshot_target.is_symlink()
            or snapshot_target.read_bytes() != args.snapshot_bundle.read_bytes()
        ):
            raise AttestationError("retained snapshot attestation differs")
    else:
        capture(args.snapshot_bundle, snapshot_target)
    admitted_snapshot(args)
    capture(args.bundle, args.work / "promoted.sigstore.json")
    proposal = publication(args)
    staged, _ = read_head("staging")
    state = json.loads((args.work / "promoted.predicate.json").read_bytes())
    if staged != state["previous"]:
        raise AttestationError("staging gate changed before promotion")
    snapshot = json.loads((args.work / "channels.json").read_bytes())
    if snapshot["image_before"] is None:
        build = json.loads(
            Release(args.tag, args.commit, args.work / "candidate/assets").asset(
                "release-manifest.json"
            )
        )
        prepare_sentinel(
            sentinel(state["manifest_sha256"], proposal.digest),
            original=build["distribution"]["docker"]["digest"],
        )
    # Worker first: any later partial channel failure has a signed promoted head
    # that rollback can advance to withdrawal before restoring prior bytes.
    (args.work / "promotion-capsule.json").write_bytes(proposal.body)
    publish_once(proposal, token=installer_token)
    client = channels(args, tap_token)
    client.promote(json.loads((args.work / "channels.json").read_bytes()))
    outputs({"promoted_digest": proposal.digest})


def channels_rollback_phase(args: argparse.Namespace, installer_token: str, tap_token: str) -> None:
    """Restore owned channels using only the original signed pre-mutation baseline.

    Gate availability, canonical GETs and withdrawal signing are deliberately outside
    this phase. Each channel still admits its live head against its captured identity.
    """
    admitted_snapshot(args)
    failures = channels(args, tap_token).rollback(
        json.loads((args.work / "channels.snapshot.json").read_bytes())
    )
    (args.work / "channels-rollback.json").write_bytes(
        canonical_bytes({"result": "failed" if failures else "passed", "failed_channels": failures})
    )
    if failures:
        raise AttestationError("independent channel rollback incomplete; inspect channel outcomes")


def withdraw_phase(args: argparse.Namespace, installer_token: str, tap_token: str) -> None:
    transaction = admitted_snapshot(args)
    admitted_prior(args, transaction)
    if not (args.work / "promoted.sigstore.json").exists():
        current, _ = read_head("canonical")
        if current == transaction["canonical_before"]:
            outputs({"rollback_needed": "false"})
            return
        raise AttestationError("original promoted proof is missing; no rollback mutation admitted")
    # All original C2 proofs are authenticated independently of Worker availability.
    candidate = json.loads(json.loads(publication(args).body)["predicate"])
    promoted_digest = predicate_digest(candidate)
    try:
        current, state = read_head("canonical")
        head_known = True
    except AttestationError:
        current, state, head_known = None, None, False
    reused = False
    if head_known and current not in {transaction["canonical_before"], promoted_digest}:
        if (
            state is None
            or state.get("stage") != "withdrawn"
            or state.get("previous") != promoted_digest
        ):
            raise AttestationError("canonical head changed outside this promotion")
        try:
            response = public_get("https://zunderlabs.com/guard/release.json.sigstore")
            if response is None or response[1].get("x-zunder-state-sha256") != current:
                raise AttestationError("withdrawn canonical capsule readback raced")
            (args.work / "withdrawn.predicate.json").write_bytes(canonical_bytes(state))
            (args.work / "withdrawn.sigstore.json").write_bytes(response[0])
            publication(args, withdrawal=True)  # Authenticate live withdrawal before reuse.
            reused = True
        except (ValueError, RunError):
            # Never admit an opaque live head as evidence. A fresh derived proposal
            # still permits independently owned channel recovery while canonical waits.
            pass
    if not reused:
        verified = VerifiedState(candidate, candidate["manifest_sha256"])
        build = json.loads((args.work / "candidate/assets/release-manifest.json").read_bytes())
        (args.work / "withdrawn.predicate.json").write_bytes(
            canonical_bytes(successor(verified, build, stage="withdrawn"))
        )
    # Always retry independent channels even if canonical was already restored.
    outputs({"rollback_needed": "true"})


def rollback_phase(args: argparse.Namespace, installer_token: str, tap_token: str) -> None:
    transaction = admitted_snapshot(args)
    admitted_prior(args, transaction)
    target = args.work / "withdrawn.sigstore.json"
    if target.exists():
        if target.is_symlink():
            raise AttestationError("withdrawal bundle must be regular")
        target.unlink()
    capture(args.bundle, target)
    proposal = publication(args, withdrawal=True)
    candidate = predicate_digest(json.loads((args.work / "promoted.predicate.json").read_bytes()))
    canonical_failures: list[str] = []
    try:
        current, state = read_head("canonical")
    except AttestationError:
        current, state = None, None
        canonical_failures.append("canonical-read")
    if not canonical_failures and current not in {
        candidate,
        proposal.digest,
        transaction["canonical_before"],
    }:
        if (
            state is not None
            and state.get("stage") == "withdrawn"
            and state.get("previous") == candidate
        ):
            # A possibly owned withdrawal must be authenticated before restoration.
            # Its missing proof cannot prevent independently owned channel recovery.
            canonical_failures.append("canonical-withdrawal-proof")
        else:
            raise AttestationError("canonical head changed outside this promotion")
    failures = channels(args, tap_token).rollback(
        json.loads((args.work / "channels.snapshot.json").read_bytes())
    )
    failures.extend(canonical_failures)
    withdrawal_published = not canonical_failures and current == proposal.digest
    if not canonical_failures and current != transaction["canonical_before"]:
        try:
            if current != proposal.digest:
                publish_once(proposal, token=installer_token)
                withdrawal_published = True
        except (AttestationError, ValueError):
            failures.append("canonical-withdrawal")
        if transaction["prior"] is not None and "canonical-withdrawal" not in failures:
            try:
                restore(proposal.digest, transaction["prior"]["digest"], token=installer_token)
            except (AttestationError, ValueError):
                failures.append("canonical")
    (args.work / "rollback.json").write_bytes(
        canonical_bytes(
            {
                "result": "failed" if failures else "passed",
                "failed_channels": failures,
                "stage": "rollback-complete" if not failures else "rollback-incomplete",
                "withdrawn_sha256": proposal.digest,
                "withdrawal_published": withdrawal_published,
                "canonical_restored": transaction["prior"] is not None
                and not canonical_failures
                and "canonical" not in failures
                and "canonical-withdrawal" not in failures,
            }
        )
    )
    if failures:
        raise AttestationError(
            "rollback incomplete; inspect channel diagnostics and signed withdrawal"
        )


def restore_phase(args: argparse.Namespace, installer_token: str, tap_token: str) -> None:
    transaction = admitted_snapshot(args)
    admitted_prior(args, transaction)
    proposal = publication(args, withdrawal=True)
    if transaction["prior"] is None:
        raise AttestationError("first stable release has no canonical predecessor to restore")
    current, _ = read_head("canonical")
    target = transaction["prior"]["digest"]
    if current == target:
        return
    if current != proposal.digest:
        raise AttestationError(
            "restore refuses a canonical head outside the authenticated withdrawal"
        )
    restore(proposal.digest, target, token=installer_token)


def execute(args: argparse.Namespace) -> None:
    stable(args.tag, args.commit)
    installer_token = os.environ.pop("INSTALLER_PUBLISH_TOKEN", "")
    tap_token = os.environ.pop("HOMEBREW_TAP_TOKEN", "")
    phases = {
        "prepare": prepare_phase,
        "publish": publish_phase,
        "withdraw": withdraw_phase,
        "channels-rollback": channels_rollback_phase,
        "rollback": rollback_phase,
        "restore": restore_phase,
    }
    phases[args.phase](args, installer_token, tap_token)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--phase",
        choices=("prepare", "publish", "withdraw", "channels-rollback", "rollback", "restore"),
        required=True,
    )
    for name in ("tag", "commit", "run-id", "attempt"):
        parser.add_argument("--" + name, required=True)
    for name in ("work", "evidence"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--snapshot-bundle", type=Path)
    parser.add_argument("--source-run", default="")
    parser.add_argument("--source-attempt", default="")
    args = parser.parse_args()
    if args.phase in {"publish", "rollback"} and args.bundle is None:
        parser.error("the mutation phase requires a signed lifecycle bundle")
    if args.phase == "publish" and args.snapshot_bundle is None:
        parser.error("publication requires the signed rollback snapshot bundle")
    execute(args)


if __name__ == "__main__":
    main()
