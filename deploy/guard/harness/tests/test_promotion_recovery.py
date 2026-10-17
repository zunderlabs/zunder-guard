"""Rollback retries authenticate source ownership and never let one failed channel block another."""

import argparse
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from guard_harness import promotion, promotion_channels, promotion_recovery
from guard_harness.attestation import AttestationError, VerifiedPredicate
from guard_harness.native_release import Release
from guard_harness.publication import Publication
from guard_harness.release_state import predicate_digest
from guard_harness.runner import RunError

COMMIT = "a" * 40


def fixture_snapshot(root: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "2")
    (root / "channels.json").write_text('{"tap_before":"synthetic"}')
    (root / "transaction.json").write_text('{"canonical_before":null,"prior":null}')
    (root / "promoted.predicate.json").write_text('{"stage":"promoted"}')
    (root / "subject.sha256").write_text("b" * 64)
    for name in promotion_recovery.FILES:
        if name.startswith("candidate/"):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("synthetic authenticated candidate bytes")
    promotion_recovery.snapshot(root, tag="v1.0.0", commit=COMMIT, run_id="99", attempt="1")
    (root / "rollback-snapshot.sigstore.json").write_text("synthetic signed bundle")
    value: dict[str, Any] = json.loads((root / "rollback-snapshot.json").read_bytes())
    return value


def authenticate(root: Path) -> dict[str, Any]:
    return promotion_recovery.authenticate(
        root,
        tag="v1.0.0",
        commit=COMMIT,
        run_id="99",
        attempt="1",
        source_run="123",
        source_attempt="2",
    )


def test_recovery_uses_authenticated_original_invocation_and_immutable_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = fixture_snapshot(tmp_path, monkeypatch)
    (tmp_path / "channels.json").write_text('{"tap_after":"unsigned interrupted progress"}')

    def verify(subject: Path, bundle: Path, **kwargs: Any) -> VerifiedPredicate:
        assert subject.name == "rollback-snapshot.json"
        assert kwargs["workflow"] == "promote.yml" and kwargs["commit"] == COMMIT
        assert (kwargs["expected_run_id"], kwargs["expected_run_attempt"]) == ("123", "2")
        assert kwargs["predicate_type"] == promotion_recovery.PREDICATE
        return VerifiedPredicate(value, "promote.yml", COMMIT)

    monkeypatch.setattr(promotion_recovery, "verify_predicate", verify)
    assert authenticate(tmp_path) == {"canonical_before": None, "prior": None}


@pytest.mark.parametrize("target", [*promotion_recovery.FILES, "rollback-snapshot.json"])
def test_modified_original_snapshot_refuses_before_any_channel_or_http_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: str
) -> None:
    fixture_snapshot(tmp_path, monkeypatch)
    (tmp_path / target).write_text('{"modified":"synthetic"}')
    monkeypatch.setattr(
        promotion_recovery, "verify_predicate", lambda *a, **k: pytest.fail("changed bytes")
    )
    with pytest.raises(AttestationError, match="inputs differ"):
        authenticate(tmp_path)


def test_snapshot_from_another_run_or_attempt_cannot_be_relabelled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture_snapshot(tmp_path, monkeypatch)
    with pytest.raises(AttestationError, match="inputs differ"):
        promotion_recovery.authenticate(
            tmp_path,
            tag="v1.0.0",
            commit=COMMIT,
            run_id="99",
            attempt="1",
            source_run="123",
            source_attempt="3",
        )


def test_unverified_snapshot_bundle_cannot_authorize_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture_snapshot(tmp_path, monkeypatch)

    def refusal(*args: Any, **kwargs: Any) -> VerifiedPredicate:
        raise AttestationError("wrong authenticated source invocation")

    monkeypatch.setattr(promotion_recovery, "verify_predicate", refusal)
    with pytest.raises(AttestationError, match="source invocation"):
        authenticate(tmp_path)


def rollback_fixture(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[argparse.Namespace, list[str]]:
    candidate = {"stage": "promoted"}
    (root / "promoted.predicate.json").write_text(json.dumps(candidate))
    (root / "channels.snapshot.json").write_text("{}")
    bundle = root / "input.bundle"
    bundle.write_text("signed withdrawal fixture")
    args = argparse.Namespace(work=root, bundle=bundle)
    transaction = {"canonical_before": "b" * 64, "prior": {"digest": "b" * 64}}
    calls: list[str] = []
    monkeypatch.setattr(promotion, "admitted_snapshot", lambda args: transaction)
    monkeypatch.setattr(
        promotion, "admitted_prior", lambda *args: calls.append("authenticate-prior")
    )
    monkeypatch.setattr(
        promotion, "publication", lambda *a, **k: Publication(b"synthetic", "c" * 64)
    )
    monkeypatch.setattr(
        promotion, "read_head", lambda channel: (predicate_digest(candidate), candidate)
    )

    def attempted(snapshot: dict[str, Any]) -> list[str]:
        calls.append("channels")
        return ["tap"]

    monkeypatch.setattr(promotion, "channels", lambda *a: SimpleNamespace(rollback=attempted))
    return args, calls


def test_withdrawal_publish_failure_never_prevents_independent_channel_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args, calls = rollback_fixture(tmp_path, monkeypatch)

    def failed(*args: Any, **kwargs: Any) -> None:
        calls.append("withdrawal")
        raise AttestationError("capsule POST refused")

    monkeypatch.setattr(promotion, "publish_once", failed)
    monkeypatch.setattr(promotion, "restore", lambda *a, **k: pytest.fail("withdrawal unconfirmed"))
    with pytest.raises(AttestationError, match="incomplete"):
        promotion.rollback_phase(args, "synthetic", "synthetic")
    assert calls == ["authenticate-prior", "channels", "withdrawal"]
    assert json.loads((tmp_path / "rollback.json").read_bytes())["failed_channels"] == [
        "tap",
        "canonical-withdrawal",
    ]


def test_recovery_after_canonical_restore_still_reconciles_other_channels(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args, calls = rollback_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(promotion, "read_head", lambda channel: ("b" * 64, None))
    monkeypatch.setattr(promotion, "publish_once", lambda *a, **k: pytest.fail("already restored"))
    monkeypatch.setattr(promotion, "restore", lambda *a, **k: pytest.fail("already restored"))
    with pytest.raises(AttestationError, match="incomplete"):
        promotion.rollback_phase(args, "synthetic", "synthetic")
    assert calls == ["authenticate-prior", "channels"]
    assert json.loads((tmp_path / "rollback.json").read_bytes())["canonical_restored"] is True


def test_newer_canonical_head_refuses_all_rollback_mutations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args, calls = rollback_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(promotion, "read_head", lambda channel: ("d" * 64, None))
    with pytest.raises(AttestationError, match="outside this promotion"):
        promotion.rollback_phase(args, "synthetic", "synthetic")
    assert calls == ["authenticate-prior"]
    assert not (tmp_path / "rollback.json").exists()


def test_each_failed_channel_is_attempted_and_newer_github_latest_is_never_replaced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from guard_harness.homebrew_stage import Tap

    client = promotion_channels.Channels(
        Release("v1.0.0", COMMIT, tmp_path), None, tmp_path, Tap(token="fixture", logs=tmp_path)
    )
    calls: list[str] = []

    def failed_tap(*args: Any, **kwargs: Any) -> Any:
        calls.append("tap")
        raise AttestationError("tap unavailable")

    def failed_image(tag: str) -> str:
        calls.append("image")
        raise AttestationError("registry unavailable")

    def newest(method: str, endpoint: str, body: Any = None) -> dict[str, Any]:
        if method != "GET":
            pytest.fail("newer latest must remain")
        if endpoint == "releases/latest":
            calls.append("github")
            return {"id": 333}
        return {"id": 222, "tag_name": "v1.0.0"}

    client.tap = cast(Any, SimpleNamespace(request=failed_tap))
    monkeypatch.setattr(promotion_channels, "image_digest", failed_image)
    monkeypatch.setattr(
        promotion_channels, "public_get", lambda url: pytest.fail("authenticated latest only")
    )
    monkeypatch.setattr(client, "github", newest)
    failures = client.rollback(
        {
            "tap_before": "a" * 40,
            "image_before": None,
            "github_before": {"id": 111},
            "candidate_release_id": 222,
        }
    )
    assert calls == ["tap", "image", "github"]
    assert failures == ["tap", "image", "github-latest"]


def test_already_restored_owned_tap_and_image_are_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from guard_harness.homebrew_stage import Tap

    client = promotion_channels.Channels(
        Release("v1.0.0", COMMIT, tmp_path), None, tmp_path, Tap(token="fixture", logs=tmp_path)
    )
    before, promoted, reverted = "a" * 40, "b" * 40, "c" * 40
    old_tree, promoted_tree = "d" * 40, "e" * 40
    old_image = "sha256:" + "f" * 64
    release_build = {"distribution": {"docker": {"digest": "sha256:" + "1" * 64}}}
    client.release = cast(
        Any,
        SimpleNamespace(
            tag="v1.0.0",
            asset=lambda name: (
                json.dumps(release_build).encode()
                if name == "release-manifest.json"
                else b"formula"
            ),
        ),
    )

    def tap(method: str, endpoint: str, body: Any = None) -> dict[str, Any]:
        assert method == "GET"
        if endpoint == "git/ref/heads/main":
            return {"object": {"sha": reverted}}
        if endpoint == "git/commits/" + reverted:
            return {"parents": [{"sha": promoted}], "tree": {"sha": old_tree}}
        if endpoint == "git/commits/" + promoted:
            return {"parents": [{"sha": before}], "tree": {"sha": promoted_tree}}
        pytest.fail("unexpected tap mutation")

    client.tap = cast(Any, SimpleNamespace(request=tap))
    monkeypatch.setattr(client, "tap_tree", lambda *a: promoted_tree)
    monkeypatch.setattr(client, "tap_commit", lambda *a: pytest.fail("already restored tap"))
    monkeypatch.setattr(client, "image", lambda *a: pytest.fail("already restored image"))
    monkeypatch.setattr(promotion_channels, "image_digest", lambda tag: old_image)
    monkeypatch.setattr(promotion_channels, "public_get", lambda url: (b'{"id":111}', {}))
    mutations = []

    def github(method: str, endpoint: str, body: Any = None) -> dict[str, Any]:
        if method == "GET":
            return (
                {"id": 222, "tag_name": "v1.0.0"}
                if endpoint.endswith("222")
                else {"id": 111, "tag_name": "v0.9.0"}
            )
        mutations.append(endpoint)
        return {}

    monkeypatch.setattr(client, "github", github)
    assert (
        client.rollback(
            {
                "tap_before": before,
                "tap_tree_before": old_tree,
                "image_before": old_image,
                "github_before": {"id": 111, "tag_name": "v0.9.0"},
                "candidate_release_id": 222,
            }
        )
        == []
    )
    assert mutations == ["releases/222", "releases/111"]


def test_restore_cli_refuses_newer_canonical_and_repeated_restore_is_noop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args, calls = rollback_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(promotion, "restore", lambda *a, **k: pytest.fail("no CAS authorized"))
    monkeypatch.setattr(promotion, "read_head", lambda channel: ("d" * 64, None))
    with pytest.raises(AttestationError, match="outside the authenticated withdrawal"):
        promotion.restore_phase(args, "synthetic", "")
    monkeypatch.setattr(promotion, "read_head", lambda channel: ("b" * 64, None))
    promotion.restore_phase(args, "synthetic", "")


def test_automatic_failure_before_publication_has_no_rollback_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args = argparse.Namespace(work=tmp_path)
    monkeypatch.setattr(
        promotion, "admitted_snapshot", lambda args: {"canonical_before": "b" * 64, "prior": None}
    )
    monkeypatch.setattr(promotion, "admitted_prior", lambda *a: None)
    monkeypatch.setattr(promotion, "read_head", lambda channel: ("b" * 64, None))
    monkeypatch.setattr(
        promotion,
        "publication",
        lambda *a, **k: pytest.fail("no promoted bundle or mutation exists"),
    )
    output: dict[str, str] = {}
    monkeypatch.setattr(promotion, "outputs", output.update)
    promotion.withdraw_phase(args, "", "")
    assert output == {"rollback_needed": "false"}


def test_recovery_after_prior_restore_is_not_skipped_by_withdrawal_preparation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from test_promotion import complete

    from guard_harness.promotion_state import successor

    previous, build = complete()
    candidate = successor(previous, build, stage="promoted")
    (tmp_path / "candidate/assets").mkdir(parents=True)
    (tmp_path / "candidate/assets/release-manifest.json").write_text(json.dumps(build))
    (tmp_path / "promoted.sigstore.json").write_text("synthetic original signed bundle")
    args = argparse.Namespace(work=tmp_path)
    monkeypatch.setattr(
        promotion,
        "admitted_snapshot",
        lambda args: {"canonical_before": "b" * 64, "prior": {"digest": "b" * 64}},
    )
    monkeypatch.setattr(promotion, "admitted_prior", lambda *a: None)
    monkeypatch.setattr(promotion, "read_head", lambda channel: ("b" * 64, None))
    monkeypatch.setattr(
        promotion,
        "publication",
        lambda *a: Publication(json.dumps({"predicate": json.dumps(candidate)}).encode(), "a" * 64),
    )
    output: dict[str, str] = {}
    monkeypatch.setattr(promotion, "outputs", output.update)
    promotion.withdraw_phase(args, "", "")
    assert output == {"rollback_needed": "true"}
    state = json.loads((tmp_path / "withdrawn.predicate.json").read_bytes())
    assert state["stage"] == "withdrawn" and state["previous"] == predicate_digest(candidate)


class ReadOnlyTap:
    """The job's read token on the public tap; any write fails the test."""

    head = "a" * 40
    tokens: list[str] = []

    def __init__(self, *, token: str, logs: Path) -> None:
        if not token:
            raise ValueError("tap credential required")
        ReadOnlyTap.tokens.append(token)

    def request(self, method: str, endpoint: str, body: Any = None) -> dict[str, Any]:
        assert (method, endpoint) == ("GET", "git/ref/heads/main"), "tap mutation refused"
        return {"object": {"sha": ReadOnlyTap.head}}


@pytest.mark.parametrize(
    ("head", "token", "tap_failed"),
    [
        ("a" * 40, "job-read-token", False),  # never moved: nothing to restore
        ("b" * 40, "job-read-token", True),  # moved, and no credential to restore it
        ("a" * 40, "", True),  # the head cannot even be read
    ],
)
def test_missing_tap_token_never_blocks_other_channel_reconciliation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, head: str, token: str, tap_failed: bool
) -> None:
    (tmp_path / "transaction.json").write_text('{"canonical_before":null,"prior":null}')
    client = promotion.channels(argparse.Namespace(work=tmp_path, tag="v1.0.0", commit=COMMIT), "")
    attempts: list[str] = []
    ReadOnlyTap.head, ReadOnlyTap.tokens = head, []
    monkeypatch.setattr(promotion_channels, "Tap", ReadOnlyTap)
    if token:
        monkeypatch.setenv("GH_TOKEN", token)
    else:
        monkeypatch.delenv("GH_TOKEN", raising=False)

    def image(tag: str) -> None:
        attempts.append("image")
        return None

    def github(method: str, endpoint: str, body: Any = None) -> dict[str, Any]:
        if method != "GET":
            pytest.fail("foreign latest mutation")
        if endpoint == "releases/latest":
            attempts.append("github")
            return {"id": 333}
        return {"id": 222, "tag_name": "v1.0.0"}

    monkeypatch.setattr(promotion_channels, "image_digest", image)
    monkeypatch.setattr(promotion_channels, "public_get", lambda url: pytest.fail("cached read"))
    monkeypatch.setattr(client, "github", github)
    failures = client.rollback(
        {
            "tap_before": "a" * 40,
            "image_before": None,
            "github_before": None,
            "candidate_release_id": 222,
        }
    )
    assert failures == (["tap"] if tap_failed else []) + ["github-latest"]
    assert attempts == ["image", "github"]
    assert ReadOnlyTap.tokens == ([token] if token else [])


@pytest.mark.parametrize("outage_route", ["head", "withdrawal-bundle", "withdrawal-proof"])
def test_canonical_get_outage_does_not_block_signed_withdrawal_preparation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, outage_route: str
) -> None:
    from test_promotion import complete

    from guard_harness.promotion_state import successor

    previous, build = complete()
    candidate = successor(previous, build, stage="promoted")
    (tmp_path / "candidate/assets").mkdir(parents=True)
    (tmp_path / "candidate/assets/release-manifest.json").write_text(json.dumps(build))
    (tmp_path / "promoted.sigstore.json").write_text("synthetic original signed bundle")
    args = argparse.Namespace(work=tmp_path)
    calls: list[str] = []
    monkeypatch.setattr(
        promotion, "admitted_snapshot", lambda args: {"canonical_before": "b" * 64, "prior": None}
    )
    monkeypatch.setattr(promotion, "admitted_prior", lambda *a: calls.append("authenticate-prior"))

    def authenticated(*args: Any, **kwargs: Any) -> Publication:
        if kwargs.get("withdrawal"):
            calls.append("authenticate-live-withdrawal")
            raise RunError("live withdrawal verifier refused")
        calls.append("authenticate-original-c2")
        return Publication(json.dumps({"predicate": json.dumps(candidate)}).encode(), "a" * 64)

    def outage(channel: str) -> Any:
        calls.append("worker-get")
        if outage_route == "head":
            raise AttestationError("Worker GET unavailable")
        return "e" * 64, {"stage": "withdrawn", "previous": predicate_digest(candidate)}

    def bundle_outage(url: str) -> Any:
        if outage_route == "withdrawal-proof":
            return b"invalid live withdrawal bundle", {"x-zunder-state-sha256": "e" * 64}
        raise AttestationError("Worker withdrawal bundle GET unavailable")

    monkeypatch.setattr(promotion, "publication", authenticated)
    monkeypatch.setattr(promotion, "read_head", outage)
    monkeypatch.setattr(promotion, "public_get", bundle_outage)
    output: dict[str, str] = {}
    monkeypatch.setattr(promotion, "outputs", output.update)
    promotion.withdraw_phase(args, "", "")
    assert calls == ["authenticate-prior", "authenticate-original-c2", "worker-get"] + (
        ["authenticate-live-withdrawal"] if outage_route == "withdrawal-proof" else []
    )
    assert output == {"rollback_needed": "true"}
    state = json.loads((tmp_path / "withdrawn.predicate.json").read_bytes())
    assert state["stage"] == "withdrawn" and state["previous"] == predicate_digest(candidate)


def test_canonical_get_outage_records_failure_after_other_channels_are_attempted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args, calls = rollback_fixture(tmp_path, monkeypatch)

    def outage(channel: str) -> Any:
        raise AttestationError("Worker GET unavailable")

    monkeypatch.setattr(promotion, "read_head", outage)
    monkeypatch.setattr(
        promotion, "publish_once", lambda *a, **k: pytest.fail("unknown canonical CAS")
    )
    monkeypatch.setattr(promotion, "restore", lambda *a, **k: pytest.fail("unknown canonical CAS"))
    with pytest.raises(AttestationError, match="incomplete"):
        promotion.rollback_phase(args, "synthetic", "synthetic")
    assert calls == ["authenticate-prior", "channels"]
    result = json.loads((tmp_path / "rollback.json").read_bytes())
    assert result["failed_channels"] == ["tap", "canonical-read"]
    assert result["canonical_restored"] is False
    assert result["withdrawal_published"] is False


def test_unavailable_withdrawal_proof_does_not_block_other_owned_channels(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args, calls = rollback_fixture(tmp_path, monkeypatch)
    candidate = predicate_digest(json.loads((tmp_path / "promoted.predicate.json").read_bytes()))
    monkeypatch.setattr(
        promotion,
        "read_head",
        lambda channel: ("e" * 64, {"stage": "withdrawn", "previous": candidate}),
    )
    monkeypatch.setattr(
        promotion, "publish_once", lambda *a, **k: pytest.fail("unadmitted live withdrawal")
    )
    monkeypatch.setattr(
        promotion, "restore", lambda *a, **k: pytest.fail("unadmitted live withdrawal")
    )
    with pytest.raises(AttestationError, match="incomplete"):
        promotion.rollback_phase(args, "synthetic", "synthetic")
    assert calls == ["authenticate-prior", "channels"]
    result = json.loads((tmp_path / "rollback.json").read_bytes())
    assert result["failed_channels"] == ["tap", "canonical-withdrawal-proof"]
    assert result["canonical_restored"] is False


def test_invalid_canonical_token_is_recorded_without_losing_channel_outcomes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args, calls = rollback_fixture(tmp_path, monkeypatch)

    def invalid(*args: Any, **kwargs: Any) -> None:
        raise ValueError("canonical publication credential required")

    monkeypatch.setattr(promotion, "publish_once", invalid)
    with pytest.raises(AttestationError, match="incomplete"):
        promotion.rollback_phase(args, "", "synthetic")
    assert calls == ["authenticate-prior", "channels"]
    assert json.loads((tmp_path / "rollback.json").read_bytes())["failed_channels"] == [
        "tap",
        "canonical-withdrawal",
    ]


@pytest.mark.parametrize("unavailable", ["gate", "withdrawal-signing"])
def test_independent_recovery_finishes_before_gate_or_signing_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unavailable: str
) -> None:
    value = fixture_snapshot(tmp_path, monkeypatch)
    monkeypatch.setattr(
        promotion_recovery,
        "verify_predicate",
        lambda *a, **k: VerifiedPredicate(value, "promote.yml", COMMIT),
    )
    args = argparse.Namespace(
        work=tmp_path,
        tag="v1.0.0",
        commit=COMMIT,
        run_id="99",
        attempt="1",
        source_run="123",
        source_attempt="2",
    )
    calls: list[str] = []

    def rollback(captured: dict[str, Any]) -> list[str]:
        assert captured == {"tap_before": "synthetic"}
        calls.extend(["tap", "image", "github"])
        return []

    monkeypatch.setattr(promotion, "channels", lambda *a: SimpleNamespace(rollback=rollback))
    monkeypatch.setattr(
        promotion, "admitted_prior", lambda *a: pytest.fail("gate admission before channels")
    )
    monkeypatch.setattr(
        promotion,
        "publication",
        lambda *a, **k: pytest.fail("withdrawal admission before channels"),
    )
    monkeypatch.setattr(
        promotion, "read_head", lambda *a: pytest.fail("canonical GET before channels")
    )
    promotion.channels_rollback_phase(args, "", "synthetic scoped credential")
    # The next external operation may fail without undoing these independent outcomes.
    with pytest.raises(AttestationError, match=unavailable):
        raise AttestationError(unavailable + " unavailable")
    assert calls == ["tap", "image", "github"]
    assert json.loads((tmp_path / "channels-rollback.json").read_bytes()) == {
        "result": "passed",
        "failed_channels": [],
    }


def test_independent_recovery_refuses_modified_candidate_before_channel_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture_snapshot(tmp_path, monkeypatch)
    (tmp_path / "candidate/assets/zunder-guard.rb").write_text("foreign formula")
    monkeypatch.setattr(promotion, "channels", lambda *a: pytest.fail("modified candidate"))
    args = argparse.Namespace(
        work=tmp_path,
        tag="v1.0.0",
        commit=COMMIT,
        run_id="99",
        attempt="1",
        source_run="123",
        source_attempt="2",
    )
    with pytest.raises(AttestationError, match="inputs differ"):
        promotion.channels_rollback_phase(args, "", "")


def test_workflow_retains_pre_mutation_recovery_and_orders_independent_restores() -> None:
    guard = Path(__file__).resolve().parents[2]
    workflow = guard / "github/workflows/promote.yml"
    if not workflow.exists():
        workflow = guard.parents[1] / ".github/workflows/promote.yml"
    body = workflow.read_text()
    promote, rollback = body.split("  rollback:\n", 1)
    assert promote.index("promotion-recovery-${{") < promote.index("Mint a short-lived token")
    assert promote.index("promotion-recovery-${{") < promote.index("--phase publish")
    assert rollback.index("--phase channels-rollback") < rollback.index("--phase withdraw")
    assert rollback.index("--phase channels-rollback") < rollback.index("Sign withdrawal revision")
    assert rollback.index("--phase channels-rollback") < rollback.index("promotion-evidence\n")
    assert "promotion-late" in rollback and "Retain original promoted attestation only" in rollback
    assert "needs.promote.outputs.mutation_attempted != 'false'" in rollback
    assert "always() && steps.channels.outcome != 'success'" in rollback
    assert body.count("queue: max") == 3


def test_rerun_consumers_name_the_promote_jobs_own_attempt() -> None:
    """A failed-jobs rerun keeps a passed promote job's earlier attempt and its artifacts."""
    import yaml

    guard = Path(__file__).resolve().parents[2]
    workflow = guard / "github/workflows/promote.yml"
    if not workflow.exists():
        workflow = guard.parents[1] / ".github/workflows/promote.yml"
    jobs = yaml.safe_load(workflow.read_text())["jobs"]
    promote = jobs["promote"]
    assert promote["outputs"]["attempt"] == "${{ steps.attempt.outputs.attempt }}"
    recorded = [i for i, step in enumerate(promote["steps"]) if step.get("id") == "attempt"]
    assert recorded == [1]
    assert promote["steps"][1]["run"] == 'echo "attempt=$GITHUB_RUN_ATTEMPT" >> "$GITHUB_OUTPUT"'
    produced = {
        step["with"]["name"]
        for step in promote["steps"]
        if "upload-artifact" in step.get("uses", "")
    }
    assert produced == {
        prefix + "-${{ github.run_id }}-${{ github.run_attempt }}"
        for prefix in ("promotion-recovery", "canonical-subjects", "promotion-transaction")
    }

    def downloads(job: dict[str, Any]) -> list[str]:
        return [
            step["with"]["name"]
            for step in job["steps"]
            if "download-artifact" in step.get("uses", "") and "name" in step["with"]
        ]

    assert downloads(jobs["canonical-smoke"]) == [
        "canonical-subjects-${{ github.run_id }}-${{ needs.promote.outputs.attempt }}"
    ]
    rollback = jobs["rollback"]
    assert rollback["env"] == {
        "SOURCE_RUN": "${{ inputs.mode == 'rollback' && inputs.source_run || github.run_id }}",
        "SOURCE_ATTEMPT": "${{ inputs.mode == 'rollback' && inputs.source_attempt"
        " || needs.promote.outputs.attempt || github.run_attempt }}",
    }
    assert downloads(rollback) == [
        "promotion-recovery-${{ env.SOURCE_RUN }}-${{ env.SOURCE_ATTEMPT }}",
        "promotion-transaction-${{ env.SOURCE_RUN }}-${{ env.SOURCE_ATTEMPT }}",
    ]
    for step in rollback["steps"]:
        assert not {"SOURCE_RUN", "SOURCE_ATTEMPT"} & set(step.get("env", {}))
    bind = rollback["steps"][0]["run"]
    assert '[ "$SOURCE_ATTEMPT" = "$SOURCE_ATTEMPT_INPUT" ]' in bind
    assert '[ "$SOURCE_ATTEMPT" -le "$GITHUB_RUN_ATTEMPT" ]' in bind


@pytest.mark.parametrize("stale_reads, restored", [(2, True), (99, False)])
def test_rollback_rereads_a_cached_github_latest_before_judging_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stale_reads: int, restored: bool
) -> None:
    # The unauthenticated latest read can lag the restore PATCH by about a minute.
    (tmp_path / "transaction.json").write_text('{"canonical_before":null,"prior":null}')
    client = promotion.channels(argparse.Namespace(work=tmp_path, tag="v1.0.0", commit=COMMIT), "")
    reads = {"count": 0}
    pauses: list[float] = []

    def latest(url: str) -> tuple[bytes, dict[str, str]] | None:
        reads["count"] += 1
        # The pre-check is authenticated; after the PATCH the public cache keeps the
        # candidate for a while.
        return (b'{"id":222}', {}) if reads["count"] <= stale_reads else None

    def github(method: str, endpoint: str, body: object = None) -> dict[str, object]:
        return {"id": 222, "tag_name": "v1.0.0"} if method == "GET" else {}

    monkeypatch.setattr(promotion_channels, "image_digest", lambda tag: None)
    monkeypatch.setattr(promotion_channels, "public_get", latest)
    monkeypatch.setattr(client, "github", github)
    monkeypatch.setattr(client, "pause", pauses.append)
    failures = client.rollback(
        {
            "tap_before": "a" * 40,
            "image_before": None,
            "github_before": None,
            "candidate_release_id": 222,
        }
    )
    assert ("github-latest" in failures) is not restored
    if restored:
        assert pauses == [promotion_channels.LATEST_REREAD_PAUSE] * stale_reads
    else:
        assert len(pauses) == promotion_channels.LATEST_REREADS
