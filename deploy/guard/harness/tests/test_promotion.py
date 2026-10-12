import hashlib
import json
import urllib.request
from pathlib import Path
from typing import Any

import pytest
from test_staged_state import COMMIT, build_bytes

from guard_harness import gate_state, promotion, promotion_channels, promotion_state, staged_state
from guard_harness.attestation import AttestationError
from guard_harness.journey_evidence import JOURNEY_COVERAGE
from guard_harness.release_state import GATE_JOURNEYS, predicate_digest
from guard_harness.state_verifier import VerifiedState


def complete(tag: str = "v1.0.0") -> tuple[VerifiedState, dict[str, Any]]:
    raw = build_bytes(tag)
    build = json.loads(raw)
    genesis = staged_state.genesis(raw, commit=COMMIT, issued_at="2026-10-11T04:00:00Z")
    gated = gate_state.successor(
        genesis,
        build,
        {
            row: "https://github.com/zunderlabs/zunder-guard/actions/runs/1/attempts/1"
            for row in GATE_JOURNEYS
        },
        coverage=dict(JOURNEY_COVERAGE),
    )
    return VerifiedState(gated, hashlib.sha256(raw).hexdigest()), build


def test_promotion_is_revision_three_and_preserves_all_admitted_evidence() -> None:
    previous, build = complete()
    result = promotion_state.successor(previous, build, stage="promoted")
    assert result["revision"] == 3 and result["stage"] == "promoted"
    assert result["previous"] == predicate_digest(previous.predicate)
    assert result["evidence"] == previous.predicate["evidence"]
    assert all(channel["status"] == "verified" for channel in result["channels"].values())


def test_withdrawal_does_not_rewrite_assets_or_rewind_lifecycle() -> None:
    previous, build = complete()
    admitted = promotion_state.successor(previous, build, stage="promoted")
    current = VerifiedState(admitted, previous.manifest_sha256)
    result = promotion_state.successor(current, build, stage="withdrawn")
    assert result["revision"] == 4 and result["previous"] == predicate_digest(admitted)
    assert result["evidence"] == admitted["evidence"]
    assert all(channel["status"] == "unavailable" for channel in result["channels"].values())
    assert all(channel["status"] == "verified" for channel in admitted["channels"].values())


@pytest.mark.parametrize("tag", ["v1.0.0-rc.1", "v1.0.0-rc.5", "latest", "main"])
def test_candidates_and_mutable_names_never_admit_promotion(tag: str) -> None:
    with pytest.raises(AttestationError, match="stable"):
        promotion_state.stable(tag, COMMIT)


def test_missing_single_gate_row_prevents_promotion() -> None:
    previous, build = complete()
    del previous.predicate["evidence"]["M2"]
    with pytest.raises(ValueError):
        promotion_state.successor(previous, build, stage="promoted")


def test_promotion_cannot_skip_staging_or_repeat_promoted_revision() -> None:
    previous, build = complete()
    previous.predicate["stage"] = "staged"
    with pytest.raises(AttestationError, match="gated revision"):
        promotion_state.successor(previous, build, stage="promoted")


def test_attestation_capture_refuses_overlarge_or_symlink_inputs(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    bundle.write_bytes(b"x" * (2 * 1024 * 1024 + 1))
    with pytest.raises(AttestationError, match="size"):
        promotion_state.capture(bundle, tmp_path / "result")
    link = tmp_path / "link"
    link.symlink_to(bundle)
    with pytest.raises(AttestationError, match="regular"):
        promotion_state.capture(link, tmp_path / "result")
    assert not (tmp_path / "result").exists()


def test_restore_refuses_null_and_unauthenticated_targets_before_http() -> None:
    with pytest.raises(AttestationError, match="captured"):
        promotion.restore("a" * 64, "", token="fixture")


def test_unknown_outcome_never_retries_restore(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    class Opener:
        def open(self, request: Any, **kwargs: Any) -> None:
            calls.append(request.full_url)
            assert request.get_header("User-agent") == "zunder-guard-release/1.0"
            raise OSError("fixture uncertainty")

    monkeypatch.setattr(urllib.request, "build_opener", lambda *args: Opener())
    monkeypatch.setattr(promotion, "read_head", lambda channel: ("c" * 64, None))
    with pytest.raises(AttestationError, match="unknown"):
        promotion.restore("a" * 64, "b" * 64, token="synthetic-token")
    assert calls == ["https://zunderlabs.com/guard/restore"]


def test_empty_prior_is_absence_and_never_constructs_fake_release(tmp_path: Path) -> None:
    assert promotion.prior(tmp_path, None, None) is None
    assert promotion.prior(tmp_path, "a" * 64, {"stage": "withdrawn"}) is None


class FakeTap:
    def request(self, method: str, endpoint: str, body: Any = None) -> dict[str, Any]:
        if endpoint == "git/ref/heads/main":
            return {"object": {"sha": "a" * 40}}
        if endpoint == "git/commits/" + "a" * 40:
            return {"tree": {"sha": "b" * 40}}
        raise AssertionError("unexpected tap mutation")


def test_channel_snapshot_does_not_infer_absence_from_failed_registry_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from guard_harness.homebrew_stage import Tap
    from guard_harness.native_release import Release

    client = promotion_channels.Channels(
        Release("v1.0.0", COMMIT, tmp_path), None, tmp_path, Tap(token="fixture", logs=tmp_path)
    )
    monkeypatch.setattr(client, "tap", FakeTap())

    def failed(tag: str) -> str:
        raise AttestationError("registry unavailable")

    monkeypatch.setattr(promotion_channels, "image_digest", failed)
    with pytest.raises(AttestationError, match="registry unavailable"):
        client.snapshot()
    assert not (tmp_path / "channels.json").exists()


def test_uncertain_publication_reads_once_without_repeating_post(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from guard_harness.publication import Publication

    proposal = Publication(b'{"channel":"canonical"}', "a" * 64)
    calls: list[str] = []

    def uncertain(value: Publication, *, token: str) -> None:
        calls.append("post")
        raise AttestationError("response lost")

    def reconciled(channel: str) -> tuple[str, None]:
        calls.append(channel)
        return "a" * 64, None

    monkeypatch.setattr(promotion, "publish", uncertain)
    monkeypatch.setattr(promotion, "read_head", reconciled)
    promotion.publish_once(proposal, token="fixture")
    assert calls == ["post", "canonical"]


def test_uncertain_publication_never_accepts_a_different_head(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from guard_harness.publication import Publication

    proposal = Publication(b'{"channel":"canonical"}', "a" * 64)

    def refused(value: Publication, *, token: str) -> None:
        raise AttestationError("response lost")

    monkeypatch.setattr(promotion, "publish", refused)
    monkeypatch.setattr(promotion, "read_head", lambda channel: ("b" * 64, None))
    with pytest.raises(AttestationError, match="response lost"):
        promotion.publish_once(proposal, token="fixture")
