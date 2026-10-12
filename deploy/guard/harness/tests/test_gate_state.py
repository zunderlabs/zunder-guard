import json
from pathlib import Path

import pytest
from test_staged_state import COMMIT, build_bytes

from guard_harness import gate_state, staged_state
from guard_harness.attestation import AttestationError
from guard_harness.journey_evidence import JOURNEY_COVERAGE
from guard_harness.release_state import GATE_JOURNEYS


def test_gate_requires_complete_set_and_links_exact_staged_predecessor() -> None:
    raw = build_bytes("v1.0.0-rc.4")
    previous = staged_state.genesis(raw, commit=COMMIT, issued_at="2026-10-11T04:00:00Z")
    references = {
        row: "https://github.com/zunderlabs/zunder-guard/actions/runs/1" for row in GATE_JOURNEYS
    }
    state = gate_state.successor(
        previous, json.loads(raw), references, coverage=dict(JOURNEY_COVERAGE)
    )
    assert state["stage"] == "gated" and state["revision"] == 2
    assert state["previous"] is not None and state["evidence"] == references
    assert all(channel["status"] == "verified" for channel in state["channels"].values())
    del references["P8"]
    with pytest.raises(ValueError):
        gate_state.successor(previous, json.loads(raw), references, coverage=dict(JOURNEY_COVERAGE))


@pytest.mark.parametrize(
    "row,token", [("I3", "D1:curl-pipe"), ("I4", "D2:irm-iex"), ("I1", "D5:manual-archive")]
)
def test_channel_status_cannot_be_derived_from_install_row_alone(row: str, token: str) -> None:
    raw = build_bytes("v1.0.0-rc.4")
    previous = staged_state.genesis(raw, commit=COMMIT, issued_at="2026-10-11T04:00:00Z")
    references = {
        row: "https://github.com/zunderlabs/zunder-guard/actions/runs/1/attempts/1"
        for row in GATE_JOURNEYS
    }
    coverage = dict(JOURNEY_COVERAGE)
    coverage[row] = coverage[row] - {token}
    with pytest.raises(AttestationError, match="documented execution"):
        gate_state.successor(previous, json.loads(raw), references, coverage=coverage)


@pytest.mark.parametrize("missing,duplicate", [(False, False), (True, False), (False, True)])
def test_bundles_cannot_admit_missing_or_ambiguous_row(
    tmp_path: Path, missing: bool, duplicate: bool
) -> None:
    for row in GATE_JOURNEYS:
        directory = tmp_path / f"{row}-123-2"
        directory.mkdir()
        if not missing or row != "P8":
            (directory / "bundle.json").write_text(
                json.dumps({"dsseEnvelope": {}, "verificationMaterial": {}})
            )
        if duplicate and row == "P8":
            (directory / "other.json").write_text(
                json.dumps({"dsseEnvelope": {"other": True}, "verificationMaterial": {}})
            )
    if missing or duplicate:
        with pytest.raises(AttestationError):
            gate_state.bundles(tmp_path, run_id="123", attempt="2")
    else:
        assert set(gate_state.bundles(tmp_path, run_id="123", attempt="2")) == GATE_JOURNEYS
    with pytest.raises(AttestationError):
        gate_state.bundles(tmp_path, run_id="124", attempt="2")
