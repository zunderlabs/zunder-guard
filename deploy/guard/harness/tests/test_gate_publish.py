"""Gate publication authenticates the staged head with the same run binding as the gate."""

import json
from pathlib import Path
from typing import Any

import pytest

from guard_harness import gate_publish
from guard_harness.attestation import AttestationError
from guard_harness.publication import Publication
from guard_harness.state_verifier import VerifiedState

RUN = "123"


def setup(tmp_path: Path, staged_attempts: tuple[str, ...]) -> tuple[Path, Path, Path]:
    work, evidence = tmp_path / "work", tmp_path / "evidence"
    work.mkdir()
    evidence.mkdir()
    for attempt in staged_attempts:
        (evidence / f"state-chain-{RUN}-{attempt}").mkdir()
    bundle = tmp_path / "gated.bundle.json"
    bundle.write_text('{"dsseEnvelope":{},"verificationMaterial":{}}')
    return work, evidence, bundle


def stub(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    calls: dict[str, Any] = {}

    def state(*args: Any, **kwargs: Any) -> VerifiedState:
        calls["state"] = {
            key: kwargs.get(key)
            for key in ("expected_run_id", "expected_run_attempt", "latest_run_attempt")
        }
        return VerifiedState({"stage": "staged"}, "a" * 64)

    def prepare(*args: Any, **kwargs: Any) -> Publication:
        calls["prepare"] = (kwargs["expected_run_id"], kwargs["expected_run_attempt"])
        calls["journeys"] = kwargs["journeys"]
        return Publication(b"body", "b" * 64)

    def bundles(evidence: Path, *, run_id: str, attempt: str) -> dict[str, Any]:
        return {"run": run_id, "attempt": attempt}

    monkeypatch.setattr(gate_publish, "authenticate_state", state)
    monkeypatch.setattr(gate_publish, "prepare", prepare)
    monkeypatch.setattr(gate_publish, "bundles", bundles)
    monkeypatch.setattr(gate_publish, "publish", lambda publication, *, token: "c" * 64)
    monkeypatch.setenv("INSTALLER_PUBLISH_TOKEN", "synthetic-token")
    return calls


def test_staged_head_is_bound_to_this_run_and_its_selected_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Staging passed in attempt 1 and again in 2; the gate reran alone in attempt 3.
    work, evidence, bundle = setup(tmp_path, ("1", "2", "4"))
    calls = stub(monkeypatch)
    gate_publish.execute(
        work=work,
        evidence=evidence,
        bundle=bundle,
        tag="v1.0.0",
        commit="a" * 40,
        run_id=RUN,
        attempt="3",
    )
    assert calls["state"] == {
        "expected_run_id": RUN,
        "expected_run_attempt": "2",
        "latest_run_attempt": None,
    }
    assert calls["prepare"] == (RUN, "3")
    assert calls["journeys"] == {"run": RUN, "attempt": "3"}
    receipt = json.loads((work / "gate-publication.json").read_text())
    assert receipt["state_sha256"] == "c" * 64 and receipt["stage"] == "gated"


@pytest.mark.parametrize("staged", [(), ("4",)])
def test_publication_refuses_without_a_staged_chain_at_or_before_the_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, staged: tuple[str, ...]
) -> None:
    work, evidence, bundle = setup(tmp_path, staged)
    calls = stub(monkeypatch)
    with pytest.raises(AttestationError, match="no artifact of this run"):
        gate_publish.execute(
            work=work,
            evidence=evidence,
            bundle=bundle,
            tag="v1.0.0",
            commit="a" * 40,
            run_id=RUN,
            attempt="3",
        )
    assert "state" not in calls and "prepare" not in calls


def test_publication_refuses_a_staged_chain_of_another_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    work, evidence, bundle = setup(tmp_path, ("1",))
    (evidence / "state-chain-124-1").mkdir()
    calls = stub(monkeypatch)
    with pytest.raises(AttestationError, match="another workflow run"):
        gate_publish.execute(
            work=work,
            evidence=evidence,
            bundle=bundle,
            tag="v1.0.0",
            commit="a" * 40,
            run_id=RUN,
            attempt="3",
        )
    assert "state" not in calls
