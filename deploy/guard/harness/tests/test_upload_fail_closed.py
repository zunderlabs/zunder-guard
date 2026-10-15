"""Evidence uploads fail closed, so a passing job never leaves an older attempt selected.

The gate and its consumers select each producer's latest attempt of the run by artifact
name. A job that passes but uploads nothing under `if-no-files-found: warn` would leave a
superseded attempt's artifact to be selected. Only diagnostics that legitimately may be
empty, and that no gate, admission or promotion step reads, may warn.
"""

from pathlib import Path
from typing import Any

import yaml

RUN = "-${{ github.run_id }}-${{ github.run_attempt }}"
# Each may be empty because its job failed before writing anything; none is read as evidence.
DIAGNOSTIC = {
    # Staging's verifier diagnostics; the gate reads state-chain, which fails closed.
    ("verify.yml", "staged-state" + RUN),
    # Failure-only snapshots before the cleanup scan; outside the T1/T2 row namespace.
    ("journey.yml", "T1-early-failure" + RUN),
    ("journey.yml", "T2-early-failure" + RUN),
    # Diagnostic-only jobs that earn no gate credit.
    ("journey.yml", "checkout-diagnostic-${{ matrix.journey }}" + RUN),
    ("journey.yml", "payment-diagnostic-${{ inputs.payment_network }}" + RUN),
    ("install-matrix.yml", "T1-diagnostic-early" + RUN),
    ("install-matrix.yml", "T1-diagnostic-final" + RUN),
    ("install-matrix.yml", "T2-diagnostic-early" + RUN),
    ("install-matrix.yml", "T2-diagnostic-final" + RUN),
    ("install-matrix.yml", "operator-recovery-diagnostic-only"),
    # Partial-failure retention; rollback reads it optionally and never as a baseline.
    ("promote.yml", "promotion-transaction" + RUN),
    # Canonical smoke and rollback outcomes, retained for people, read by no later job.
    (
        "promote.yml",
        "canonical-${{ matrix.channel }}-${{ matrix.runner }}-${{ matrix.shell }}" + RUN,
    ),
    ("promote.yml", "rollback" + RUN),
}


def workflows() -> Path:
    guard = Path(__file__).resolve().parents[2]
    private = guard / "github/workflows"
    return private if private.is_dir() else guard.parents[1] / ".github/workflows"


def uploads(name: str) -> list[dict[str, Any]]:
    document = yaml.safe_load((workflows() / name).read_text())
    return [
        step["with"]
        for job in document["jobs"].values()
        for step in job.get("steps", [])
        if "actions/upload-artifact@" in step.get("uses", "")
    ]


def test_every_evidence_upload_fails_closed_and_only_listed_diagnostics_warn() -> None:
    seen: set[tuple[str, str]] = set()
    for name in ("verify.yml", "journey.yml", "install-matrix.yml", "promote.yml"):
        for upload in uploads(name):
            key = (name, upload["name"])
            # The action's default is warn, so the choice must be explicit.
            expected = "warn" if key in DIAGNOSTIC else "error"
            assert upload.get("if-no-files-found") == expected, key
            seen.add(key)
    assert DIAGNOSTIC <= seen


def test_gate_rows_and_their_signed_inputs_are_among_the_fail_closed_uploads() -> None:
    names = {upload["name"] for upload in uploads("journey.yml")}
    names |= {upload["name"] for upload in uploads("install-matrix.yml")}
    for row in ("P8", "T1", "T2", "M3", "I7", "signing-${{ matrix.platform }}"):
        assert row + RUN in names
    assert "${{ matrix.journey }}" + RUN in names
    assert "${{ matrix.row }}" + RUN in names
