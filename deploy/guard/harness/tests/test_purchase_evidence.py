import pytest

from guard_harness.attestation import AttestationError
from guard_harness.purchase_coverage import TITLES
from guard_harness.purchase_evidence import measured


@pytest.mark.parametrize("row", list(TITLES))
def test_exact_executed_purchase_scenarios(row: str) -> None:
    proof = {
        "status": "passed",
        "tests": [{"title": title, "status": "passed"} for title in TITLES[row]],
    }
    assert measured(row, proof) == sorted(TITLES[row])


@pytest.mark.parametrize("mutation", ["empty", "skip", "missing", "extra", "duplicate", "failed"])
def test_exit_zero_cannot_replace_complete_p5_execution(mutation: str) -> None:
    tests = [{"title": title, "status": "passed"} for title in sorted(TITLES["P5"])]
    status = "passed"
    if mutation == "empty":
        tests = []
    elif mutation == "skip":
        tests[0]["status"] = "skipped"
    elif mutation == "missing":
        tests.pop()
    elif mutation == "extra":
        tests.append({"title": "unrelated successful test", "status": "passed"})
    elif mutation == "duplicate":
        tests.append(tests[0])
    else:
        status = "failed"
    with pytest.raises(AttestationError):
        measured("P5", {"status": status, "tests": tests})
