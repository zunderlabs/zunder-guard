"""Exercise actual job admission expressions, including GitHub's implicit status guard."""

import itertools
import re
from pathlib import Path

import pytest

RESULTS = ("success", "failure", "cancelled", "skipped")
GUARD = Path(__file__).resolve().parents[2]
PRIVATE = GUARD / "github/workflows/verify.yml"
WORKFLOW = PRIVATE if PRIVATE.exists() else GUARD.parents[1] / ".github/workflows/verify.yml"


def condition(job: str) -> str:
    source = WORKFLOW.read_text()
    body = re.search(rf"^  {re.escape(job)}:\n(.*?)(?=^  [a-z][a-z-]*:|\Z)", source, re.M | re.S)
    assert body is not None
    match = re.search(r"^    if: \$\{\{ (.+) \}\}$", body[1], re.M)
    assert match is not None, f"{job} requires explicit dependency admission"
    return match[1]


def admitted(
    job: str, needs: dict[str, str], *, rc: bool, cancelled: bool, ancestors: tuple[str, ...] = ()
) -> bool:
    expression = condition(job)
    # GitHub inserts success() unless a status function appears explicitly. That
    # default includes ancestors: the intentionally skipped stable template used to
    # suppress the RC children even though their direct staging dependency succeeded.
    if not re.search(r"\b(?:success|failure|cancelled|always)\(\)", expression):
        if any(result != "success" for result in (*needs.values(), *ancestors)):
            return False
    expression = expression.replace("cancelled()", str(cancelled)).replace("always()", "True")
    expression = expression.replace("contains(inputs.tag, '-rc.')", str(rc))
    for name, result in needs.items():
        assert result in RESULTS
        expression = expression.replace(f"needs.{name}.result", repr(result))
    expression = expression.replace("&&", " and ").replace("||", " or ").replace("!", " not ")
    # Only boolean constants/operators and the four fixed status literals may remain;
    # this test evaluator cannot invoke code from workflow shell steps or the host.
    remainder = re.sub(r"'(?:(?:success)|(?:failure)|(?:cancelled)|(?:skipped))'", "", expression)
    remainder = re.sub(r"\b(?:True|False|and|or|not)\b", "", remainder)
    assert re.fullmatch(r"[\s()=]*", remainder), "unsupported dependency expression"
    result = eval(expression.strip(), {"__builtins__": {}}, {})
    assert type(result) is bool
    return result


@pytest.mark.parametrize(
    "rc,cancelled,result", itertools.product((False, True), (False, True), RESULTS)
)
def test_staging_accepts_template_skip_only_for_uncancelled_rc(
    rc: bool, cancelled: bool, result: str
) -> None:
    expected = not cancelled and (result == "success" or (rc and result == "skipped"))
    assert admitted("staging", {"stable-template": result}, rc=rc, cancelled=cancelled) == expected


@pytest.mark.parametrize("cancelled,result", itertools.product((False, True), RESULTS))
def test_rc_journeys_run_after_successful_staging_despite_intentionally_skipped_ancestor(
    cancelled: bool, result: str
) -> None:
    assert admitted(
        "journeys", {"staging": result}, rc=True, cancelled=cancelled, ancestors=("skipped",)
    ) == (not cancelled and result == "success")


@pytest.mark.parametrize("rc,cancelled", itertools.product((False, True), (False, True)))
@pytest.mark.parametrize("staging,journeys", itertools.product(RESULTS, repeat=2))
def test_readers_require_successful_staging_and_completed_journeys(
    rc: bool, cancelled: bool, staging: str, journeys: str
) -> None:
    # An intentionally skipped RC-only stable ancestor must not suppress readers,
    # while a failed/cancelled/skipped trader result must never release them.
    assert admitted(
        "install-matrix",
        {"staging": staging, "journeys": journeys},
        rc=rc,
        cancelled=cancelled,
        ancestors=("skipped" if rc else "success",),
    ) == (not cancelled and staging == "success" and journeys == "success")


def test_journeys_remain_independent_of_install_matrix() -> None:
    body = re.search(
        r"^  journeys:\n(.*?)(?=^  [a-z][a-z-]*:|\Z)", WORKFLOW.read_text(), re.M | re.S
    )
    assert body is not None
    assert re.search(r"^    needs: staging$", body[1], re.M)
    assert "needs.install-matrix" not in condition("journeys")


@pytest.mark.parametrize("cancelled", (False, True))
@pytest.mark.parametrize("results", itertools.product(RESULTS, repeat=3))
def test_gate_requires_every_direct_success_and_refuses_cancellation(
    cancelled: bool, results: tuple[str, ...]
) -> None:
    needs = dict(zip(("staging", "install-matrix", "journeys"), results, strict=True))
    assert admitted("gate", needs, rc=True, cancelled=cancelled, ancestors=("skipped",)) == (
        not cancelled and all(result == "success" for result in results)
    )


@pytest.mark.parametrize(
    "rc,cancelled,result", itertools.product((False, True), (False, True), RESULTS)
)
def test_only_successful_uncancelled_stable_gate_can_promote(
    rc: bool, cancelled: bool, result: str
) -> None:
    assert admitted("promote", {"gate": result}, rc=rc, cancelled=cancelled) == (
        not rc and not cancelled and result == "success"
    )


@pytest.mark.parametrize("rc,cancelled", itertools.product((False, True), (False, True)))
def test_template_publication_only_runs_for_uncancelled_stable(rc: bool, cancelled: bool) -> None:
    assert admitted("stable-template", {}, rc=rc, cancelled=cancelled) == (not rc and not cancelled)


def completion_script() -> str:
    source = WORKFLOW.read_text()
    body = source.split("  completion:\n", 1)[1]
    assert (
        "    needs: [stable-template, staging, install-matrix, journeys, gate, promote]\n" in body
    )
    assert "    timeout-minutes: 5\n" in body and "    permissions: {}\n" in body
    assert "        shell: python\n" in body
    assert "          RESULTS: ${{ toJSON(needs) }}\n" in body
    assert "uses:" not in body and "secrets." not in body
    return "\n".join(
        line.removeprefix("          ")
        for line in body.split("        run: |\n", 1)[1].splitlines()
    )


def completion(rc: bool, results: dict[str, dict[str, str]], *, optimized: bool = False) -> bool:
    import json
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, *(["-O"] if optimized else []), "-c", completion_script()],
        env={"TAG": "v1.0.0-rc.8" if rc else "v1.0.0", "RESULTS": json.dumps(results)},
        capture_output=True,
        timeout=5,
        check=False,
    )
    return result.returncode == 0


def completed_results(rc: bool) -> dict[str, dict[str, str]]:
    return {
        name: {"result": "skipped" if rc and name in {"stable-template", "promote"} else "success"}
        for name in ("stable-template", "staging", "install-matrix", "journeys", "gate", "promote")
    }


@pytest.mark.parametrize("rc", (False, True))
def test_optimized_actual_completion_script_preserves_release_admission(rc: bool) -> None:
    results = completed_results(rc)
    assert completion(rc, results, optimized=True)
    results["gate"] = {"result": "skipped"}
    assert not completion(rc, results, optimized=True)


@pytest.mark.parametrize("rc", (False, True))
def test_actual_completion_step_accepts_only_complete_expected_release_outcome(rc: bool) -> None:
    assert admitted("completion", {}, rc=rc, cancelled=True, ancestors=("skipped",))
    assert completion(rc, completed_results(rc))
    assert not completion(rc, dict.fromkeys(completed_results(rc), {"result": "skipped"}))


@pytest.mark.parametrize("rc", (False, True))
@pytest.mark.parametrize(
    "job", ("stable-template", "staging", "install-matrix", "journeys", "gate", "promote")
)
@pytest.mark.parametrize("state", RESULTS)
def test_actual_completion_step_refuses_every_wrong_job_result(
    rc: bool, job: str, state: str
) -> None:
    results = completed_results(rc)
    expected_state = results[job]["result"]
    results[job] = {"result": state}
    assert completion(rc, results) == (state == expected_state)


@pytest.mark.parametrize("rc", (False, True))
@pytest.mark.parametrize(
    "mutation", ("missing-job", "extra-job", "missing-result", "unknown-result")
)
def test_actual_completion_step_refuses_incomplete_or_ambiguous_results(
    rc: bool, mutation: str
) -> None:
    results = completed_results(rc)
    if mutation == "missing-job":
        del results["gate"]
    elif mutation == "extra-job":
        results["unexpected"] = {"result": "success"}
    elif mutation == "missing-result":
        results["gate"] = {}
    else:
        results["gate"] = {"result": "unknown"}
    assert not completion(rc, results)


@pytest.mark.parametrize("rc,cancelled", itertools.product((False, True), (False, True)))
@pytest.mark.parametrize("staging,journeys,installs", itertools.product(RESULTS, repeat=3))
def test_wallet_restore_waits_for_every_trading_and_install_row(
    rc: bool, cancelled: bool, staging: str, journeys: str, installs: str
) -> None:
    # W18: the merchant's transfers start only once journeys (P8, T1, T2, purchases) and the
    # install rows have finished. A failed journey may have paid, so it still restores; a
    # cancelled dependency or run is left for a person to reconcile.
    assert admitted(
        "wallet-restore",
        {"staging": staging, "journeys": journeys, "install-matrix": installs},
        rc=rc,
        cancelled=cancelled,
        ancestors=("skipped" if rc else "success",),
    ) == (
        not cancelled
        and staging == "success"
        and journeys in {"success", "failure"}
        and installs in {"success", "failure", "skipped"}
    )
