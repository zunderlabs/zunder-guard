import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from guard_harness.job_deadline import (
    LISTING_LOOKUPS,
    LISTING_WAIT_SECONDS,
    JobNotListed,
    deadline,
    settled_deadline,
)
from guard_harness.testnet_process import ENTRY_REMAINING
from guard_harness.testnet_scan import SCAN_TIMEOUT


def values() -> dict[str, Any]:
    return dict(
        pages=[
            {
                "jobs": [
                    {
                        "runner_name": "worker",
                        "status": "in_progress",
                        "run_id": 1,
                        "run_attempt": 2,
                        "head_sha": "a" * 40,
                        "started_at": "2026-10-11T02:00:00Z",
                    }
                ]
            }
        ],
        runner="worker",
        run=1,
        attempt=2,
        commit="a" * 40,
        now=datetime(2026, 10, 11, 2, 2, tzinfo=UTC),
        monotonic=100,
    )


def test_deadline_counts_setup_time_and_reserves_upload() -> None:
    assert deadline(**values()) == 100 + 7200 - SCAN_TIMEOUT - 90 - 120


def test_setup_boundary_keeps_work_and_both_independent_scans_reserved() -> None:
    args = values()
    setup_budget = 7200 - (SCAN_TIMEOUT + 90) - SCAN_TIMEOUT - ENTRY_REMAINING
    started = datetime(2026, 10, 11, 2, 0, tzinfo=UTC)
    args["now"] = started + timedelta(seconds=setup_budget - 1)
    assert deadline(**args) - args["monotonic"] == SCAN_TIMEOUT + ENTRY_REMAINING + 1
    for elapsed in (setup_budget, 600):
        args["now"] = started + timedelta(seconds=elapsed)
        with pytest.raises(ValueError, match="cleanup budget unavailable"):
            deadline(**args)


@pytest.mark.parametrize("change", ["runner", "attempt", "commit", "duplicate", "future", "late"])
def test_unbound_or_expired_jobs_refuse(change: str) -> None:
    args = values()
    if change == "duplicate":
        args["pages"][0]["jobs"] *= 2
    elif change == "future":
        args["now"] = datetime(2026, 10, 11, 1, 59, tzinfo=UTC)
    elif change == "late":
        args["now"] = datetime(2026, 10, 11, 2, 24, tzinfo=UTC)
    else:
        args[change] = 9 if change == "attempt" else "different"
    with pytest.raises(ValueError):
        deadline(**args)


class Listing:
    """A jobs listing that GitHub fills in late, with a fake clock and sleep."""

    def __init__(self, path: Path, answers: list[list[dict[str, Any]]]) -> None:
        self.path, self.answers, self.refreshes, self.slept = path, answers, 0, 0.0
        path.write_text(json.dumps(answers[0]))

    def refresh(self) -> None:
        self.refreshes += 1
        self.path.write_text(json.dumps(self.answers[min(self.refreshes, len(self.answers) - 1)]))

    def sleep(self, seconds: float) -> None:
        self.slept += seconds

    def now(self) -> datetime:
        return datetime(2026, 10, 11, 2, 2, tzinfo=UTC) + timedelta(seconds=self.slept)

    def settle(self) -> float:
        args = values()
        return settled_deadline(
            self.path,
            self.refresh,
            runner=args["runner"],
            run=args["run"],
            attempt=args["attempt"],
            commit=args["commit"],
            job_timeout=7200,
            clock=self.now,
            monotonic=lambda: 100 + self.slept,
            sleep=self.sleep,
        )


def not_yet_listed() -> list[dict[str, Any]]:
    pages: list[dict[str, Any]] = values()["pages"]
    pages[0]["jobs"][0].update(status="queued", runner_name=None)
    return pages


def test_late_listing_is_read_again_and_the_deadline_never_grows(tmp_path: Path) -> None:
    # Diagnostic 38454029938 refused 24 s after its job started, before any custody:
    # the listing did not show the runner's in-progress job yet.
    listing = Listing(
        tmp_path / "jobs.json", [not_yet_listed(), not_yet_listed(), values()["pages"]]
    )
    assert listing.settle() == deadline(**values())  # The same absolute monotonic deadline.
    assert listing.refreshes == 2 and listing.slept == 2 * LISTING_WAIT_SECONDS


def test_listing_that_never_shows_the_job_refuses_after_bounded_lookups(tmp_path: Path) -> None:
    listing = Listing(tmp_path / "jobs.json", [not_yet_listed()])
    with pytest.raises(JobNotListed, match="unique current runner job required"):
        listing.settle()
    assert listing.refreshes == LISTING_LOOKUPS - 1
    assert listing.slept == (LISTING_LOOKUPS - 1) * LISTING_WAIT_SECONDS


@pytest.mark.parametrize("change", ["duplicate", "attempt", "commit", "late"])
def test_listed_but_unbound_or_expired_jobs_refuse_without_reading_again(
    tmp_path: Path, change: str
) -> None:
    pages: list[dict[str, Any]] = values()["pages"]
    job = pages[0]["jobs"][0]
    if change == "duplicate":
        pages[0]["jobs"] *= 2
    elif change == "attempt":
        job["run_attempt"] = 9
    elif change == "commit":
        job["head_sha"] = "b" * 40
    else:
        job["started_at"] = "2026-10-11T00:00:00Z"
    listing = Listing(tmp_path / "jobs.json", [pages, values()["pages"]])
    with pytest.raises(ValueError) as refused:
        listing.settle()
    assert type(refused.value) is ValueError
    assert listing.refreshes == 0 and listing.slept == 0


def test_lookups_stay_inside_one_minute() -> None:
    assert (LISTING_LOOKUPS - 1) * LISTING_WAIT_SECONDS <= 60
