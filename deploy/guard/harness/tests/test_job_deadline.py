from datetime import UTC, datetime
from typing import Any

import pytest

from guard_harness.job_deadline import deadline


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
        now=datetime(2026, 10, 11, 2, 10, tzinfo=UTC),
        monotonic=100,
    )


def test_deadline_counts_setup_time_and_reserves_upload() -> None:
    assert deadline(**values()) == 2110  # 100 + 2700 - 90 - ten minutes setup.


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
