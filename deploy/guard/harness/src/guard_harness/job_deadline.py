"""Reserve journey cleanup against the actual current GitHub job's recorded start."""

import json
import math
import os
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def deadline(
    pages: list[dict[str, Any]],
    *,
    runner: str,
    run: int,
    attempt: int,
    commit: str,
    now: datetime,
    monotonic: float,
) -> float:
    jobs = [
        job
        for page in pages
        for job in page["jobs"]
        if job.get("runner_name") == runner and job.get("status") == "in_progress"
    ]
    if not runner or len(jobs) != 1:
        raise ValueError("unique current runner job required")
    job = jobs[0]
    if (
        job.get("run_id") != run
        or job.get("run_attempt") != attempt
        or job.get("head_sha") != commit
        or now.tzinfo is None
        or not math.isfinite(monotonic)
    ):
        raise ValueError("job source/attempt differs")
    started = datetime.fromisoformat(job["started_at"].replace("Z", "+00:00"))
    elapsed = (now - started).total_seconds()
    # The reusable T1 job has 45 minutes. Reserve 90s for clock skew/artifact upload.
    if not 0 <= elapsed < 2700 - 90 - 1200:
        raise ValueError("job cleanup budget unavailable")
    return monotonic + 2700 - 90 - elapsed


def main() -> None:
    value = deadline(
        json.loads(Path(os.environ["JOB_PAGES"]).read_text()),
        runner=os.environ["RUNNER_NAME"],
        run=int(os.environ["GITHUB_RUN_ID"]),
        attempt=int(os.environ["GITHUB_RUN_ATTEMPT"]),
        commit=os.environ["GITHUB_SHA"],
        now=datetime.now(UTC),
        monotonic=time.monotonic(),
    )
    with Path(os.environ["GITHUB_ENV"]).open("a") as stream:
        stream.write(f"JOURNEY_DEADLINE={value}\n")


if __name__ == "__main__":
    main()
