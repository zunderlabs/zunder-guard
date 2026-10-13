"""Reserve journey cleanup against the actual current GitHub job's recorded start."""

import json
import math
import os
import subprocess
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from guard_harness.testnet_process import ENTRY_REMAINING
from guard_harness.testnet_scan import SCAN_TIMEOUT

# GitHub's jobs listing can trail a job's own start by seconds (rc.14 T1 diagnostic
# 38454029938 refused 24 s after its start, before any custody). Only a listing that
# does not yet show this runner's job is read again; every other refusal is final.
LISTING_LOOKUPS = 6
LISTING_WAIT_SECONDS = 10


class JobNotListed(ValueError):
    """The jobs listing does not show this runner's in-progress job (yet)."""


def deadline(
    pages: list[dict[str, Any]],
    *,
    runner: str,
    run: int,
    attempt: int,
    commit: str,
    now: datetime,
    monotonic: float,
    job_timeout: int = 7200,
) -> float:
    jobs = [
        job
        for page in pages
        for job in page["jobs"]
        if job.get("runner_name") == runner and job.get("status") == "in_progress"
    ]
    if runner and not jobs:
        raise JobNotListed("unique current runner job required")
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
    # Reserve an independent failure scan plus clock skew/upload outside the journey.
    reserve = SCAN_TIMEOUT + 90
    if type(job_timeout) is not int or not 0 < job_timeout <= 21600:
        raise ValueError("bounded calling job timeout required")
    if not 0 <= elapsed < job_timeout - reserve - SCAN_TIMEOUT - ENTRY_REMAINING:
        raise ValueError("job cleanup budget unavailable")
    return monotonic + job_timeout - reserve - elapsed


def settled_deadline(
    pages: Path,
    refresh: Callable[[], None],
    *,
    runner: str,
    run: int,
    attempt: int,
    commit: str,
    job_timeout: int,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> float:
    """Read the listing again only while it omits this job; each answer uses a fresh clock.

    A later lookup only adds elapsed time, so the reserved deadline never grows. Duplicate
    or foreign jobs, another source or attempt and an expired budget refuse at once.
    """
    for lookup in range(LISTING_LOOKUPS):
        if lookup:
            sleep(LISTING_WAIT_SECONDS)
            refresh()
        try:
            return deadline(
                json.loads(pages.read_text()),
                runner=runner,
                run=run,
                attempt=attempt,
                commit=commit,
                now=clock(),
                monotonic=monotonic(),
                job_timeout=job_timeout,
            )
        except JobNotListed:
            if lookup == LISTING_LOOKUPS - 1:
                raise
    raise AssertionError("bounded listing lookups always return or raise")


def main() -> None:
    pages = Path(os.environ["JOB_PAGES"])
    run, attempt = int(os.environ["GITHUB_RUN_ID"]), int(os.environ["GITHUB_RUN_ATTEMPT"])
    url = (
        f"repos/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{run}"
        f"/attempts/{attempt}/jobs?per_page=100"
    )

    def refresh() -> None:
        # The same read-only listing the calling step made, replaced only when complete.
        listed = subprocess.run(
            ["gh", "api", "--paginate", "--slurp", url],
            check=True,
            capture_output=True,
            timeout=60,
        ).stdout
        pending = pages.with_suffix(".pending")
        pending.write_bytes(listed)
        pending.chmod(0o600)
        pending.replace(pages)

    value = settled_deadline(
        pages,
        refresh,
        runner=os.environ["RUNNER_NAME"],
        run=run,
        attempt=attempt,
        commit=os.environ["GITHUB_SHA"],
        job_timeout=int(os.environ["JOB_TIMEOUT_SECONDS"]),
    )
    with Path(os.environ["GITHUB_ENV"]).open("a") as stream:
        stream.write(f"JOURNEY_DEADLINE={value}\n")


if __name__ == "__main__":
    main()
