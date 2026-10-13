"""Read a Guard row board from Actions jobs; never dispatch or authenticate a release.

Usage: python -m guard_harness.row_status RUN_ID [DIAGNOSTIC_RUN_ID ...]
The latest attempt is pinned before reading paginated jobs. This is a one-shot
snapshot, not a watcher: invoke at most once a minute. Diagnostic passes require
all lifecycle variants at one harness commit, and are never gate evidence.
"""

import argparse
import json
import re
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

ROWS = tuple(
    f"{group}{number}"
    for group, count in (("P", 8), ("D", 7), ("I", 7), ("T", 2), ("M", 3))
    for number in range(1, count + 1)
)
CHANNEL_ROWS = {
    "D1": ("I1", "I2", "I3"),
    "D2": ("I4",),
    "D3": ("I3",),
    "D4": ("I5",),
    "D5": ("I1",),
    "D6": ("I7",),
    "D7": ("I6",),
}
FAILURES = {"failure", "cancelled", "timed_out", "action_required", "startup_failure", "stale"}
INSTALL_JOBS = {"I1": "linux-amd64", "I2": "linux-arm64", "I6": "linux-container"}


@dataclass(frozen=True)
class Job:
    run_id: int
    attempt: int
    source: str
    id: int
    name: str
    status: str
    conclusion: str | None
    steps: tuple[dict[str, Any], ...]

    @property
    def leaf(self) -> str:
        return self.name.rsplit(" / ", 1)[-1]

    def matches(self, name: str, *variants: str) -> bool:
        match = re.fullmatch(r"([^()]+?)(?: \(([^()]*)\))?", self.leaf)
        return bool(
            match and match[1] == name and set(variants) <= set((match[2] or "").split(", "))
        )

    def reference(self, repo: str) -> str:
        return (
            f"{self.name} [run {self.run_id}, attempt {self.attempt}, job {self.id}] "
            f"https://github.com/{repo}/actions/runs/{self.run_id}/job/{self.id}"
        )


@dataclass(frozen=True)
class Run:
    id: int
    attempt: int
    source: str
    workflow: str
    jobs: tuple[Job, ...]


@dataclass(frozen=True)
class Result:
    row: str
    status: str
    jobs: tuple[Job, ...]
    reason: str


def api(endpoint: str, *, pages: bool = False) -> Any:
    command = ["gh", "api", "--method", "GET", endpoint]
    if pages:
        command += ["--paginate", "--slurp"]
    try:
        process = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("GitHub read unavailable; install/sign in to gh and retry") from error
    if process.returncode:
        # Never echo subprocess diagnostics, environment values, or raw API bodies.
        raise ValueError("GitHub read refused or failed; no board was produced")
    try:
        return json.loads(process.stdout)
    except ValueError as error:
        raise ValueError("GitHub returned invalid JSON; no board was produced") from error


def load_run(repo: str, run_id: int) -> Run:
    root = f"repos/{repo}/actions/runs/{run_id}"
    metadata = api(root)
    attempt = metadata["run_attempt"]
    source = metadata["head_sha"]
    workflow = metadata["path"].split("@", 1)[0].rsplit("/", 1)[-1]
    if metadata["id"] != run_id or type(attempt) is not int or attempt < 1:
        raise ValueError("GitHub returned a different run or invalid attempt")
    if workflow not in {"verify.yml", "install-matrix.yml", "journey.yml"}:
        raise ValueError("only verify, install-matrix and journey runs are supported")
    pages = api(f"{root}/attempts/{attempt}/jobs?per_page=100", pages=True)
    jobs = tuple(
        Job(
            run_id,
            attempt,
            source,
            item["id"],
            item["name"],
            item["status"],
            item["conclusion"],
            tuple(item.get("steps", [])),
        )
        for page in pages
        for item in page["jobs"]
    )
    if any(
        item.get("run_id") != run_id or item.get("run_attempt", attempt) != attempt
        for page in pages
        for item in page["jobs"]
    ):
        raise ValueError("GitHub returned jobs from another run or attempt")
    return Run(run_id, attempt, source, workflow, jobs)


def assess(row: str, job: Job | None, step: str | None = None) -> Result:
    if job is None:
        return Result(row, "missing", (), "job absent")
    if job.conclusion in FAILURES:
        return Result(row, "fail", (job,), job.conclusion)
    if job.status != "completed" or job.conclusion != "success":
        return Result(row, "missing", (job,), job.conclusion or job.status)
    if step and not any(
        item.get("name") == step
        and item.get("status") == "completed"
        and item.get("conclusion") == "success"
        for item in job.steps
    ):
        return Result(row, "missing", (job,), f"required step not successful: {step}")
    return Result(row, "pass", (job,), "successful deciding job")


def combine(row: str, results: Sequence[Result], reason: str) -> Result:
    status = (
        "fail"
        if any(item.status == "fail" for item in results)
        else "missing"
        if any(item.status == "missing" for item in results)
        else "pass"
    )
    deciding = [item for item in results if item.status == status]
    jobs = tuple(dict.fromkeys(job.id for item in deciding for job in item.jobs))
    by_id = {job.id: job for item in deciding for job in item.jobs}
    detail = "; ".join(dict.fromkeys(item.reason for item in deciding))
    return Result(row, status, tuple(by_id[id] for id in jobs), f"{reason}: {detail}")


def latest(jobs: Sequence[Job], name: str, *variants: str) -> Job | None:
    matches = [job for job in jobs if job.matches(name, *variants)]
    return max(matches, key=lambda job: (job.run_id, job.attempt, job.id), default=None)


def component(
    row: str, jobs: Sequence[Job], name: str, variants: tuple[str, ...], step: str
) -> Result:
    selected = latest(jobs, name, *variants)
    if selected is None:
        suffix = f" ({', '.join(variants)})" if variants else ""
        return Result(row, "missing", (), f"required job absent: {name}{suffix}")
    return assess(row, selected, step)


def lifecycle(row: str, jobs: Sequence[Job]) -> Result:
    if row == "I7":
        return component(
            row,
            jobs,
            "aws-stack",
            (),
            "I7 signed public template, paper bot, reboot, upgrade and owned cleanup",
        )
    parts = []
    for scenario in ("fresh", "upgrade"):
        if row in INSTALL_JOBS:
            parts.append(
                component(
                    row,
                    jobs,
                    INSTALL_JOBS[row],
                    (scenario,),
                    f"{row} authenticated paper and protected Testnet lifecycle",
                )
            )
        elif row == "I5":
            for channel in ("docker", "compose"):
                parts.append(
                    component(
                        row,
                        jobs,
                        "docker",
                        (scenario, channel),
                        "I5 signed digest Docker and Compose paper and Testnet lifecycle",
                    )
                )
        else:
            variants = (
                ("macos",)
                if row == "I3"
                else ("windows2022-ps51", "windows2022-ps7", "windows2025-ps51", "windows2025-ps7")
            )
            for variant in variants:
                parts.append(
                    component(
                        row,
                        jobs,
                        "native",
                        (variant, scenario),
                        "Released-byte paper and read-only native testnet lifecycles",
                    )
                )
    return combine(row, parts, "fresh + upgrade, all variants")


def refusal_observations(row: str, jobs: Sequence[Job]) -> Result:
    if row == "M1":
        parts = [
            component(
                row,
                jobs,
                "linux-mainnet",
                (mode,),
                "M1 protected staged native/container userRole refusal in KVM",
            )
            for mode in ("native", "container")
        ]
        parts += [
            component(
                row,
                jobs,
                "native-mainnet",
                (variant,),
                "M1 actual hidden-terminal unapproved wallet refusal, no orders",
            )
            for variant in ("macos", "windows")
        ]
        parts.append(lifecycle("I7", jobs))
    else:
        parts = [
            component(
                row,
                jobs,
                "mainnet-setup",
                (variant,),
                "Actual released-byte no-key mainnet setup refusals",
            )
            for variant in ("linux", "windows")
        ]
        parts.append(
            component(
                row,
                jobs,
                "native",
                ("macos", "upgrade"),
                "Released-byte paper and read-only native testnet lifecycles",
            )
        )
    return combine(row, parts, "all required refusal observation jobs")


def blocked_install(row: str, result: Result, jobs: Sequence[Job]) -> Result:
    parent = latest(jobs, "install-matrix")
    if result.status == "missing" and not result.jobs and parent is not None:
        return Result(
            row,
            "missing",
            (parent,),
            f"install workflow did not produce row jobs: {parent.conclusion or parent.status}",
        )
    return result


def verify_row(row: str, jobs: Sequence[Job]) -> Result:
    if row.startswith("I"):
        name = (
            "aws-stack"
            if row == "I7"
            else "native-admission"
            if row in {"I3", "I4"}
            else "linux-container-admission"
        )
        step = (
            "Prepare I7 predicate only after full lifecycle and confirmed cleanup"
            if row == "I7"
            else "Admit only the complete native row at the exact released source"
            if row in {"I3", "I4"}
            else "Admit complete paper and Testnet lifecycles on exact released bytes"
        )
        result = assess(row, latest(jobs, name, *(() if row == "I7" else (row,))), step)
        if result.status == "missing":
            producers = lifecycle(row, jobs)
            if producers.status == "fail":
                return producers
        return blocked_install(row, result, jobs)
    if row in {"M1", "M2"}:
        result = assess(
            row,
            latest(jobs, "mainnet-admission", row),
            "Fail closed unless every platform observation completed",
        )
        # Refusal workers also run in diagnostics, but only the complete admission
        # can decide an M row. Do not credit a subset of the protected routes.
        if result.status == "missing":
            producers = refusal_observations(row, jobs)
            if producers.status == "fail":
                return producers
        return blocked_install(row, result, jobs)
    name = "T1" if row == "P8" else row
    step = (
        "Attest completed P8 including the actual Guard fee-bearing fill"
        if row == "P8"
        else "Attest passing purchase journey"
        if row.startswith("P")
        else "Attest passing T1 against the signed immutable manifest"
        if row == "T1"
        else "Attest passing T2 against the signed immutable manifest"
        if row == "T2"
        else "Authenticate all three SDK platforms and both live testnet journeys"
    )
    return assess(row, latest(jobs, name), step)


def diagnostic_row(row: str, jobs: Sequence[Job]) -> Result:
    if row.startswith("I"):
        return lifecycle(row, jobs)
    if row in {"T1", "T2"}:
        name = "T1 foreground diagnostic only" if row == "T1" else "T2 systemd diagnostic only"
        step = f"Run the exact released {row} with only API wallet stdin"
        return assess(row, latest(jobs, name), step)
    if row in {"M1", "M2"}:
        return refusal_observations(row, jobs)
    partial = latest(jobs, f"Checkout diagnostic {row}", "no payment")
    if partial is None and row in {"P2", "P3"}:
        network = "arbitrum" if row == "P2" else "base"
        partial = latest(jobs, f"{network} payment diagnostic only", "no gate credit")
    if partial is not None:
        return Result(row, "missing", (partial,), "partial checkout/payment only; no complete row")
    return Result(row, "missing", (), "no complete diagnostic row; no gate credit")


def board(runs: Sequence[Run]) -> tuple[Result, ...]:
    if not runs:
        raise ValueError("at least one run required")
    verification = [run for run in runs if run.workflow == "verify.yml"]
    if verification and len(runs) != 1:
        raise ValueError("use one verify run OR a set of diagnostic runs, never mix them")
    results = {}
    for row in ROWS:
        if row.startswith("D"):
            continue
        if verification:
            results[row] = verify_row(row, verification[0].jobs)
        else:
            # Never stitch fresh and upgrade on different preview source commits.
            cohorts = []
            for source in sorted({run.source for run in runs}):
                jobs = tuple(job for run in runs if run.source == source for job in run.jobs)
                cohorts.append(diagnostic_row(row, jobs))
            failures = [result for result in cohorts if result.status == "fail"]
            passes = [result for result in cohorts if result.status == "pass"]
            results[row] = (
                combine(row, failures, "diagnostic failure")
                if failures
                else passes[-1]
                if passes
                else combine(row, cohorts, "incomplete diagnostic")
            )
    for row, dependencies in CHANNEL_ROWS.items():
        results[row] = combine(
            row,
            [results[dep] for dep in dependencies],
            "measured channel via " + ", ".join(dependencies),
        )
    return tuple(results[row] for row in ROWS)


def positive_id(value: str) -> int:
    if not re.fullmatch(r"[1-9][0-9]*", value):
        raise argparse.ArgumentTypeError("run id must be a positive decimal integer")
    return int(value)


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_ids", nargs="+", type=positive_id)
    parser.add_argument("--repo", default="zunderlabs/zunder-guard")
    parser.add_argument("--json", action="store_true", help="emit the same board as JSON")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repo):
        parser.error("repo must be OWNER/REPO")
    try:
        runs = [load_run(args.repo, id) for id in dict.fromkeys(args.run_ids)]
        results = board(runs)
    except (ValueError, KeyError, TypeError) as error:
        # KeyError/TypeError identify malformed API structures without dumping them.
        parser.exit(
            2, f"row_status: {error if isinstance(error, ValueError) else 'invalid API shape'}\n"
        )
    diagnostic = runs[0].workflow != "verify.yml"
    note = (
        "Diagnostic job coverage only; released-byte identity is not authenticated; no gate credit."
        if diagnostic
        else "Actions job status only; release authentication remains the gate's job."
    )
    if args.json:
        print(
            json.dumps(
                {
                    "diagnostic": diagnostic,
                    "note": note,
                    "runs": [
                        {"id": run.id, "attempt": run.attempt, "source": run.source} for run in runs
                    ],
                    "rows": [
                        {
                            "row": result.row,
                            "status": result.status,
                            "reason": result.reason,
                            "jobs": [job.reference(args.repo) for job in result.jobs],
                        }
                        for result in results
                    ],
                },
                indent=2,
            )
        )
    else:
        print(note)
        for run in runs:
            print(f"Run {run.id}, attempt {run.attempt}, source {run.source}")
        for result in results:
            jobs = "; ".join(job.reference(args.repo) for job in result.jobs) or "-"
            print(f"{result.row:<3} {result.status:<7} {jobs} | {result.reason}")


if __name__ == "__main__":
    main()
