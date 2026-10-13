"""The board must distinguish measured rows, partial matrices and read failures."""

import json
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest
import yaml

from guard_harness import row_status as rs

SOURCE = "a" * 40
ROOT = Path(__file__).resolve().parents[2]


def job(
    name: str,
    *,
    conclusion: str | None = "success",
    status: str = "completed",
    steps: Sequence[str] = (),
    run_id: int = 100,
    source: str = SOURCE,
    id: int = 1,
) -> rs.Job:
    return rs.Job(
        run_id,
        1,
        source,
        id,
        name,
        status,
        conclusion,
        tuple({"name": step, "status": "completed", "conclusion": "success"} for step in steps),
    )


def run(
    jobs: Sequence[rs.Job], workflow: str = "verify.yml", *, id: int = 100, source: str = SOURCE
) -> rs.Run:
    return rs.Run(id, 1, source, workflow, tuple(jobs))


def row(runs: Sequence[rs.Run], name: str) -> rs.Result:
    return next(item for item in rs.board(runs) if item.row == name)


def workflow_steps(workflow: str, job_name: str) -> tuple[str, ...]:
    definition = yaml.safe_load((ROOT / "github/workflows" / workflow).read_text())
    return tuple(step["name"] for step in definition["jobs"][job_name]["steps"] if "name" in step)


def full_verify() -> rs.Run:
    jobs = []
    for number in range(1, 8):
        jobs.append(
            job(
                f"Released trading and purchase journeys / P{number}",
                steps=workflow_steps("journey.yml", "purchase"),
            )
        )
    for name, key in (
        ("T1", "testnet-foreground"),
        ("T2", "testnet-systemd"),
        ("M3", "signing-gate"),
    ):
        jobs.append(
            job(
                "Released trading and purchase journeys / " + name,
                steps=workflow_steps("journey.yml", key),
            )
        )
    for number in range(1, 7):
        name = "native-admission" if number in {3, 4} else "linux-container-admission"
        jobs.append(
            job(
                f"install-matrix / {name} (I{number})",
                steps=workflow_steps("install-matrix.yml", name),
            )
        )
    jobs.append(
        job("install-matrix / aws-stack", steps=workflow_steps("install-matrix.yml", "aws-stack"))
    )
    for number in (1, 2):
        jobs.append(
            job(
                f"install-matrix / mainnet-admission (M{number})",
                steps=workflow_steps("install-matrix.yml", "mainnet-admission"),
            )
        )
    return run(
        [
            rs.Job(
                item.run_id,
                item.attempt,
                item.source,
                index,
                item.name,
                item.status,
                item.conclusion,
                item.steps,
            )
            for index, item in enumerate(jobs, 1)
        ]
    )


def test_every_gate_row_and_channel_uses_successful_deciding_jobs() -> None:
    results = rs.board([full_verify()])
    assert [item.row for item in results] == [
        *(f"P{i}" for i in range(1, 9)),
        *(f"D{i}" for i in range(1, 8)),
        *(f"I{i}" for i in range(1, 8)),
        "T1",
        "T2",
        "M1",
        "M2",
        "M3",
    ]
    assert all(item.status == "pass" and item.jobs for item in results)
    assert len(row([full_verify()], "D1").jobs) == 3
    assert row([full_verify()], "P8").jobs == row([full_verify()], "T1").jobs


@pytest.mark.parametrize(
    "conclusion,status,expected",
    [
        ("success", "completed", "pass"),
        ("failure", "completed", "fail"),
        ("cancelled", "completed", "fail"),
        ("timed_out", "completed", "fail"),
        ("action_required", "completed", "fail"),
        ("startup_failure", "completed", "fail"),
        ("skipped", "completed", "missing"),
        ("neutral", "completed", "missing"),
        (None, "queued", "missing"),
        (None, "in_progress", "missing"),
        ("unknown", "completed", "missing"),
    ],
)
def test_outcomes(conclusion: str | None, status: str, expected: str) -> None:
    assert (
        rs.assess("I1", job("linux-amd64 (fresh)", conclusion=conclusion, status=status)).status
        == expected
    )


def test_green_checkout_and_browser_approval_do_not_pass_purchase_or_p8() -> None:
    observed = run(
        [
            job("Checkout diagnostic P1 (no payment)"),
            job("T1", steps=["P8 browser approval with the dedicated testnet owner"]),
        ]
    )
    assert row([observed], "P1").status == "missing"
    assert row([observed], "P8").status == "missing"


def test_failed_t1_decides_p8_too_and_skipped_t2_remains_missing() -> None:
    observed = run(
        [
            job("Released trading and purchase journeys / T1", conclusion="failure"),
            job("Released trading and purchase journeys / T2", conclusion="skipped"),
        ]
    )
    assert row([observed], "T1").status == "fail"
    assert row([observed], "P8").status == "fail"
    assert row([observed], "T2").status == "missing"


def test_skipped_or_absent_install_admission_exposes_producer_failure() -> None:
    observed = run(
        [
            job("install-matrix / linux-amd64 (fresh)", conclusion="failure", id=2),
            job("install-matrix / linux-container-admission (I1)", conclusion="skipped", id=3),
        ]
    )
    result = row([observed], "I1")
    assert result.status == "fail"
    assert result.jobs[0].id == 2
    assert row([observed], "D5").status == "fail"
    assert row([observed], "D1").status == "fail"


def test_failed_i2_admission_decides_d1_but_not_other_channels() -> None:
    observed = full_verify()
    jobs = [
        item
        if not item.matches("linux-container-admission", "I2")
        else job(item.name, conclusion="failure", id=item.id)
        for item in observed.jobs
    ]
    assert row([run(jobs)], "D1").status == "fail"
    assert row([run(jobs)], "D3").status == "pass"
    assert row([run(jobs)], "D5").status == "pass"


def test_green_runtime_without_official_admission_is_missing_in_verify() -> None:
    steps = workflow_steps("install-matrix.yml", "linux-amd64")
    observed = run(
        [job(f"linux-amd64 ({scenario})", steps=steps) for scenario in ("fresh", "upgrade")]
    )
    assert row([observed], "I1").status == "missing"


@pytest.mark.parametrize("number", range(1, 8))
def test_diagnostics_require_full_lifecycle_matrix(number: int) -> None:
    name = f"I{number}"
    jobs = []
    if number == 7:
        jobs.append(job("aws-stack", steps=workflow_steps("install-matrix.yml", "aws-stack")))
    else:
        for scenario in ("fresh", "upgrade"):
            if number in {1, 2, 6}:
                key = {1: "linux-amd64", 2: "linux-arm64", 6: "linux-container"}[number]
                jobs.append(
                    job(f"{key} ({scenario})", steps=workflow_steps("install-matrix.yml", key))
                )
            elif number == 5:
                for channel in ("docker", "compose"):
                    jobs.append(
                        job(
                            f"docker ({scenario}, {channel})",
                            steps=workflow_steps("install-matrix.yml", "docker"),
                        )
                    )
            else:
                variants = (
                    ["macos"]
                    if number == 3
                    else [
                        "windows2022-ps51",
                        "windows2022-ps7",
                        "windows2025-ps51",
                        "windows2025-ps7",
                    ]
                )
                for variant in variants:
                    jobs.append(
                        job(
                            f"native ({variant}, {scenario}, ignored include fields)",
                            steps=workflow_steps("install-matrix.yml", "native"),
                        )
                    )
    observed = run(jobs, "install-matrix.yml")
    assert row([observed], name).status == "pass"
    assert row([run(jobs[:-1], "install-matrix.yml")], name).status == "missing"


def test_diagnostics_combine_only_same_source_and_latest_component_wins() -> None:
    steps = workflow_steps("install-matrix.yml", "linux-amd64")
    fresh = run([job("linux-amd64 (fresh)", steps=steps)], "install-matrix.yml")
    upgrade = run(
        [job("linux-amd64 (upgrade)", steps=steps, run_id=101)], "install-matrix.yml", id=101
    )
    assert row([fresh, upgrade], "I1").status == "pass"
    changed = run(
        [job("linux-amd64 (upgrade)", steps=steps, source="b" * 40)],
        "install-matrix.yml",
        source="b" * 40,
    )
    assert row([fresh, changed], "I1").status == "missing"
    failed = run(
        [job("linux-amd64 (fresh)", conclusion="failure", run_id=102)], "install-matrix.yml", id=102
    )
    assert row([fresh, upgrade, failed], "I1").status == "fail"


def test_diagnostics_do_not_mask_failure_on_another_source() -> None:
    steps = workflow_steps("install-matrix.yml", "linux-amd64")
    complete = run(
        [job(f"linux-amd64 ({scenario})", steps=steps) for scenario in ("fresh", "upgrade")],
        "install-matrix.yml",
    )
    failed = run(
        [job("linux-amd64 (fresh)", conclusion="failure", source="b" * 40)],
        "install-matrix.yml",
        source="b" * 40,
    )
    assert row([complete, failed], "I1").status == "fail"


def test_testnet_diagnostic_does_not_credit_p8_or_m3() -> None:
    observed = run(
        [
            job(
                "T1 foreground diagnostic only",
                steps=["Run the exact released T1 with only API wallet stdin"],
            )
        ],
        "install-matrix.yml",
    )
    assert row([observed], "T1").status == "pass"
    assert row([observed], "P8").status == "missing"
    assert row([observed], "M3").status == "missing"


def test_checkout_and_payment_diagnostics_show_the_partial_job_without_passing() -> None:
    observed = run(
        [
            job("Checkout diagnostic P1 (no payment)", id=51),
            job("base payment diagnostic only (no gate credit)", id=52),
        ],
        "journey.yml",
    )
    assert row([observed], "P1").status == "missing"
    assert row([observed], "P1").jobs[0].id == 51
    assert row([observed], "P3").status == "missing"
    assert row([observed], "P3").jobs[0].id == 52


@pytest.mark.parametrize(
    "name,row_name", [("linux-mainnet (native)", "M1"), ("mainnet-setup (linux)", "M2")]
)
def test_partial_mainnet_diagnostic_surfaces_failure_only(name: str, row_name: str) -> None:
    assert row([run([job(name)], "install-matrix.yml")], row_name).status == "missing"
    assert (
        row([run([job(name, conclusion="failure")], "install-matrix.yml")], row_name).status
        == "fail"
    )


def test_do_not_mix_verification_with_diagnostics_or_other_verify_runs() -> None:
    for other in ("verify.yml", "install-matrix.yml"):
        with pytest.raises(ValueError, match="never mix"):
            rs.board([run([]), run([], other)])


def test_skipped_parent_is_reported_when_all_install_rows_are_absent() -> None:
    observed = run([job("install-matrix", conclusion="skipped", id=33)])
    for name in ("I1", "I7", "M1", "M2", "D1", "D7"):
        result = row([observed], name)
        assert result.status == "missing"
        assert result.jobs[0].id == 33
        assert "did not produce row jobs" in result.reason


@pytest.mark.parametrize("row_name", ["M1", "M2"])
def test_complete_refusal_diagnostics_require_every_observation_route(row_name: str) -> None:
    names = (
        [
            "linux-mainnet (native)",
            "linux-mainnet (container)",
            "native-mainnet (macos-15, sh, macos)",
            "native-mainnet (windows-2022, powershell.exe, windows)",
            "aws-stack",
        ]
        if row_name == "M1"
        else ["mainnet-setup (linux)", "mainnet-setup (windows)", "native (macos, upgrade)"]
    )
    jobs = [
        job(name, id=index, steps=workflow_steps("install-matrix.yml", name.split(" (")[0]))
        for index, name in enumerate(names, 1)
    ]
    assert row([run(jobs, "install-matrix.yml")], row_name).status == "pass"
    for index in range(len(jobs)):
        partial = run(jobs[:index] + jobs[index + 1 :], "install-matrix.yml")
        assert row([partial], row_name).status == "missing"


def test_empty_board_has_every_row_missing() -> None:
    assert all(item.status == "missing" for item in rs.board([run([])]))


def test_api_pins_latest_attempt_paginates_and_only_gets(monkeypatch: pytest.MonkeyPatch) -> None:
    commands = []

    def fake(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        if "--paginate" not in command:
            value: Any = {
                "id": 100,
                "run_attempt": 2,
                "head_sha": SOURCE,
                "path": ".github/workflows/verify.yml",
            }
        else:
            value = [
                {
                    "jobs": [
                        {
                            "id": id,
                            "name": f"P{id}",
                            "run_id": 100,
                            "run_attempt": 2,
                            "status": "completed",
                            "conclusion": "success",
                            "steps": [],
                        }
                    ]
                }
                for id in (1, 2)
            ]
        return subprocess.CompletedProcess(command, 0, json.dumps(value), "")

    monkeypatch.setattr(subprocess, "run", fake)
    observed = rs.load_run("zunderlabs/zunder-guard", 100)
    assert observed.attempt == 2
    assert len(observed.jobs) == 2
    assert all(command[:5] == ["gh", "api", "--method", "GET", command[4]] for command in commands)
    assert commands[1][4].endswith("/attempts/2/jobs?per_page=100")
    assert commands[1][-2:] == ["--paginate", "--slurp"]


@pytest.mark.parametrize(
    "value",
    [
        {"id": 101, "run_attempt": 1, "head_sha": SOURCE, "path": ".github/workflows/verify.yml"},
        {"id": 100, "run_attempt": 1, "head_sha": SOURCE, "path": ".github/workflows/promote.yml"},
    ],
)
def test_refuse_wrong_run_or_workflow(monkeypatch: pytest.MonkeyPatch, value: Any) -> None:
    monkeypatch.setattr(rs, "api", lambda *args, **kwargs: value)
    with pytest.raises(ValueError):
        rs.load_run("zunderlabs/zunder-guard", 100)


def test_wrong_job_attempt_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake(endpoint: str, *, pages: bool = False) -> Any:
        if not pages:
            return {
                "id": 100,
                "run_attempt": 2,
                "head_sha": SOURCE,
                "path": ".github/workflows/verify.yml",
            }
        return [
            {
                "jobs": [
                    {
                        "id": 1,
                        "run_id": 100,
                        "run_attempt": 1,
                        "name": "P1",
                        "status": "completed",
                        "conclusion": "success",
                    }
                ]
            }
        ]

    monkeypatch.setattr(rs, "api", fake)
    with pytest.raises(ValueError, match="another run or attempt"):
        rs.load_run("zunderlabs/zunder-guard", 100)


def test_cli_json_deduplicates_ids_and_keeps_job_links(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls = []

    def fake(repo: str, id: int) -> rs.Run:
        calls.append(id)
        return full_verify()

    monkeypatch.setattr(rs, "load_run", fake)
    rs.main(["100", "100", "--json"])
    value = json.loads(capsys.readouterr().out)
    assert calls == [100]
    assert value["diagnostic"] is False
    assert len(value["rows"]) == 27
    assert "/actions/runs/100/job/" in value["rows"][0]["jobs"][0]


def test_cli_diagnostics_are_clearly_labelled(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(rs, "load_run", lambda *args: run([], "install-matrix.yml"))
    rs.main(["100"])
    output = capsys.readouterr().out
    assert "no gate credit" in output
    assert "P1  missing" in output
    assert "M3  missing" in output


@pytest.mark.parametrize(
    "args",
    [
        ["0"],
        ["-1"],
        ["1; gh run cancel"],
        ["100", "--repo", "-bad/repo"],
        ["100", "--repo", "owner/repo?x=secret"],
    ],
)
def test_invalid_input_never_calls_github(monkeypatch: pytest.MonkeyPatch, args: list[str]) -> None:
    def forbidden(*args: Any) -> Any:
        pytest.fail("invalid input called GitHub")

    monkeypatch.setattr(rs, "load_run", forbidden)
    with pytest.raises(SystemExit) as error:
        rs.main(args)
    assert error.value.code == 2


def test_api_failure_never_prints_raw_diagnostics(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 1, "private output", "private stderr"
        ),
    )
    with pytest.raises(SystemExit) as error:
        rs.main(["100"])
    assert error.value.code == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "read refused or failed" in output.err
    assert "private" not in output.err
