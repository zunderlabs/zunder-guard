"""Execute the actual M1 policy step with inert subjects and registry preparation."""

import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from guard_harness import windows_policy
from guard_harness.c6_owner import document
from guard_harness.native_paper import LifecycleError
from guard_harness.native_release import Release

GUARD = Path(__file__).resolve().parents[2]
WORKFLOW = (
    GUARD / "github/workflows/install-matrix.yml"
    if (GUARD / "github/workflows").is_dir()
    else GUARD.parents[1] / ".github/workflows/install-matrix.yml"
)


@pytest.mark.parametrize("refused", [False, True])
def test_m1_reuses_measured_policy_before_hidden_terminal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, refused: bool
) -> None:
    steps = document(WORKFLOW.read_text())["jobs"]["native-mainnet"]["steps"]
    policy_index = next(i for i, step in enumerate(steps) if "crash policy" in step.get("name", ""))
    terminal_index = next(
        i for i, step in enumerate(steps) if "hidden-terminal" in step.get("name", "")
    )
    step = steps[policy_index]
    assert policy_index < terminal_index
    assert step["if"] == "${{ matrix.variant == 'windows' }}"
    assert "continue-on-error" not in step
    assert step["env"] == {"TAG": "${{ inputs.tag }}", "SOURCE": "${{ inputs.commit }}"}
    assert "set -euo pipefail" in step["run"]
    assert "guard_harness.native_testnet --mode mainnet-refusal" in steps[terminal_index]["run"]
    assert "if" not in steps[terminal_index]  # A failed policy step prevents terminal admission.
    script = step["run"].split("python - <<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setenv("TAG", "v1.0.0-rc.14")
    monkeypatch.setenv("SOURCE", "a" * 40)
    monkeypatch.setenv("WALLET_FRAME", "inert-private-fixture")
    monkeypatch.setenv("UNRELATED_TOKEN", "inert-token-fixture")
    monkeypatch.setenv("ZUNDER_GUARD_KEY", "inert-key-fixture")
    calls: list[Path] = []

    def prepare(release: Release, work: Path, env: dict[str, str]) -> dict[str, object]:
        assert release == Release("v1.0.0-rc.14", "a" * 40, tmp_path / "subjects/candidate/assets")
        assert work == tmp_path / "mainnet/windows-policy"
        assert work.parent.is_dir() and not work.exists()
        assert "PATH" in env
        assert not any(
            name.startswith("ZUNDER_") or "WALLET" in name or "TOKEN" in name for name in env
        )
        assert not (tmp_path / "mainnet/M1").exists()
        calls.append(work)
        if refused:
            raise LifecycleError("policy refused before terminal admission")
        return {"crash_dump_policy": windows_policy.REMOVAL_NOTE}

    monkeypatch.setattr(windows_policy, "prepare", prepare)
    if refused:
        with pytest.raises(LifecycleError, match="before terminal admission"):
            exec(compile(script, "<M1-policy-step>", "exec"), {})
    else:
        exec(compile(script, "<M1-policy-step>", "exec"), {})
    assert calls == [tmp_path / "mainnet/windows-policy"]
    assert not (tmp_path / "mainnet/M1").exists()
    if os.name != "nt":
        assert tmp_path.joinpath("mainnet").stat().st_mode & 0o777 == 0o700


def test_m1_retains_policy_receipts_separately_even_after_refusal() -> None:
    steps = document(WORKFLOW.read_text())["jobs"]["native-mainnet"]["steps"]
    upload: dict[str, Any] = next(
        step for step in steps if step.get("uses", "").startswith("actions/upload-artifact@")
    )
    assert upload["if"] == "always()"
    paths = upload["with"]["path"].splitlines()
    assert "${{ runner.temp }}/mainnet/M1/*.json" in paths
    assert "${{ runner.temp }}/mainnet/M1/*.log" in paths
    assert "${{ runner.temp }}/mainnet/windows-policy/*.receipt.json" in paths
    assert not any("zunder-guard.exe" in path or "**" in path for path in paths)


@pytest.mark.parametrize("failed", [False, True])
def test_linux_m1_failure_reason_does_not_hide_failure_or_credit_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failed: bool
) -> None:
    steps = document(WORKFLOW.read_text())["jobs"]["linux-mainnet"]["steps"]
    step = next(step for step in steps if "M1 protected" in step.get("name", ""))
    script = step["run"].split("python - <<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    script = "failed=False" + script.split("failed=False", 1)[1].split("    archive=", 1)[0]
    output = tmp_path / "linux-mainnet"
    output.mkdir()
    (output / "host-18.log").write_text(
        "guard_harness.linux_lifecycle.LifecycleError: "
        "venue unapproved-wallet refusal was not observed\n"
    )
    monkeypatch.setenv("MODE", "native")

    def run(*args: Any, **kwargs: Any) -> None:
        if failed:
            raise subprocess.CalledProcessError(1, ["inert-guest"])

    monkeypatch.setattr(subprocess, "run", run)
    scope = dict(subprocess=subprocess, os=os, base=tmp_path, output=output, words=["inert-guest"])
    if failed:
        with pytest.raises(subprocess.CalledProcessError):
            exec(compile(script, "<linux-M1-failure-step>", "exec"), scope)
        assert (tmp_path / "mainnet/M1/linux-systemd.failure.json").is_file()
    else:
        exec(compile(script, "<linux-M1-failure-step>", "exec"), scope)
        assert list((tmp_path / "mainnet/M1").iterdir()) == []
