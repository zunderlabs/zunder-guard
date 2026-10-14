import subprocess
from pathlib import Path

import pytest

from guard_harness.native_paper import LifecycleError
from guard_harness.runner import RunError
from guard_harness.windows_diagnostics import REFUSALS, STEPS, observe


@pytest.mark.parametrize("step", sorted(STEPS))
@pytest.mark.parametrize(
    "error,reason",
    [
        (RuntimeError("private sentinel output"), "unknown"),
        (RunError("private sentinel output"), "command-failed"),
        (subprocess.TimeoutExpired(["private sentinel argv"], 10), "command-timeout"),
        (ModuleNotFoundError("private sentinel output", name="pwd"), "posix-pwd-unavailable"),
        (ModuleNotFoundError("private sentinel output", name="other"), "unknown"),
        *[(LifecycleError(message), reason) for message, reason in REFUSALS.items()],
    ],
)
def test_failure_observations_emit_only_fixed_step_and_reason(
    tmp_path: Path, step: str, error: Exception, reason: str
) -> None:
    with pytest.raises(type(error)) as caught:
        with observe(tmp_path, step):
            raise error
    assert caught.value is error  # Evidence never changes refusal or grants a pass.
    assert (tmp_path / f"windows-{step}-failure.log").read_text() == (
        f"Windows lifecycle failure step: {step}\nfailure reason: {reason}\n"
    )
    assert not list(tmp_path.glob("*.json"))  # No positive receipt or gate token.


def test_unknown_step_is_withheld_and_success_has_no_failure_log(tmp_path: Path) -> None:
    with observe(tmp_path, "scm-install"):
        pass
    assert not list(tmp_path.iterdir())
    with pytest.raises(RuntimeError):
        with observe(tmp_path, "private sentinel step"):
            raise RuntimeError("private sentinel output")
    assert (tmp_path / "windows-unknown-failure.log").read_text() == (
        "Windows lifecycle failure step: unknown\nfailure reason: unknown\n"
    )
