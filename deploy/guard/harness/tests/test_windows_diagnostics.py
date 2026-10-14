import subprocess
import textwrap
from pathlib import Path

import pytest

from guard_harness.native_paper import LifecycleError
from guard_harness.runner import RunError
from guard_harness.windows_diagnostics import (
    INSTALLER_REFUSALS,
    INSTALLER_WRAPPER,
    REFUSALS,
    STEPS,
    installer_refusal,
    observe,
)


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


@pytest.mark.parametrize("shell", ["ps51", "ps7"])
@pytest.mark.parametrize("message", sorted(INSTALLER_REFUSALS))
def test_installer_literals_survive_powershell_error_formatting(shell: str, message: str) -> None:
    if shell == "ps51":
        # PowerShell 5.1 includes a filename then wraps the exception payload.
        stderr = "private-machine\\install-windows-service.ps1 : " + textwrap.fill(message, 72)
        stderr += "\nAt private-machine:1 char:1\n+ throw 'source excerpt'\n"
    else:
        stderr = "\x1b[31mException: private-machine:80\x1b[0m\nLine |\n"
        stderr += "80 | throw 'source excerpt'\n"
        stderr += "\n".join("   | " + line for line in textwrap.wrap(message, 72))
    # The loader can add this wrapper after the helper's actual exception.
    stderr += "\n" + INSTALLER_WRAPPER + "\nprivate stderr sentinel"
    assert installer_refusal(stderr) == message


@pytest.mark.parametrize(
    "kind", ["drive-root", "program-data-root", "program-files-root", "protected-path"]
)
def test_acl_rights_only_emit_the_fixed_path_class(kind: str) -> None:
    message = f"Unprivileged machine path mutation rights refused ({kind}, rights=001f01ff)."
    assert installer_refusal(message) == (
        f"Unprivileged machine path mutation rights refused ({kind}, rights withheld)."
    )


@pytest.mark.parametrize(
    "stderr",
    [
        "private stderr sentinel",
        "SCM operation failed; transaction remains pending. private sentinel",
        "private sentinel SCM operation failed; transaction remains pending.",
        "+ throw 'SCM operation failed; transaction remains pending.'",
        "45 | throw 'SCM operation failed; transaction remains pending.'",
        "Untrusted machine path owner (private-path, owner=private-sid).",
        "Unprivileged machine path mutation rights refused (protected-path, rights=private).",
        (
            "Unprivileged machine path mutation rights refused (protected-path, "
            "rights=00000001). extra"
        ),
    ],
)
def test_unknown_or_source_excerpt_is_never_exported(stderr: str) -> None:
    assert installer_refusal(stderr) == "unknown"


def test_loader_wrapper_is_only_a_fallback() -> None:
    assert installer_refusal(INSTALLER_WRAPPER) == INSTALLER_WRAPPER
    specific = "SCM operation failed; transaction remains pending."
    assert installer_refusal(INSTALLER_WRAPPER + "\n" + specific) == specific


@pytest.mark.parametrize("failure", ["unknown", "timeout", "other-step", "success"])
def test_installer_observer_does_not_grant_credit_or_export_exception_details(
    tmp_path: Path, failure: str
) -> None:
    step = "per-user-lifecycle" if failure == "other-step" else "scm-install"
    error = (
        subprocess.TimeoutExpired(["private argv"], 10)
        if failure == "timeout"
        else RunError("private exception sentinel")
    )

    def execute() -> None:
        with observe(tmp_path, step, installer=True) as classifier:
            if classifier is not None and failure == "timeout":
                classifier("SCM operation failed; transaction remains pending.")
            if failure != "success":
                raise error

    if failure == "success":
        execute()
        assert not list(tmp_path.iterdir())
    else:
        with pytest.raises(type(error)) as caught:
            execute()
        assert caught.value is error
        body = (tmp_path / f"windows-{step}-failure.log").read_text()
        assert "private" not in body
        if failure == "other-step":
            assert "installer refusal" not in body
        else:
            assert body.endswith("installer refusal: unknown\n")
        assert not list(tmp_path.glob("*.json"))
