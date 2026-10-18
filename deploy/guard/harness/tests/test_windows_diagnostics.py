import re
import subprocess
import textwrap
from pathlib import Path

import pytest

from guard_harness.guard_refusals import GUARD_SERVICE_REFUSALS
from guard_harness.native_paper import LifecycleError
from guard_harness.runner import RunError
from guard_harness.windows_diagnostics import (
    INSTALLER_REFUSALS,
    INSTALLER_WRAPPER,
    REFUSALS,
    STEPS,
    installer_details,
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


@pytest.mark.parametrize("width", [41, 80, 120])
@pytest.mark.parametrize("message", sorted(INSTALLER_REFUSALS))
def test_installer_literals_survive_powershell_51_hard_wrapping(width: int, message: str) -> None:
    # Redirected PowerShell 5.1 output breaks lines at the buffer width, mid-word too.
    payload = "C:\\private-machine\\install-windows-service.ps1 : " + message
    stderr = "\n".join(payload[at : at + width] for at in range(0, len(payload), width))
    assert installer_refusal(stderr + "\n" + INSTALLER_WRAPPER) == message
    fqid = "    + FullyQualifiedErrorId : " + message
    stderr = "\n".join(fqid[at : at + width] for at in range(0, len(fqid), width))
    assert installer_refusal(stderr) == message


def test_hard_wrapping_never_admits_extra_or_partial_text() -> None:
    message = "SCM operation failed; transaction remains pending."
    for stderr in (
        message[:20] + "\n" + message[20:] + " private",
        "private " + message[:20] + "\n" + message[20:],
        message[:20] + "\n" + message[20:-1],
    ):
        assert installer_refusal(stderr) == "unknown"


def test_installer_details_emit_only_closed_classes() -> None:
    stderr = "\n".join(
        [
            "zunder-guard: service refused: service ACL grants another identity access",
            "zunder-guard: service I/O: Access is denied. (os error 5)",
            "zunder-guard: the account 0x1111111111111111111111111111111111111111 is private",
            "C:\\private\\install-windows-service.ps1 : Exception calling SetAccessControl",
            "    + CategoryInfo          : PermissionDenied: (C:\\private:String) [], Unauth",
            "    + FullyQualifiedErrorId : UnauthorizedAccessException",
            "    + CategoryInfo          : NotSpecified: (wrote C:\\private:String) [], Remote",
            "    + FullyQualifiedErrorId : NativeCommandError",
            "    + FullyQualifiedErrorId : System.IO.IOException,Microsoft.PowerShell.Commands",
            "    + FullyQualifiedErrorId : C:\\private\\path",
            "    + FullyQualifiedErrorId : key0123456789abcdef",
            "    + CategoryInfo          : PrivateCategory: (x) [], y",
            "zunder-guard: service refused: invalid 0x1111 secret",
            "zunder-guard: service refused: C:\\private\\path is wrong",
        ]
    )
    assert installer_details(stderr) == [
        "guard service refusal: service ACL grants another identity access",
        "guard os error: 5",
        "guard error: present",
        "powershell error category: PermissionDenied",
        "powershell error category: NotSpecified",
        "powershell error id: UnauthorizedAccessException",
        "powershell error id: NativeCommandError",
        "powershell error id: System.IO.IOException",
    ]
    assert installer_details("private stderr sentinel 0123") == []


def test_failed_installer_observation_records_classes_and_closed_state(tmp_path: Path) -> None:
    stderr = (
        "zunder-guard: service refused: service ACL grants another identity access\n"
        "    + FullyQualifiedErrorId : NativeCommandError\n" + INSTALLER_WRAPPER
    )

    def state() -> list[str]:
        return [
            "transaction phase: config-preparing",
            "scm state: STOPPED",
            "private: C:\\private\\path",
            "scm start: DISABLED\nprivate",
        ]

    with pytest.raises(RunError):
        with observe(tmp_path, "scm-install", installer=True, after_failure=state) as classify:
            assert classify is not None
            classify(stderr)
            raise RunError("private exception sentinel")
    assert (tmp_path / "windows-scm-install-failure.log").read_text() == (
        "Windows lifecycle failure step: scm-install\n"
        "failure reason: command-failed\n"
        f"installer refusal: {INSTALLER_WRAPPER}\n"
        "guard service refusal: service ACL grants another identity access\n"
        "powershell error id: NativeCommandError\n"
        "transaction phase: config-preparing\n"
        "scm state: STOPPED\n"
    )

    def broken() -> list[str]:
        raise OSError("private sentinel")

    other = tmp_path / "other"
    with pytest.raises(RunError):
        with observe(other, "scm-install", installer=True, after_failure=broken):
            raise RunError("private exception sentinel")
    body = (other / "windows-scm-install-failure.log").read_text()
    assert body.endswith("installer refusal: unknown\nafter-failure observation: unavailable\n")
    assert "private" not in body


def test_scm_state_reads_only_closed_phase_and_scm_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import platform

    from test_install_evidence import release

    import guard_harness.native_testnet as native

    monkeypatch.setattr(platform, "system", lambda: "Windows")
    monkeypatch.setenv("ProgramData", str(tmp_path / "data"))
    current = release(tmp_path / "assets")
    controller = native.NativeTestnet(current, current, tmp_path / "work", "inert", "pwsh.exe")
    outputs = {
        "query": (0, b"SERVICE_NAME: x\n        STATE              : 1  STOPPED\n"),
        "qc": (0, b"        START_TYPE         : 4   DISABLED\n private C:\\path\n"),
    }

    def fake(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        code, out = outputs[argv[1]]
        return subprocess.CompletedProcess(argv, code, out, b"private stderr")

    monkeypatch.setattr("guard_harness.native_testnet.subprocess.run", fake)
    assert controller.scm_state() == [
        "transaction phase: absent",
        "scm state: STOPPED",
        "scm start: DISABLED",
    ]
    controller.transaction.parent.mkdir(parents=True)
    controller.transaction.write_text('{"phase": "config-preparing", "account": "0xprivate"}')
    outputs["query"] = (1060, b"private")
    outputs["qc"] = (0, b"START_TYPE : 9 PRIVATE_VALUE\n")
    assert controller.scm_state() == [
        "transaction phase: config-preparing",
        "scm state: absent",
        "scm start: exit 0",
    ]
    controller.transaction.write_text('{"phase": "C:\\\\private"}')
    assert controller.scm_state()[0] == "transaction phase: other"
    for unhashable in ('{"phase": ["config-preparing"]}', '{"phase": {"x": 1}}', "[1]"):
        controller.transaction.write_text(unhashable)
        assert controller.scm_state()[0] in (
            "transaction phase: other",
            "transaction phase: unreadable",
        )


def test_guard_refusal_literals_are_exactly_the_rust_source() -> None:
    root = Path(__file__).resolve().parents[4]
    sources = [
        root / "crates/zunder-guard/src/service.rs",
        *sorted((root / "crates/zunder-guard/src/service").glob("*.rs")),
    ]
    assert len(sources) >= 4
    literals: set[str] = set()
    for source in sources:
        literals |= set(re.findall(r'refused\(\s*"((?:[^"\\]|\\.)*)"', source.read_text()))
    assert literals == GUARD_SERVICE_REFUSALS


def test_only_a_fixed_guard_literal_is_named() -> None:
    literal = "service ACL grants another identity access"
    assert literal in GUARD_SERVICE_REFUSALS
    assert installer_details("zunder-guard: service refused: " + literal) == [
        "guard service refusal: " + literal
    ]
    # Words-only text that is not one of Guard's literals is only "present".
    for other in (
        "service ACL grants another identity access today",
        "please read the private notes",
        "",
    ):
        assert installer_details("zunder-guard: service refused: " + other) == [
            "guard error: present"
        ]


def test_every_fixed_installer_literal_is_thrown_by_the_signed_loader_or_helper() -> None:
    guard = Path(__file__).resolve().parents[2]
    source = (guard / "windows/service.ps1").read_text() + (guard / "loader/i.ps1").read_text()
    interpolated = ("Untrusted machine path owner (", "Organization ")
    for message in INSTALLER_REFUSALS:
        if not message.startswith(interpolated):
            quoted = "'" + message.replace("'", "''") + "'"  # PowerShell single-quote escaping
            assert quoted in source, message
    # rc.1 I4: an incomplete environment now refuses with this literal, not an
    # ArgumentException from an empty machine path.
    assert (
        "Windows did not resolve ProgramData or Program Files for this process; run the "
        "installer with the complete Windows environment."
    ) in INSTALLER_REFUSALS
