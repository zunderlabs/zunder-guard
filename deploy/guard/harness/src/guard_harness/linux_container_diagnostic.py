"""Explicit nongate source-installer rehearsal on genuinely signed released images.

This is only for local disposable guests before the new paper installer is published.
It cannot stand in for I6: the installer source is unshipped and no gate evidence is emitted.
"""

from pathlib import Path
from typing import Any

from guard_harness.linux_container_lifecycle import ContainerLifecycle
from guard_harness.linux_lifecycle import require


class SourceContainerDiagnostic(ContainerLifecycle):
    def install(self, name: str, installer: Path, *, files_only: bool = False) -> None:
        require(not files_only, "diagnostic requires the actual managed paper installer")
        stage = Path("/opt/guard-release-harness/container-paper-source")
        version = (
            self.inputs.previous_version if name == "previous-install" else self.inputs.version
        )
        args = [
            "python3",
            "-I",
            str(stage / "install-container-paper.py"),
            "--version",
            version,
            "--network",
            "paper",
            "--non-interactive",
            "--account",
            self.inputs.account,
            "--rules",
            self.inputs.rules,
            "--account-network",
            self.inputs.account_network,
        ]
        self.command(name, args, sensitive=True)

    def command(self, name: str, argv: list[str], *, sensitive: bool = False) -> str:
        if name == "uninstall":
            argv = [
                "python3",
                "-I",
                "/usr/local/libexec/zunder-guard-container-paper/install.py",
                "--uninstall",
            ]
        return super().command(name, argv, sensitive=sensitive)

    def after_reboot(self, *, require_reboot: bool = True) -> None:
        # Run the normal real Docker/systemd lifecycle, replacing only the prepublication
        # installer admission. Uninstall remains the real copied installed management script.
        uninstall_wrapper = self.inputs.installer
        super().after_reboot(require_reboot=require_reboot)
        require(uninstall_wrapper.is_file(), "source diagnostic installer wrapper vanished")

    def write(self, record: dict[str, Any]) -> None:
        record["gate_eligible"] = False
        record["installer_admission"] = "unpublished-source-diagnostic"
        super().write(record)
