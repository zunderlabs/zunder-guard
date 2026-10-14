"""Fixed macOS uninstall diagnostics and measured hosted foreground cleanup."""

import os
import stat
from pathlib import Path

from guard_harness.native_channels import remove_macos_paper
from guard_harness.native_paper import LifecycleError
from guard_harness.native_release import Release
from guard_harness.runner import RunError, run

INSTALLER_REFUSALS = frozenset(
    {
        "macOS managed uninstall requires service-instance testnet",
        "macOS uninstall accepts no setup inputs",
        "macOS managed uninstall requires root",
        "untrusted macOS uninstall path",
        "writable macOS uninstall path",
    }
)
HELPER_REFUSALS = frozenset(
    {
        "Testnet uninstall requires root",
        "owned Testnet release inventory missing",
        "owned LaunchDaemon label differs",
        "owned LaunchDaemon executable differs",
        "LaunchDaemon absence could not be confirmed",
        "offline owned Testnet LaunchDaemon uninstall only",
        "uninstall path is not plain root-owned protected state",
        "owned Testnet binding executable differs",
        "another protected route has an incomplete binding inventory",
        "another protected route has an unknown binding entry",
        "another protected route has an unexpected release reference",
        "unknown installed release entry; uninstall refused",
        "installed release executable identity changed",
        "foreground executable is not one regular file",
        "foreground executable belongs to another installation",
        "foreground release notices differ",
        "installed release entry is not one regular file",
        "foreground notice is not a regular file",
        "foreground release notice identity differs",
    }
)
UNKNOWN = "unknown macOS uninstall failure"
LEGACY = "Owned macOS Testnet uninstall refused; retain state for review"


def failure_reason(stderr: str) -> str:
    """Return only our literals; never retain stderr, suffixes or exception text."""
    admitted = {"install.sh: " + reason: reason for reason in INSTALLER_REFUSALS}
    admitted.update(
        {
            "Owned macOS Testnet uninstall refused: " + reason + "; retain state for review": reason
            for reason in HELPER_REFUSALS
        }
    )
    admitted[LEGACY] = LEGACY
    found = {admitted[line] for line in stderr.splitlines() if line in admitted}
    return next(iter(found)) if len(found) == 1 else UNKNOWN


def prepare_foreground(
    release: Release,
    work: Path,
    env: dict[str, str],
    *,
    binary: Path = Path("/usr/local/bin/zunder-guard"),
) -> str:
    """Remove our signed copy only for the hosted image's two mutable ancestors.

    The service helper still refuses untrusted foreground paths. Do not chown
    shared runner directories or credit this manual cleanup to product uninstall.
    """
    if not binary.exists() and not binary.is_symlink():
        return "absent"
    notices = binary.parent.parent / "share/licenses/zunder-guard"
    mutable = {binary.parent, binary.parent.parent / "share"}
    needs_cleanup = False
    for component in set((*binary.parents, notices, *notices.parents)):
        info = component.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o002:
            raise LifecycleError("hosted foreground ancestor is not a protected directory")
        if info.st_uid != 0 or info.st_mode & 0o022:
            if component not in mutable or info.st_uid not in {0, os.getuid()}:
                raise LifecycleError("unexpected hosted foreground ancestor ownership")
            needs_cleanup = True
    if not needs_cleanup:
        return "product-uninstall"
    # This existing harness operation checks the exact signed binary and all
    # three notices, plain files and link counts before removing only those files.
    remove_macos_paper(release, binary, env=env, work=work)
    return "owned-manual-cleanup-runner-ancestors"


def execute(release: Release, work: Path, env: dict[str, str], log: Path) -> None:
    uninstaller = work / "uninstall-current.sh"
    uninstaller.write_bytes(release.asset("install.sh"))
    reason = UNKNOWN

    def classify(stderr: str) -> str:
        nonlocal reason
        reason = failure_reason(stderr)
        return "unknown"  # The shared runner admits categories, not arbitrary text.

    try:
        run(
            [
                "sudo",
                "sh",
                str(uninstaller),
                "--uninstall",
                "--service-instance",
                "testnet",
                "--non-interactive",
            ],
            env=env,
            log=log,
            timeout=600,
            stdin=b"",
            sensitive_output=True,
            failure_classifier=classify,
        )
    except RunError:
        # install-matrix uploads *.log even when no passing receipt exists.
        with log.open("a") as output:
            output.write("uninstall failure reason: " + reason + "\n")
        raise
