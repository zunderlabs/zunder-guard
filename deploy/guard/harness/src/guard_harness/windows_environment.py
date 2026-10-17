"""The environment native installer children keep: exact names plus Windows locations.

Python reports Windows environment names in upper case; callers compare `name.upper()`.
Only OS, profile, program and module locations: never a key, token, secret, wallet or
ZUNDER_ setting (tests/test_windows_policy.py pins both).
"""

WINDOWS_LOCATIONS = frozenset(
    {
        # Windows resolves the machine folders (ProgramData, Program Files) from these:
        # without them Windows PowerShell 5.1's GetFolderPath('CommonApplicationData') is
        # empty and the protected service installer failed before its first step (rc.1 I4,
        # ArgumentException; the M1 route, which keeps the whole environment, passed).
        "ALLUSERSPROFILE",
        "SYSTEMDRIVE",
        "PUBLIC",
        "COMMONPROGRAMFILES",
        "COMMONPROGRAMFILES(X86)",
        "COMMONPROGRAMW6432",
        # PowerShell needs these to run a downloaded .exe and to load its own modules
        # (rc.16: "Cannot run a document in the middle of a pipeline" without PATHEXT).
        "APPDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "PROGRAMW6432",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "PSMODULEPATH",
    }
)

# The names native_run passes to every installer child on any OS (exact spelling).
INSTALLER_NAMES = frozenset(
    {
        "PATH",
        "HOME",
        "USERPROFILE",
        "LOCALAPPDATA",
        "ProgramData",
        "ProgramFiles",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "SystemRoot",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "LANG",
        "GITHUB_ACTIONS",
        "RUNNER_ENVIRONMENT",
        "INSTALL_MATRIX_PROFILE",
        "DIAGNOSTIC",
        # The harness source identity every receipt records (rc.17: without it the
        # upgrade's Homebrew M2 receipt had an empty harness_commit and M2 refused).
        "GITHUB_SHA",
    }
)


def windows_installer_names() -> list[str]:
    """Every name a Windows installer child keeps, upper case as Windows Python reports it.

    deploy/guard/test/windows-scm-diagnostic.ps1 runs the released loader with exactly
    these (`python -m guard_harness.windows_environment`), so the gate environment is
    proven without the testnet account.
    """
    return sorted({name.upper() for name in INSTALLER_NAMES} | WINDOWS_LOCATIONS)


if __name__ == "__main__":
    print("\n".join(windows_installer_names()))
