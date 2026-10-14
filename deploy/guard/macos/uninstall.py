#!/usr/bin/env python3
"""Offline removal of the owned Testnet LaunchDaemon; retained custody/state is untouched."""

import sys

sys.dont_write_bytecode = True

import hashlib
import json
import os
import plistlib
import re
import subprocess
from pathlib import Path


FIXED_REFUSALS = frozenset(
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


class UninstallRefused(RuntimeError):
    """A fixed refusal that is safe to retain without paths or private state."""


def refusal_message(error: Exception) -> str:
    prefix = "Owned macOS Testnet uninstall refused"
    if type(error) is UninstallRefused and str(error) in FIXED_REFUSALS:
        return prefix + ": " + str(error) + "; retain state for review"
    return prefix + "; retain state for review"


def trusted(path: Path) -> None:
    for component in (path, *path.parents):
        stat = component.lstat()
        if component.is_symlink() or stat.st_uid != 0 or stat.st_mode & 0o022:
            raise UninstallRefused(
                "uninstall path is not plain root-owned protected state"
            )


def remove(base: Path, plist: Path, generic: Path, notices: Path) -> None:
    if os.geteuid() != 0:
        raise UninstallRefused("Testnet uninstall requires root")
    trusted(base)
    helper = base / "management/uninstall-testnet.py"
    trusted(helper)
    bindings = base / "bindings-testnet"
    trusted(bindings)
    releases: set[Path] = set()
    for binding in bindings.glob("*.json"):
        trusted(binding)
        value = json.loads(binding.read_bytes())
        executable = Path(value["executable"])
        release = executable.parent
        if (
            executable.name != "zunder-guard"
            or release.parent != base / "releases"
            or not re.fullmatch(r"[0-9a-f]{64}", release.name)
        ):
            raise UninstallRefused("owned Testnet binding executable differs")
        releases.add(release)
    if not releases:
        raise UninstallRefused("owned Testnet release inventory missing")
    retained: set[Path] = set()
    other_bindings = base / "bindings"
    others = []
    if other_bindings.exists() or other_bindings.is_symlink():
        trusted(other_bindings)
        if not other_bindings.is_dir():
            raise UninstallRefused(
                "another protected route has an incomplete binding inventory"
            )
        others = list(other_bindings.iterdir())
    for other in others:
        if other.suffix != ".json" or not other.is_file():
            raise UninstallRefused(
                "another protected route has an unknown binding entry"
            )
        trusted(other)
        executable = Path(json.loads(other.read_bytes())["executable"])
        if (
            executable.name != "zunder-guard"
            or executable.parent.parent != base / "releases"
            or not re.fullmatch(r"[0-9a-f]{64}", executable.parent.name)
        ):
            raise UninstallRefused(
                "another protected route has an unexpected release reference"
            )
        retained.add(executable.parent)
    names = {"zunder-guard", "LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.md"}
    for release in releases:
        if not release.exists():
            continue  # An earlier recorded release may already have been removed.
        trusted(release)
        entries = list(release.iterdir())
        if {path.name for path in entries} != names:
            raise UninstallRefused("unknown installed release entry; uninstall refused")
        for path in entries:
            trusted(path)
            if not path.is_file() or path.stat().st_nlink != 1:
                raise UninstallRefused(
                    "installed release entry is not one regular file"
                )
        if (
            hashlib.sha256((release / "zunder-guard").read_bytes()).hexdigest()
            != release.name
        ):
            raise UninstallRefused("installed release executable identity changed")
    trusted(plist)
    registration = plistlib.loads(plist.read_bytes())
    if registration.get("Label") != "com.zunderlabs.guard.testnet-native":
        raise UninstallRefused("owned LaunchDaemon label differs")
    active = bindings / "active.json"
    trusted(active)
    active_executable = Path(json.loads(active.read_bytes())["executable"])
    words = registration.get("ProgramArguments")
    if (
        words != [str(active_executable), "service", "run", "--binding", str(active)]
        or active_executable.parent not in releases
    ):
        raise UninstallRefused("owned LaunchDaemon executable differs")
    generic_owned = False
    if generic.exists():
        trusted(generic)
        if not generic.is_file() or generic.stat().st_nlink != 1:
            raise UninstallRefused("foreground executable is not one regular file")
        digest = hashlib.sha256(generic.read_bytes()).hexdigest()
        generic_owned = digest in {p.name for p in releases}
        if not generic_owned:
            raise UninstallRefused(
                "foreground executable belongs to another installation"
            )
        trusted(notices)
        if {p.name for p in notices.iterdir()} != names - {"zunder-guard"}:
            raise UninstallRefused("foreground release notices differ")
        for path in notices.iterdir():
            trusted(path)
            if not path.is_file() or path.stat().st_nlink != 1:
                raise UninstallRefused("foreground notice is not a regular file")
            if (
                path.read_bytes()
                != (base / "releases" / digest / path.name).read_bytes()
            ):
                raise UninstallRefused("foreground release notice identity differs")
    subprocess.run(
        ["/bin/launchctl", "bootout", "system/com.zunderlabs.guard.testnet-native"],
        capture_output=True,
        check=False,
        timeout=30,
    )
    probe = subprocess.run(
        ["/bin/launchctl", "print", "system/com.zunderlabs.guard.testnet-native"],
        capture_output=True,
        check=False,
        timeout=30,
    )
    if probe.returncode != 113:
        raise UninstallRefused("LaunchDaemon absence could not be confirmed")
    plist.unlink()
    for release in releases - retained:
        if release.exists():
            for path in release.iterdir():
                path.unlink()
            release.rmdir()
    if generic_owned and not retained:
        generic.unlink()
        for path in notices.iterdir():
            path.unlink()
        notices.rmdir()
    # Binding history, journals, config, service identity and Keychain custody are data.
    helper.unlink()
    if not any(helper.parent.iterdir()):
        helper.parent.rmdir()


def main() -> None:
    if sys.argv[1:] != ["--network", "testnet"] or sys.platform != "darwin":
        raise UninstallRefused("offline owned Testnet LaunchDaemon uninstall only")
    remove(
        Path("/Library/Application Support/Zunder Guard"),
        Path("/Library/LaunchDaemons/com.zunderlabs.guard.testnet-native.plist"),
        Path("/usr/local/bin/zunder-guard"),
        Path("/usr/local/share/licenses/zunder-guard"),
    )


if __name__ == "__main__":
    try:
        main()
    except (
        OSError,
        ValueError,
        KeyError,
        RuntimeError,
        subprocess.SubprocessError,
    ) as error:
        raise SystemExit(refusal_message(error)) from None
