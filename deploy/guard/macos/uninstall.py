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


def trusted(path: Path) -> None:
    for component in (path, *path.parents):
        stat = component.lstat()
        if component.is_symlink() or stat.st_uid != 0 or stat.st_mode & 0o022:
            raise RuntimeError("uninstall path is not plain root-owned protected state")


def remove(base: Path, plist: Path, generic: Path, notices: Path) -> None:
    if os.geteuid() != 0:
        raise RuntimeError("Testnet uninstall requires root")
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
            raise RuntimeError("owned Testnet binding executable differs")
        releases.add(release)
    if not releases:
        raise RuntimeError("owned Testnet release inventory missing")
    retained: set[Path] = set()
    other_bindings = base / "bindings"
    others = []
    if other_bindings.exists() or other_bindings.is_symlink():
        trusted(other_bindings)
        if not other_bindings.is_dir():
            raise RuntimeError("another protected route has an incomplete binding inventory")
        others = list(other_bindings.iterdir())
    for other in others:
        if other.suffix != ".json" or not other.is_file():
            raise RuntimeError("another protected route has an unknown binding entry")
        trusted(other)
        executable = Path(json.loads(other.read_bytes())["executable"])
        if (
            executable.name != "zunder-guard"
            or executable.parent.parent != base / "releases"
            or not re.fullmatch(r"[0-9a-f]{64}", executable.parent.name)
        ):
            raise RuntimeError("another protected route has an unexpected release reference")
        retained.add(executable.parent)
    names = {"zunder-guard", "LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.md"}
    for release in releases:
        if not release.exists():
            continue  # An earlier recorded release may already have been removed.
        trusted(release)
        entries = list(release.iterdir())
        if {path.name for path in entries} != names:
            raise RuntimeError("unknown installed release entry; uninstall refused")
        for path in entries:
            trusted(path)
            if not path.is_file() or path.stat().st_nlink != 1:
                raise RuntimeError("installed release entry is not one regular file")
        if hashlib.sha256((release / "zunder-guard").read_bytes()).hexdigest() != release.name:
            raise RuntimeError("installed release executable identity changed")
    trusted(plist)
    registration = plistlib.loads(plist.read_bytes())
    if registration.get("Label") != "com.zunderlabs.guard.testnet-native":
        raise RuntimeError("owned LaunchDaemon label differs")
    active = bindings / "active.json"
    trusted(active)
    active_executable = Path(json.loads(active.read_bytes())["executable"])
    words = registration.get("ProgramArguments")
    if (
        words != [str(active_executable), "service", "run", "--binding", str(active)]
        or active_executable.parent not in releases
    ):
        raise RuntimeError("owned LaunchDaemon executable differs")
    generic_owned = False
    if generic.exists():
        trusted(generic)
        if not generic.is_file() or generic.stat().st_nlink != 1:
            raise RuntimeError("foreground executable is not one regular file")
        digest = hashlib.sha256(generic.read_bytes()).hexdigest()
        generic_owned = digest in {p.name for p in releases}
        if not generic_owned:
            raise RuntimeError("foreground executable belongs to another installation")
        trusted(notices)
        if {p.name for p in notices.iterdir()} != names - {"zunder-guard"}:
            raise RuntimeError("foreground release notices differ")
        for path in notices.iterdir():
            trusted(path)
            if not path.is_file() or path.stat().st_nlink != 1:
                raise RuntimeError("foreground notice is not a regular file")
            if path.read_bytes() != (base / "releases" / digest / path.name).read_bytes():
                raise RuntimeError("foreground release notice identity differs")
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
        raise RuntimeError("LaunchDaemon absence could not be confirmed")
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
        raise RuntimeError("offline owned Testnet LaunchDaemon uninstall only")
    remove(
        Path("/Library/Application Support/Zunder Guard"),
        Path("/Library/LaunchDaemons/com.zunderlabs.guard.testnet-native.plist"),
        Path("/usr/local/bin/zunder-guard"),
        Path("/usr/local/share/licenses/zunder-guard"),
    )


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError):
        raise SystemExit("Owned macOS Testnet uninstall refused; retain state for review") from None
