#!/usr/bin/env python3
"""Offline removal of the owned Testnet LaunchDaemon; retained custody/state is untouched."""

import sys

sys.dont_write_bytecode = True

import hashlib
import json
import os
import plistlib
import re
import stat
import subprocess
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Set


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
        "foreground copy changed during removal",
    }
)
# Read from the signed release asset by the release gate: this helper itself removes a
# verified foreground copy from a /usr/local whose bin or share others may write.
CAPABILITIES = frozenset({"writable-usr-local-foreground"})
# The only ancestors of the foreground copy that someone other than root may write: Homebrew
# owns them on Intel Macs, and GitHub's macOS image makes them runner-owned. Every other
# ancestor must be root-owned and writable by root only, and none may be world-writable.
MUTABLE_FOREGROUND = frozenset({Path("/usr/local/bin"), Path("/usr/local/share")})
DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
# O_NONBLOCK: a FIFO put in a file's place cannot stall the uninstall before it is refused.
FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
NOTICES = ("LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.md")


class UninstallRefused(RuntimeError):
    """A fixed refusal that is safe to retain without paths or private state."""


class NotPlainFile(RuntimeError):
    """An installed file's name holds a link, a hard-linked, foreign or writable file."""


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


def ownership(fd: int) -> os.stat_result:
    """Owner and mode of an open entry for admission (tests model root ownership here)."""
    return os.fstat(fd)


def open_directory(path: Path, mutable: FrozenSet[Path]) -> Optional[int]:
    """Open `path` one component at a time from /, never following a link; None if absent.

    Each step opens the next name relative to the descriptor admitted before it, so renaming
    or replacing an entry in a directory someone else can write (Homebrew's /usr/local/bin)
    never redirects the walk, and every later read, check and removal acts on descriptors.
    """
    fd = os.open("/", DIRECTORY)
    current = Path("/")
    try:
        while True:
            info = ownership(fd)
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_mode & 0o002
                or (
                    current not in mutable
                    and (info.st_uid != 0 or info.st_mode & 0o022)
                )
            ):
                raise UninstallRefused(
                    "uninstall path is not plain root-owned protected state"
                )
            if current == path:
                return fd
            name = path.parts[len(current.parts)]
            try:
                child = os.open(name, DIRECTORY, dir_fd=fd)
            except FileNotFoundError:
                os.close(fd)
                return None
            except OSError:  # a link (ELOOP) or not a directory (ENOTDIR)
                raise UninstallRefused(
                    "uninstall path is not plain root-owned protected state"
                ) from None
            os.close(fd)
            fd, current = child, current / name
    except BaseException:
        os.close(fd)
        raise


def open_child_directory(parent: int, name: str) -> Optional[int]:
    """Open one root-protected directory relative to an admitted one; None if absent."""
    try:
        fd = os.open(name, DIRECTORY, dir_fd=parent)
    except FileNotFoundError:
        return None
    except OSError:
        raise UninstallRefused(
            "uninstall path is not plain root-owned protected state"
        ) from None
    info = ownership(fd)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        os.close(fd)
        raise UninstallRefused("uninstall path is not plain root-owned protected state")
    return fd


def open_file(parent: int, name: str) -> Optional[int]:
    """Open one installed file: regular, one link, root-owned, writable by root only."""
    try:
        fd = os.open(name, FILE, dir_fd=parent)
    except FileNotFoundError:
        return None
    except OSError:  # a link (ELOOP), or nothing a plain file could be
        raise NotPlainFile() from None
    info, owner = os.fstat(fd), ownership(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or owner.st_uid != 0
        or owner.st_mode & 0o022
    ):
        os.close(fd)
        raise NotPlainFile()
    return fd


def contents(fd: int) -> bytes:
    chunks: List[bytes] = []
    offset = 0
    while True:
        chunk = os.pread(fd, 1 << 20, offset)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        offset += len(chunk)


def same_entry(parent: int, name: str, fd: int) -> None:
    """Refuse unless `name` in `parent` still names the very inode held open as `fd`."""
    held = os.fstat(fd)
    try:
        entry = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        raise UninstallRefused("foreground copy changed during removal") from None
    if (entry.st_dev, entry.st_ino) != (held.st_dev, held.st_ino):
        raise UninstallRefused("foreground copy changed during removal")


class Foreground:
    """The convenience copy install.sh put in /usr/local, verified and held open.

    The executable hashes to a release this uninstall removes and the notices equal that
    release's bytes. Removal unlinks by name relative to the held directories, and only
    while each name still refers to the inode that was verified.
    """

    def __init__(self) -> None:
        self.fds: List[int] = []
        self.bin_dir = self.binary = self.licences = self.notice_dir = -1
        self.notices: Dict[str, int] = {}

    def hold(self, fd: int) -> int:
        self.fds.append(fd)
        return fd

    def close(self) -> None:
        for fd in self.fds:
            os.close(fd)
        self.fds = []

    def remove(self, generic: Path, notices: Path) -> None:
        # The one entry in a directory others may write: unlink it only while it is still
        # the verified inode, then confirm that inode has no name left anywhere.
        same_entry(self.bin_dir, generic.name, self.binary)
        os.unlink(generic.name, dir_fd=self.bin_dir)
        if os.fstat(self.binary).st_nlink != 0:
            raise UninstallRefused("foreground copy changed during removal")
        # The notice directory and licenses/ are root-owned and writable by root only.
        for name, fd in self.notices.items():
            same_entry(self.notice_dir, name, fd)
            os.unlink(name, dir_fd=self.notice_dir)
        same_entry(self.licences, notices.name, self.notice_dir)
        os.rmdir(notices.name, dir_fd=self.licences)


def verify_foreground(
    generic: Path, notices: Path, digests: FrozenSet[str], base: Path
) -> Optional[Foreground]:
    """Verify the foreground copy and its notices; None when no copy is installed."""
    if not generic.exists():
        return None  # as before: nothing installed there, so its ancestors are not judged
    held = Foreground()
    try:
        bin_dir = open_directory(generic.parent, MUTABLE_FOREGROUND)
        if bin_dir is None:
            return None
        held.bin_dir = held.hold(bin_dir)
        try:
            binary = open_file(held.bin_dir, generic.name)
        except NotPlainFile:
            raise UninstallRefused(
                "foreground executable is not one regular file"
            ) from None
        if binary is None:
            held.close()
            return None
        held.binary = held.hold(binary)
        digest = hashlib.sha256(contents(held.binary)).hexdigest()
        if digest not in digests:
            raise UninstallRefused(
                "foreground executable belongs to another installation"
            )
        licences = open_directory(notices.parent, MUTABLE_FOREGROUND)
        if licences is None:
            raise UninstallRefused("foreground release notices differ")
        held.licences = held.hold(licences)
        notice_dir = open_child_directory(held.licences, notices.name)
        if notice_dir is None:
            raise UninstallRefused("foreground release notices differ")
        held.notice_dir = held.hold(notice_dir)
        if sorted(os.listdir(held.notice_dir)) != sorted(NOTICES):
            raise UninstallRefused("foreground release notices differ")
        for name in NOTICES:
            try:
                fd = open_file(held.notice_dir, name)
            except NotPlainFile:
                raise UninstallRefused("foreground notice is not a regular file") from None
            if fd is None:
                raise UninstallRefused("foreground release notices differ")
            held.notices[name] = held.hold(fd)
            if contents(fd) != (base / "releases" / digest / name).read_bytes():
                raise UninstallRefused("foreground release notice identity differs")
        return held
    except BaseException:
        held.close()
        raise


def remove(base: Path, plist: Path, generic: Path, notices: Path) -> None:
    if os.geteuid() != 0:
        raise UninstallRefused("Testnet uninstall requires root")
    trusted(base)
    helper = base / "management/uninstall-testnet.py"
    trusted(helper)
    bindings = base / "bindings-testnet"
    trusted(bindings)
    releases: Set[Path] = set()
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
    retained: Set[Path] = set()
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
    names = {"zunder-guard", *NOTICES}
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
    # The foreground copy is checked before anything is stopped, and held open until removed.
    foreground = verify_foreground(
        generic, notices, frozenset(p.name for p in releases), base
    )
    try:
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
        # Before the registration and releases go: a refusal here leaves an uninstall that
        # can simply be run again.
        if foreground is not None and not retained:
            foreground.remove(generic, notices)
    finally:
        if foreground is not None:
            foreground.close()
    plist.unlink()
    for release in releases - retained:
        if release.exists():
            for path in release.iterdir():
                path.unlink()
            release.rmdir()
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
