"""Copy exact staged subjects into private verification workspaces; no admission credit."""

import hashlib
import os
import re
import stat
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Literal

from guard_harness.actions_artifacts import MAX_FILE, ArtifactError


def _private(path: Path, *, directory: bool = False) -> None:
    if not path.is_absolute() or ".." in path.parts:
        raise ArtifactError("absolute private staging path required")
    owner = os.geteuid()
    for ancestor in reversed(path.parents):
        info = ancestor.lstat()
        mode = stat.S_IMODE(info.st_mode)
        sticky_root = info.st_uid == 0 and bool(mode & stat.S_ISVTX)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid not in (0, owner)
            or (mode & 0o022 and not sticky_root)
        ):
            raise ArtifactError("staging ancestor is unsafe")
    info = path.lstat()
    regular = (
        stat.S_ISDIR(info.st_mode)
        if directory
        else stat.S_ISREG(info.st_mode) and info.st_nlink == 1
    )
    if info.st_uid != owner or stat.S_IMODE(info.st_mode) & 0o077 or not regular:
        raise ArtifactError("staging path must be private and owned")


def copy(
    staged: Path,
    destination: Path,
    *,
    tag: str,
    phase: Literal["seed", "subjects"],
    manifest_sha256: str | None = None,
) -> None:
    """Copy one snapshot after verifying its private inventory and subject hashes.

    Seed contains checksums, its signature and SLSA provenance. Subjects are copied
    only after the caller authenticates that seed. Matching unsigned hashes alone
    does not grant signature/provenance credit. No output survives a partial copy.
    """
    if phase not in {"seed", "subjects"} or not re.fullmatch(
        r"v\d+\.\d+\.\d+(?:-rc\.[1-9]\d*)?", tag
    ):
        raise ArtifactError("staging phase or release tag refused")
    _private(staged, directory=True)
    _private(destination.parent, directory=True)
    if destination.exists() or destination.is_symlink():
        raise ArtifactError("fresh staging destination required")
    manifest = staged / "SHA256SUMS"
    _private(manifest)
    if not 0 < manifest.stat().st_size <= 65536:
        raise ArtifactError("staged checksum manifest size refused")
    with manifest.open("rb") as stream:
        captured_manifest = stream.read(65537)
    if not 0 < len(captured_manifest) <= 65536:
        raise ArtifactError("staged checksum manifest size refused")
    if phase == "subjects" and hashlib.sha256(captured_manifest).hexdigest() != manifest_sha256:
        raise ArtifactError("staged checksum manifest differs from authenticated seed")
    entries: dict[str, str] = {}
    try:
        for line in captured_manifest.decode("utf-8").splitlines():
            match = re.fullmatch(r"([0-9a-f]{64}) [ *]([A-Za-z0-9][A-Za-z0-9._-]*)", line)
            if match is None or ".." in match[2] or match[2] in entries:
                raise ArtifactError("staged checksum manifest entry refused")
            entries[match[2]] = match[1]
    except UnicodeError:
        raise ArtifactError("staged checksum manifest encoding refused") from None
    seed = {"SHA256SUMS", "SHA256SUMS.sigstore.json", f"zunder-guard-{tag}.intoto.jsonl"}
    if (
        not 0 < len(entries) <= 61
        or seed.intersection(entries)
        or {path.name for path in staged.iterdir()} != seed | entries.keys()
    ):
        raise ArtifactError("staged subject inventory differs")
    names = seed if phase == "seed" else entries.keys()
    with TemporaryDirectory(prefix="guard-subjects-", dir=destination.parent) as directory:
        output = Path(directory) / "subjects"
        output.mkdir(mode=0o700)
        for name in sorted(names):
            source = staged / name
            _private(source)
            if name == "SHA256SUMS":
                data = captured_manifest
            else:
                with source.open("rb") as stream:
                    data = stream.read(MAX_FILE + 1)
            if not 0 < len(data) <= MAX_FILE:
                raise ArtifactError("staged subject size refused")
            if phase == "subjects" and hashlib.sha256(data).hexdigest() != entries[name]:
                raise ArtifactError("staged subject checksum differs")
            target = output / name
            with target.open("xb") as sink:
                target.chmod(0o600)
                sink.write(data)
        output.rename(destination)
