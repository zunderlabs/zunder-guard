import hashlib
import os
from pathlib import Path
from typing import Literal

import pytest

from guard_harness.actions_artifacts import ArtifactError
from guard_harness.staged_subjects import copy


@pytest.fixture
def staging(tmp_path: Path) -> Path:
    staged = tmp_path / "stage"
    staged.mkdir(mode=0o700)
    contents = {
        "i": b"unix",
        "i.ps1": b"windows\r\n",
        "SHA256SUMS.sigstore.json": b"signature",
        "zunder-guard-v1.0.0-rc.1.intoto.jsonl": b"provenance",
    }
    contents["SHA256SUMS"] = "".join(
        f"{hashlib.sha256(contents[name]).hexdigest()}  {name}\n" for name in ("i", "i.ps1")
    ).encode()
    for name, data in contents.items():
        target = staged / name
        target.write_bytes(data)
        target.chmod(0o600)
    return staged


@pytest.mark.parametrize(
    "phase,names",
    [
        (
            "seed",
            {"SHA256SUMS", "SHA256SUMS.sigstore.json", "zunder-guard-v1.0.0-rc.1.intoto.jsonl"},
        ),
        ("subjects", {"i", "i.ps1"}),
    ],
)
def test_exact_seed_and_subject_bytes(
    staging: Path,
    tmp_path: Path,
    phase: Literal["seed", "subjects"],
    names: set[str],
) -> None:
    out = tmp_path / "copied"
    copy(
        staging,
        out,
        tag="v1.0.0-rc.1",
        phase=phase,
        manifest_sha256=hashlib.sha256((staging / "SHA256SUMS").read_bytes()).hexdigest(),
    )
    assert {p.name for p in out.iterdir()} == names
    assert all((out / name).read_bytes() == (staging / name).read_bytes() for name in names)
    assert out.stat().st_mode & 0o777 == 0o700
    assert all((out / name).stat().st_mode & 0o777 == 0o600 for name in names)


def test_tampered_subject_leaves_no_output(staging: Path, tmp_path: Path) -> None:
    (staging / "i.ps1").write_bytes(b"tampered")
    out = tmp_path / "copied"
    with pytest.raises(ArtifactError, match="checksum"):
        copy(
            staging,
            out,
            tag="v1.0.0-rc.1",
            phase="subjects",
            manifest_sha256=hashlib.sha256((staging / "SHA256SUMS").read_bytes()).hexdigest(),
        )
    assert not out.exists()


@pytest.mark.parametrize("change", ["missing", "extra", "symlink", "hardlink", "public"])
def test_unsafe_inventory_refused(staging: Path, tmp_path: Path, change: str) -> None:
    source = staging / "i"
    if change == "missing":
        source.unlink()
    elif change == "extra":
        (staging / "unexpected").write_text("unlisted")
    elif change == "public":
        source.chmod(0o644)
    elif change == "hardlink":
        os.link(source, tmp_path / "linked")
    else:
        source.unlink()
        source.symlink_to(staging / "i.ps1")
    out = tmp_path / "copied"
    with pytest.raises(ArtifactError):
        copy(
            staging,
            out,
            tag="v1.0.0-rc.1",
            phase="subjects",
            manifest_sha256=hashlib.sha256((staging / "SHA256SUMS").read_bytes()).hexdigest(),
        )
    assert not out.exists()


@pytest.mark.parametrize("entry", ["../escape", "i\n", "SHA256SUMS", "i"])
def test_malformed_or_duplicate_checksums_refused(
    staging: Path, tmp_path: Path, entry: str
) -> None:
    sums = staging / "SHA256SUMS"
    sums.write_text(sums.read_text() + f"{'a' * 64}  {entry}\n")
    with pytest.raises(ArtifactError):
        copy(
            staging,
            tmp_path / "copied",
            tag="v1.0.0-rc.1",
            phase="subjects",
            manifest_sha256=hashlib.sha256((staging / "SHA256SUMS").read_bytes()).hexdigest(),
        )


def test_existing_destination_preserved(staging: Path, tmp_path: Path) -> None:
    out = tmp_path / "copied"
    out.mkdir(mode=0o700)
    (out / "operator-file").write_text("preserve")
    with pytest.raises(ArtifactError, match="fresh"):
        copy(staging, out, tag="v1.0.0-rc.1", phase="seed")
    assert (out / "operator-file").read_text() == "preserve"


def test_symlink_staging_ancestor_refused(staging: Path, tmp_path: Path) -> None:
    alias = tmp_path / "alias"
    alias.symlink_to(staging, target_is_directory=True)
    with pytest.raises(ArtifactError):
        copy(alias, tmp_path / "copied", tag="v1.0.0-rc.1", phase="seed")


def test_subjects_require_the_authenticated_seed_digest(staging: Path, tmp_path: Path) -> None:
    with pytest.raises(ArtifactError, match="authenticated seed"):
        copy(staging, tmp_path / "copied", tag="v1.0.0-rc.1", phase="subjects")


def test_replaced_seed_cannot_authorize_changed_subjects(staging: Path, tmp_path: Path) -> None:
    original = hashlib.sha256((staging / "SHA256SUMS").read_bytes()).hexdigest()
    (staging / "i").write_bytes(b"tampered")
    sums = staging / "SHA256SUMS"
    sums.write_text(
        sums.read_text().replace(
            hashlib.sha256(b"unix").hexdigest(), hashlib.sha256(b"tampered").hexdigest()
        )
    )
    with pytest.raises(ArtifactError, match="authenticated seed"):
        copy(
            staging,
            tmp_path / "copied",
            tag="v1.0.0-rc.1",
            phase="subjects",
            manifest_sha256=original,
        )


def test_unsafe_destination_parent_refused(staging: Path, tmp_path: Path) -> None:
    parent = tmp_path / "unsafe"
    parent.mkdir(mode=0o777)
    parent.chmod(0o777)
    with pytest.raises(ArtifactError):
        copy(staging, parent / "copied", tag="v1.0.0-rc.1", phase="seed")
    assert not (parent / "copied").exists()
