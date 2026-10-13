import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from guard_harness import source_installer as source
from guard_harness.testnet_process import ProcessError


@pytest.fixture
def exported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A real local Git export-shaped fixture, never a release or private identifier."""
    root = tmp_path / "repository"
    guard = root / "deploy/guard"
    guard.mkdir(parents=True)
    (guard / "install.sh").write_bytes(b'#!/bin/sh\nVERSION="@VERSION@"\nexit 0\n')

    def git(*args: str) -> str:
        return subprocess.check_output(["git", *args], cwd=root, text=True).strip()

    git("init", "-q")
    git("add", ".")
    tree = git("write-tree")
    message = (
        "Export fixture\n\nZunder-Source: "
        + "1" * 40
        + "\nZunder-Export-Tree: "
        + tree
        + "\nZunder-Export-Manifest: "
        + "2" * 64
    )
    git(
        "-c",
        "user.name=Zunder Labs",
        "-c",
        "user.email=export@zunderlabs.com",
        "commit",
        "-q",
        "-m",
        message,
    )
    head = git("rev-parse", "HEAD")
    monkeypatch.setattr(source, "ROOT", guard)
    for key, value in {
        "SOURCE_INSTALLER_DIAGNOSTIC": "true",
        "GITHUB_SHA": head,
        "CALLER_SHA": head,
        "CALLER_REF": "refs/heads/preview/fixture",
        "CALLER_EVENT": "workflow_dispatch",
        "CALLER_REPOSITORY": "zunderlabs/zunder-guard",
        "WORKFLOW_REF": "zunderlabs/zunder-guard/.github/workflows/install-matrix.yml@"
        "refs/heads/preview/fixture",
        "SCENARIO": "fresh",
        "INSTALL_MATRIX_TARGET": "unix",
        "INSTALL_MATRIX_PROFILE": "all",
        "DIAGNOSTIC": "true",
    }.items():
        monkeypatch.setenv(key, value)
    return guard


def test_exact_git_bound_candidate_changes_only_version_and_never_release_identity(
    exported: Path, tmp_path: Path
) -> None:
    candidate = source.prepare("v1.0.0-rc.14", "a" * 40, scenario="fresh", row="I1")
    assert candidate is not None
    assert candidate.rendered == (exported / "install.sh").read_bytes().replace(
        source.TOKEN, b'VERSION="v1.0.0-rc.14"'
    )
    stage = tmp_path / "stage"
    stage.mkdir(mode=0o700)
    path = candidate.stage(stage)
    assert path.read_bytes() == candidate.rendered and path.stat().st_mode & 0o777 == 0o600
    record = json.loads((stage / "source-installer.json").read_bytes())
    assert record["release_commit"] == "a" * 40
    assert record["installer_harness_commit"] == candidate.harness_commit
    assert record["source_component"] is True and record["gate_eligible"] is False
    assert record["diagnostic"] is True
    path.write_bytes(b"changed source")
    with pytest.raises(ProcessError):
        source.verify_file(path, candidate.digest)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("SOURCE_INSTALLER_DIAGNOSTIC", "1"),
        ("SOURCE_INSTALLER_DIAGNOSTIC", "TRUE"),
        ("CALLER_SHA", "a" * 40),
        ("GITHUB_SHA", "a" * 40),
        ("SCENARIO", "upgrade"),
        ("INSTALL_MATRIX_TARGET", "all"),
        ("INSTALL_MATRIX_PROFILE", "nightly"),
        ("DIAGNOSTIC", "false"),
        ("CALLER_EVENT", "workflow_call"),
        ("CALLER_REPOSITORY", "foreign/repository"),
        (
            "WORKFLOW_REF",
            "zunderlabs/zunder-guard/.github/workflows/verify.yml@refs/heads/preview/fixture",
        ),
    ],
)
def test_other_context_never_admits_source(
    exported: Path, monkeypatch: pytest.MonkeyPatch, key: str, value: str
) -> None:
    monkeypatch.setenv(key, value)
    with pytest.raises(ProcessError):
        source.prepare("v1.0.0-rc.14", "a" * 40, scenario="fresh", row="I1")


@pytest.mark.parametrize("mutation", ["modified", "symlink", "hardlink", "row", "version"])
def test_fixed_git_blob_and_scope_refuse_drift(exported: Path, mutation: str) -> None:
    path = exported / "install.sh"
    if mutation == "modified":
        path.write_bytes(path.read_bytes() + b"extra\n")
    elif mutation == "symlink":
        body = path.read_bytes()
        path.unlink()
        target = exported / "other"
        target.write_bytes(body)
        path.symlink_to(target)
    elif mutation == "hardlink":
        (exported / "alias").hardlink_to(path)
    with pytest.raises(ProcessError):
        source.prepare(
            "bad" if mutation == "version" else "v1.0.0-rc.14",
            "a" * 40,
            scenario="fresh",
            row="I2" if mutation == "row" else "I1",
        )


@pytest.mark.parametrize("flag", [None, "false"])
def test_default_mode_does_not_read_git_or_source(
    monkeypatch: pytest.MonkeyPatch, flag: str | None
) -> None:
    if flag is None:
        monkeypatch.delenv("SOURCE_INSTALLER_DIAGNOSTIC", raising=False)
    else:
        monkeypatch.setenv("SOURCE_INSTALLER_DIAGNOSTIC", flag)

    def forbidden(*args: Any) -> bytes:
        pytest.fail("normal gate read source diagnostic provenance")

    monkeypatch.setattr(source, "git", forbidden)
    assert source.prepare("normal", "normal", scenario="upgrade", row="I2") is None


def test_staged_symlink_and_hardlink_do_not_become_candidate(tmp_path: Path) -> None:
    path = tmp_path / "source.sh"
    path.write_bytes(b"fixture")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    alias = tmp_path / "alias"
    alias.symlink_to(path)
    with pytest.raises(ProcessError):
        source.verify_file(alias, digest)
    alias.unlink()
    alias.hardlink_to(path)
    with pytest.raises(ProcessError):
        source.verify_file(path, digest)


@pytest.mark.parametrize("mutation", ["author", "tree", "duplicate", "missing"])
def test_export_provenance_is_required_not_just_a_claimed_sha(
    exported: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    original = source.git

    def git(*args: str) -> bytes:
        body = original(*args)
        if args[:3] == ("show", "-s", "--format=%an <%ae>%n%cn <%ce>") and mutation == "author":
            return b"foreign author\nforeign author\n"
        if args[:3] == ("show", "-s", "--format=%B"):
            if mutation == "tree":
                lines = body.decode().splitlines()
                body = "\n".join(
                    "Zunder-Export-Tree: " + "0" * 40
                    if line.startswith("Zunder-Export-Tree:")
                    else line
                    for line in lines
                ).encode()
            elif mutation == "duplicate":
                body += b"\nZunder-Source: " + b"1" * 40 + b"\n"
            elif mutation == "missing":
                body = b"Export without trailers\n"
        return body

    monkeypatch.setattr(source, "git", git)
    with pytest.raises(ProcessError):
        source.prepare("v1.0.0-rc.14", "a" * 40, scenario="fresh", row="I1")
