import copy
import hashlib
import stat
import zipfile
from pathlib import Path
from typing import Any

import pytest

from guard_harness.actions_artifacts import ArtifactError, ReleaseAttempt, extract


@pytest.fixture
def metadata() -> tuple[ReleaseAttempt, dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    selected = ReleaseAttempt(11, 22, 3, "a" * 40, "v1.0.0-rc.1")
    repository = {"id": selected.repository_id, "full_name": "zunderlabs/zunder-guard"}
    run = {
        "id": selected.run_id,
        "run_attempt": selected.attempt,
        "head_sha": selected.commit,
        "head_branch": selected.tag,
        "event": "push",
        "path": ".github/workflows/release.yml",
        "status": "completed",
        "conclusion": "success",
        "repository": repository,
        "head_repository": repository,
        "run_started_at": "2026-10-10T10:00:00Z",
        "updated_at": "2026-10-10T10:05:00Z",
    }
    artifact = {
        "id": 33,
        "name": "dist",
        "expired": False,
        "size_in_bytes": 100,
        "digest": "sha256:" + "b" * 64,
        "created_at": "2026-10-10T10:02:00Z",
        "updated_at": "2026-10-10T10:02:00Z",
        "workflow_run": {
            "id": selected.run_id,
            "head_sha": selected.commit,
            "head_branch": selected.tag,
            "repository_id": selected.repository_id,
            "head_repository_id": selected.repository_id,
        },
    }
    jobs = [
        {
            "name": "package",
            "run_id": selected.run_id,
            "run_attempt": selected.attempt,
            "status": "completed",
            "conclusion": "success",
            "started_at": "2026-10-10T10:01:00Z",
            "completed_at": "2026-10-10T10:03:00Z",
        }
    ]
    return selected, run, artifact, jobs


def test_current_repository_attempt_and_job_bind(metadata: Any) -> None:
    selected, run, artifact, jobs = metadata
    assert selected.artifact(artifact, run, jobs, name="dist", job_name="package") == (
        33,
        "b" * 64,
        100,
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("run_attempt", 2),
        ("head_sha", "c" * 40),
        ("head_branch", "main"),
        ("event", "pull_request"),
        ("path", ".github/workflows/other.yml"),
        ("status", "in_progress"),
        ("conclusion", "failure"),
        ("updated_at", "2026-10-10T09:00:00Z"),
    ],
)
def test_changed_run_refused(metadata: Any, field: str, value: Any) -> None:
    selected, run, artifact, jobs = metadata
    run[field] = value
    with pytest.raises(ArtifactError):
        selected.artifact(artifact, run, jobs, name="dist", job_name="package")


@pytest.mark.parametrize(
    "field,value",
    [
        ("expired", True),
        ("id", True),
        ("name", "other"),
        ("digest", "sha256:wrong"),
        ("size_in_bytes", 0),
        ("updated_at", "2026-10-10T10:04:00Z"),
        ("created_at", "2026-10-10T10:06:00Z"),
    ],
)
def test_changed_artifact_refused(metadata: Any, field: str, value: Any) -> None:
    selected, run, artifact, jobs = metadata
    artifact[field] = value
    with pytest.raises(ArtifactError):
        selected.artifact(artifact, run, jobs, name="dist", job_name="package")


def test_archive_repository_and_fork_are_refused(metadata: Any) -> None:
    selected, run, artifact, jobs = metadata
    run["head_repository"] = {"id": selected.repository_id, "full_name": "other/fork"}
    with pytest.raises(ArtifactError):
        selected.artifact(artifact, run, jobs, name="dist", job_name="package")
    run["head_repository"] = {"id": 99, "full_name": "zunderlabs/zunder-guard"}
    with pytest.raises(ArtifactError):
        selected.artifact(artifact, run, jobs, name="dist", job_name="package")


def test_rerun_and_ambiguous_jobs_refused(metadata: Any) -> None:
    selected, run, artifact, jobs = metadata
    jobs[0]["run_attempt"] -= 1
    with pytest.raises(ArtifactError):
        selected.artifact(artifact, run, jobs, name="dist", job_name="package")
    jobs[0]["run_attempt"] = selected.attempt
    jobs.append(copy.deepcopy(jobs[0]))
    with pytest.raises(ArtifactError):
        selected.artifact(artifact, run, jobs, name="dist", job_name="package")


def carrier(tmp_path: Path, entries: list[tuple[str, int, bytes]]) -> Path:
    path = tmp_path / "carrier.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, mode, data in entries:
            item = zipfile.ZipInfo(name)
            item.create_system = 3
            item.external_attr = mode << 16
            archive.writestr(item, data)
    return path


def unpack(path: Path, destination: Path, names: set[str]) -> None:
    extract(
        path,
        destination,
        digest=hashlib.sha256(path.read_bytes()).hexdigest(),
        size=path.stat().st_size,
        names=names,
    )


def test_extracts_exact_bytes_privately(tmp_path: Path) -> None:
    path = carrier(
        tmp_path,
        [("i", stat.S_IFREG | 0o644, b"loader"), ("i.ps1", stat.S_IFREG | 0o644, b"windows\r\n")],
    )
    out = tmp_path / "subjects"
    unpack(path, out, {"i", "i.ps1"})
    assert (out / "i.ps1").read_bytes() == b"windows\r\n"
    assert stat.S_IMODE(out.stat().st_mode) == 0o700
    assert stat.S_IMODE((out / "i").stat().st_mode) == 0o600


@pytest.mark.parametrize(
    "name,mode",
    [
        ("../escape", stat.S_IFREG),
        ("/escape", stat.S_IFREG),
        ("dir/file", stat.S_IFREG),
        ("i", stat.S_IFLNK),
        ("i", stat.S_IFDIR),
        ("i", stat.S_IFIFO),
    ],
)
def test_unsafe_members_leave_no_subjects(tmp_path: Path, name: str, mode: int) -> None:
    path = carrier(tmp_path, [(name, mode, b"not-a-subject")])
    out = tmp_path / "subjects"
    with pytest.raises(ArtifactError):
        unpack(path, out, {name})
    assert not out.exists()


def test_missing_extra_duplicate_and_case_colliding_members_refused(tmp_path: Path) -> None:
    path = carrier(tmp_path, [("i", stat.S_IFREG, b"one"), ("I", stat.S_IFREG, b"two")])
    for names in [{"i"}, {"i", "I"}, {"missing"}]:
        with pytest.raises(ArtifactError):
            unpack(path, tmp_path / "subjects", names)


def test_changed_transport_digest_and_existing_destination_refused(tmp_path: Path) -> None:
    path = carrier(tmp_path, [("i", stat.S_IFREG, b"loader")])
    out = tmp_path / "subjects"
    with pytest.raises(ArtifactError):
        extract(path, out, digest="f" * 64, size=path.stat().st_size, names={"i"})
    out.mkdir()
    sentinel = out / "sentinel"
    sentinel.write_text("preserve")
    with pytest.raises(ArtifactError):
        unpack(path, out, {"i"})
    assert sentinel.read_text() == "preserve"


def test_declared_expansion_limit_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import guard_harness.actions_artifacts as transport

    path = carrier(tmp_path, [("i", stat.S_IFREG, b"loader")])
    monkeypatch.setattr(transport, "MAX_FILE", 2)
    with pytest.raises(ArtifactError):
        unpack(path, tmp_path / "subjects", {"i"})
    assert not (tmp_path / "subjects").exists()


def test_corrupt_crc_leaves_no_partial_subjects(tmp_path: Path) -> None:
    path = carrier(tmp_path, [("i", stat.S_IFREG, b"loader")])
    path.write_bytes(path.read_bytes().replace(b"loader", b"broken"))
    with pytest.raises(ArtifactError):
        unpack(path, tmp_path / "subjects", {"i"})
    assert not (tmp_path / "subjects").exists()


def test_extraction_uses_the_hashed_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = carrier(tmp_path, [("i", stat.S_IFREG, b"loader")])
    captured = path.read_bytes()
    digest = hashlib.sha256(captured).hexdigest()
    sha256 = hashlib.sha256

    def replacing(data: bytes) -> Any:
        result = sha256(data)
        path.write_bytes(b"replaced source after capture")
        return result

    monkeypatch.setattr(hashlib, "sha256", replacing)
    out = tmp_path / "subjects"
    extract(path, out, digest=digest, size=len(captured), names={"i"})
    assert (out / "i").read_bytes() == b"loader"
