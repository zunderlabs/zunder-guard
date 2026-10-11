"""Bind downloaded Actions artifacts to an exact attempt; not release admission."""

import hashlib
import io
import re
import stat
import zipfile
from collections.abc import Mapping, Sequence, Set
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

MAX_ZIP = 128 * 1024 * 1024
MAX_FILE = MAX_ZIP
MAX_TOTAL = 256 * 1024 * 1024


class ArtifactError(ValueError):
    """Artifact identity, transport or extraction differs from the selected build."""


def _need(condition: bool) -> None:
    if not condition:
        raise ArtifactError("Actions artifact scope or bytes refused")


def _time(value: Any) -> datetime:
    _need(isinstance(value, str) and bool(re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value)))
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ArtifactError("Actions timestamp refused") from None


@dataclass(frozen=True)
class ReleaseAttempt:
    # Repository ID comes from the current canonical repository API, never a prior repo's ID.
    repository_id: int
    run_id: int
    attempt: int
    commit: str
    tag: str

    def window(self, run: Mapping[str, Any]) -> tuple[datetime, datetime]:
        _need(
            all(
                type(value) is int and value > 0
                for value in (self.repository_id, self.run_id, self.attempt)
            )
        )
        _need(
            bool(re.fullmatch(r"[0-9a-f]{40}", self.commit))
            and bool(re.fullmatch(r"v\d+\.\d+\.\d+(?:-rc\.[1-9]\d*)?", self.tag))
        )
        _need(
            run.get("id") == self.run_id
            and run.get("run_attempt") == self.attempt
            and run.get("head_sha") == self.commit
            and run.get("head_branch") == self.tag
            and run.get("event") == "push"
            and run.get("path") == ".github/workflows/release.yml"
            and run.get("status") == "completed"
            and run.get("conclusion") == "success"
        )
        for name in ("repository", "head_repository"):
            repository = run.get(name)
            if not isinstance(repository, dict):
                raise ArtifactError("Actions repository metadata refused")
            _need(
                repository.get("id") == self.repository_id
                and repository.get("full_name") == "zunderlabs/zunder-guard"
            )
        start, end = _time(run.get("run_started_at")), _time(run.get("updated_at"))
        _need(start <= end)
        return start, end

    def artifact(
        self,
        value: Mapping[str, Any],
        run: Mapping[str, Any],
        jobs: Sequence[Mapping[str, Any]],
        *,
        name: str,
        job_name: str,
    ) -> tuple[int, str, int]:
        start, end = self.window(run)
        artifact_id, size, digest = value.get("id"), value.get("size_in_bytes"), value.get("digest")
        if type(artifact_id) is not int or type(size) is not int or not isinstance(digest, str):
            raise ArtifactError("Actions artifact metadata types refused")
        _need(
            type(artifact_id) is int
            and artifact_id > 0
            and value.get("name") == name
            and value.get("expired") is False
            and type(size) is int
            and 0 < size <= MAX_ZIP
            and isinstance(digest, str)
            and bool(re.fullmatch(r"sha256:[0-9a-f]{64}", digest))
        )
        scope = value.get("workflow_run")
        if not isinstance(scope, dict):
            raise ArtifactError("Actions artifact run metadata refused")
        _need(
            scope.get("id") == self.run_id
            and scope.get("head_sha") == self.commit
            and scope.get("head_branch") == self.tag
            and scope.get("repository_id") == self.repository_id
            and scope.get("head_repository_id") == self.repository_id
        )
        created = _time(value.get("created_at"))
        _need(start <= created == _time(value.get("updated_at")) <= end)
        matches = [job for job in jobs if job.get("name") == job_name]
        _need(len(matches) == 1)
        job = matches[0]
        _need(
            job.get("run_id") == self.run_id
            and job.get("run_attempt") == self.attempt
            and job.get("status") == "completed"
            and job.get("conclusion") == "success"
            and _time(job.get("started_at")) <= created <= _time(job.get("completed_at"))
        )
        return artifact_id, digest.removeprefix("sha256:"), size


def extract(
    archive: Path,
    destination: Path,
    *,
    digest: str,
    size: int,
    names: Set[str],
) -> None:
    """Extract a complete bounded carrier into a fresh private directory.

    Expected digest/size come from authenticated API metadata. Extracting bytes
    grants no Sigstore/provenance credit; verify before execution or publication.
    """
    _need(bool(re.fullmatch(r"[0-9a-f]{64}", digest)) and 0 < size <= MAX_ZIP)
    _need(not archive.is_symlink() and archive.is_file())
    with archive.open("rb") as stream:
        captured = stream.read(MAX_ZIP + 1)
    _need(len(captured) == size and hashlib.sha256(captured).hexdigest() == digest)
    with io.BytesIO(captured) as stream:
        try:
            with zipfile.ZipFile(stream) as carrier:
                entries = carrier.infolist()
                _need(0 < len(entries) <= 64 and {item.filename for item in entries} == names)
                seen: set[str] = set()
                total = 0
                for item in entries:
                    _need(
                        bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", item.filename))
                        and ".." not in item.filename
                        and item.filename.casefold() not in seen
                        and not item.is_dir()
                        and item.create_system == 3
                        and stat.S_ISREG(item.external_attr >> 16)
                        and not item.flag_bits & 1
                        and item.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                        and 0 < item.file_size <= MAX_FILE
                    )
                    seen.add(item.filename.casefold())
                    total += item.file_size
                    _need(total <= MAX_TOTAL)
                _need(not destination.exists() and not destination.is_symlink())
                with TemporaryDirectory(
                    prefix="guard-artifact-", dir=destination.parent
                ) as directory:
                    staging = Path(directory) / "subjects"
                    staging.mkdir(mode=0o700)
                    for item in entries:
                        target = staging / item.filename
                        with carrier.open(item) as source, target.open("xb") as output:
                            target.chmod(0o600)
                            written = 0
                            while block := source.read(65536):
                                written += len(block)
                                _need(written <= item.file_size)
                                output.write(block)
                            _need(written == item.file_size)
                    staging.rename(destination)
        except (zipfile.BadZipFile, RuntimeError, OSError):
            raise ArtifactError("Actions carrier extraction refused") from None
