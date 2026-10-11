"""Bounded canonical gh transport and all-or-nothing release artifact staging (POSIX)."""

import json
import os
import re
import selectors
import subprocess
import time
from collections.abc import Set
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Protocol

from guard_harness.actions_artifacts import (
    MAX_TOTAL,
    MAX_ZIP,
    ArtifactError,
    ReleaseAttempt,
    extract,
)
from guard_harness.staged_subjects import _private

REPOSITORY = "repos/zunderlabs/zunder-guard"


class ActionsAPI(Protocol):
    def metadata(self, path: str) -> dict[str, Any]: ...

    def download(self, path: str, target: Path) -> None: ...


class GhActions:
    """No shell, token argv or server diagnostics; caller retains fixed-error diagnostics."""

    def _stream(self, path: str, limit: int, target: Path | None = None) -> bytes:
        suffix = path.removeprefix(REPOSITORY)
        if not path.startswith(REPOSITORY) or not re.fullmatch(
            r"(?:/actions/(?:runs/[1-9]\d*(?:/attempts/[1-9]\d*)?"
            r"(?:/(?:jobs|artifacts)\?per_page=100)?|artifacts/[1-9]\d*/zip))?",
            suffix,
        ):
            raise ArtifactError("canonical Actions API path required")
        child = subprocess.Popen(
            ["gh", "api", "--hostname", "github.com", path],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        body = bytearray()
        sink = None
        try:
            if target is not None:
                sink = target.open("xb")
                target.chmod(0o600)
            if child.stdout is None:
                raise ArtifactError("Actions transport stdout absent")
            deadline = time.monotonic() + 180
            total = 0
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    if time.monotonic() >= deadline:
                        raise ArtifactError("Actions transport deadline")
                    for item, _ in selector.select(0.1):
                        block = os.read(item.fd, 65536)
                        if not block:
                            selector.unregister(item.fileobj)
                            continue
                        total += len(block)
                        if total > limit:
                            raise ArtifactError("Actions transport byte limit")
                        if sink is not None:
                            sink.write(block)
                        else:
                            body.extend(block)
            if child.wait(timeout=max(0.01, deadline - time.monotonic())):
                raise ArtifactError("Actions transport failed")
            return bytes(body)
        except (OSError, subprocess.TimeoutExpired):
            raise ArtifactError("Actions transport failed") from None
        finally:
            if sink is not None:
                sink.close()
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
            if child.stdout is not None:
                child.stdout.close()

    def metadata(self, path: str) -> dict[str, Any]:
        captured = self._stream(path, 2 * 1024 * 1024)
        try:
            value = json.loads(captured)
        except (ValueError, UnicodeError):
            raise ArtifactError("Actions API JSON refused") from None
        if not isinstance(value, dict):
            raise ArtifactError("Actions API object required")
        return value

    def download(self, path: str, target: Path) -> None:
        self._stream(path, MAX_ZIP, target)


def _inventory(value: dict[str, Any], key: str) -> list[dict[str, Any]]:
    entries, count = value.get(key), value.get("total_count")
    if (
        not isinstance(entries, list)
        or type(count) is not int
        or count != len(entries)
        or not 0 <= count <= 100
        or not all(isinstance(entry, dict) for entry in entries)
    ):
        raise ArtifactError("Actions inventory incomplete or oversized")
    return entries


def stage(
    api: ActionsAPI,
    selected: ReleaseAttempt,
    output: Path,
    *,
    dist_names: Set[str],
) -> dict[str, Any]:
    """Stage exact caller-specified payload names; signatures remain a separate gate.

    Supply the dist inventory from the release packaging contract. API names/digests
    cannot establish cryptographic release trust. No output survives a failed re-read.
    """
    _private(output.parent, directory=True)
    if output.exists() or output.is_symlink():
        raise ArtifactError("fresh Actions staging path required")
    repository = api.metadata(REPOSITORY)
    if repository.get("id") != selected.repository_id or repository.get("full_name") != (
        "zunderlabs/zunder-guard"
    ):
        raise ArtifactError("current canonical repository differs")
    root = f"{REPOSITORY}/actions/runs/{selected.run_id}"
    attempt = f"{root}/attempts/{selected.attempt}"
    run = api.metadata(attempt)
    window = selected.window(run)
    artifacts = _inventory(api.metadata(root + "/artifacts?per_page=100"), "artifacts")
    jobs = _inventory(api.metadata(attempt + "/jobs?per_page=100"), "jobs")
    provenance = f"zunder-guard-{selected.tag}.intoto.jsonl"
    if not dist_names or provenance.casefold() in {name.casefold() for name in dist_names}:
        raise ArtifactError("separate exact payload and provenance inventories required")
    report: list[dict[str, Any]] = []
    with TemporaryDirectory(prefix="guard-actions-", dir=output.parent) as directory:
        workspace = Path(directory)
        subjects = workspace / "subjects"
        subjects.mkdir(mode=0o700)
        total = 0
        for name, job, names in (
            ("dist", "package", dist_names),
            (provenance, "provenance / generator", {provenance}),
        ):
            matches = [value for value in artifacts if value.get("name") == name]
            if len(matches) != 1:
                raise ArtifactError("unique exact Actions artifact required")
            artifact_id, digest, size = selected.artifact(
                matches[0], run, jobs, name=name, job_name=job
            )
            archive = workspace / f"{artifact_id}.zip"
            api.download(f"{REPOSITORY}/actions/artifacts/{artifact_id}/zip", archive)
            unpacked = workspace / str(artifact_id)
            extract(archive, unpacked, digest=digest, size=size, names=names)
            for path in unpacked.iterdir():
                total += path.stat().st_size
                if total > MAX_TOTAL or len(list(subjects.iterdir())) >= 64:
                    raise ArtifactError("combined Actions expansion limit")
                path.rename(subjects / path.name)
            report.append({"id": artifact_id, "name": name, "sha256": digest, "bytes": size})
        for endpoint in (attempt, root):
            if selected.window(api.metadata(endpoint)) != window:
                raise ArtifactError("Actions attempt changed during download")
        subjects.rename(output)
    return {
        "schema": 1,
        "tag": selected.tag,
        "commit": selected.commit,
        "run_id": selected.run_id,
        "run_attempt": selected.attempt,
        "artifacts": report,
        "cryptographic_release_verification": False,
    }
