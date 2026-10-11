import copy
import hashlib
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest
import test_actions_artifacts as reference
from test_actions_artifacts import carrier

from guard_harness.actions_artifacts import ArtifactError
from guard_harness.actions_download import REPOSITORY, GhActions, stage


@pytest.fixture
def metadata() -> Any:
    fixture: Any = reference.metadata
    return fixture.__wrapped__()


class API:
    def __init__(self, fixture: Any, tmp_path: Path) -> None:
        self.selected, run, artifact, jobs = fixture
        self.root = f"{REPOSITORY}/actions/runs/{self.selected.run_id}"
        self.attempt = f"{self.root}/attempts/{self.selected.attempt}"
        self.provenance = f"zunder-guard-{self.selected.tag}.intoto.jsonl"
        self.calls: list[str] = []
        self.bodies: dict[str, bytes] = {}
        self.after_download: Any = None
        artifacts = []
        for index, name in enumerate(["dist", self.provenance]):
            path = carrier(tmp_path, [("i" if index == 0 else name, 0o100644, name.encode())])
            body = path.read_bytes()
            value = copy.deepcopy(artifact)
            value.update(
                id=33 + index,
                name=name,
                digest="sha256:" + hashlib.sha256(body).hexdigest(),
                size_in_bytes=len(body),
            )
            artifacts.append(value)
            self.bodies[f"{REPOSITORY}/actions/artifacts/{33 + index}/zip"] = body
        provenance_job = copy.deepcopy(jobs[0])
        provenance_job["name"] = "provenance / generator"
        self.values = {
            REPOSITORY: run["repository"],
            self.attempt: run,
            self.root: copy.deepcopy(run),
            self.root + "/artifacts?per_page=100": {"total_count": 2, "artifacts": artifacts},
            self.attempt + "/jobs?per_page=100": {
                "total_count": 2,
                "jobs": [jobs[0], provenance_job],
            },
        }

    def metadata(self, path: str) -> dict[str, Any]:
        self.calls.append(path)
        return copy.deepcopy(self.values[path])

    def download(self, path: str, target: Path) -> None:
        self.calls.append(path)
        target.write_bytes(self.bodies[path])
        if self.after_download is not None:
            self.after_download()


def test_complete_staging_rechecks_attempt_and_latest(metadata: Any, tmp_path: Path) -> None:
    api = API(metadata, tmp_path)
    out = tmp_path / "out"
    receipt = stage(api, api.selected, out, dist_names={"i"})
    assert {path.name for path in out.iterdir()} == {"i", api.provenance}
    assert (out / "i").read_bytes() == b"dist"
    assert api.calls[-2:] == [api.attempt, api.root]
    assert receipt["cryptographic_release_verification"] is False


@pytest.mark.parametrize("inventory", ["artifacts", "jobs"])
@pytest.mark.parametrize("count", [True, 1, 101])
def test_incomplete_inventory_refused(
    metadata: Any, tmp_path: Path, inventory: str, count: Any
) -> None:
    api = API(metadata, tmp_path)
    endpoint = (
        api.root if inventory == "artifacts" else api.attempt
    ) + f"/{inventory}?per_page=100"
    api.values[endpoint]["total_count"] = count
    with pytest.raises(ArtifactError, match="inventory"):
        stage(api, api.selected, tmp_path / "out", dist_names={"i"})
    assert not (tmp_path / "out").exists()
    assert not any(path.endswith("/zip") for path in api.calls)


@pytest.mark.parametrize("latest", [True, False])
@pytest.mark.parametrize(
    "field,value", [("run_attempt", 4), ("updated_at", "2026-10-10T10:06:00Z")]
)
def test_concurrent_rerun_leaves_no_output(
    metadata: Any, tmp_path: Path, latest: bool, field: str, value: Any
) -> None:
    api = API(metadata, tmp_path)
    endpoint = api.root if latest else api.attempt
    api.after_download = lambda: api.values[endpoint].update({field: value})
    with pytest.raises(ArtifactError):
        stage(api, api.selected, tmp_path / "out", dist_names={"i"})
    assert not (tmp_path / "out").exists()
    assert not list(tmp_path.glob("guard-actions-*"))


def test_recreated_repository_refused_before_download(metadata: Any, tmp_path: Path) -> None:
    api = API(metadata, tmp_path)
    api.values[REPOSITORY] = {"id": 99, "full_name": "zunderlabs/zunder-guard"}
    with pytest.raises(ArtifactError, match="repository"):
        stage(api, api.selected, tmp_path / "out", dist_names={"i"})
    assert api.calls == [REPOSITORY]


@pytest.mark.parametrize("failure", ["duplicate", "corrupt", "extra", "provenance-name"])
def test_changed_payload_leaves_no_output(metadata: Any, tmp_path: Path, failure: str) -> None:
    api = API(metadata, tmp_path)
    names = {"i"}
    if failure == "duplicate":
        listing = api.values[api.root + "/artifacts?per_page=100"]
        listing["artifacts"].append(copy.deepcopy(listing["artifacts"][0]))
        listing["total_count"] += 1
    elif failure == "corrupt":
        api.bodies[next(iter(api.bodies))] = b"corrupt"
    elif failure == "extra":
        names.add("missing")
    else:
        names.add(api.provenance)
    with pytest.raises(ArtifactError):
        stage(api, api.selected, tmp_path / "out", dist_names=names)
    assert not (tmp_path / "out").exists()


def test_existing_output_preserved(metadata: Any, tmp_path: Path) -> None:
    api = API(metadata, tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    (out / "sentinel").write_text("preserve")
    with pytest.raises(ArtifactError):
        stage(api, api.selected, out, dist_names={"i"})
    assert (out / "sentinel").read_text() == "preserve"
    assert not api.calls


@pytest.mark.parametrize("case", ["limit", "failure", "success"])
def test_subprocess_transport_bounded_and_errors_withheld(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    original = subprocess.Popen
    script = {
        "limit": "import sys; sys.stdout.write('x'*5000)",
        "failure": "import sys; sys.stderr.write('secret-token'); sys.exit(1)",
        "success": "import sys; sys.stdout.buffer.write(b'payload')",
    }[case]

    def child(argv: Any, **kwargs: Any) -> Any:
        assert argv == ["gh", "api", "--hostname", "github.com", REPOSITORY]
        return original([sys.executable, "-c", script], **kwargs)

    monkeypatch.setattr(subprocess, "Popen", child)
    transport = GhActions()
    if case == "success":
        target = tmp_path / "zip"
        assert transport._stream(REPOSITORY, 100, target) == b""
        assert target.read_bytes() == b"payload"
        assert target.stat().st_mode & 0o777 == 0o600
    else:
        with pytest.raises(ArtifactError) as caught:
            transport._stream(REPOSITORY, 100)
        assert "secret-token" not in str(caught.value)


@pytest.mark.parametrize(
    "path",
    [
        "repos/other/repo/actions/runs/1",
        REPOSITORY + "/actions/../issues",
        REPOSITORY + "/actions/runs/1?unexpected=true",
    ],
)
def test_transport_rejects_noncanonical_paths(path: str) -> None:
    with pytest.raises(ArtifactError, match="canonical"):
        GhActions().metadata(path)


def test_combined_expansion_is_bounded(
    metadata: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import guard_harness.actions_download as transport

    api = API(metadata, tmp_path)
    monkeypatch.setattr(transport, "MAX_TOTAL", 1)
    with pytest.raises(ArtifactError, match="combined"):
        stage(api, api.selected, tmp_path / "out", dist_names={"i"})
    assert not (tmp_path / "out").exists()
    assert not list(tmp_path.glob("guard-actions-*"))


def test_hanging_transport_is_killed(monkeypatch: pytest.MonkeyPatch) -> None:
    original = subprocess.Popen
    children: list[Any] = []
    clock = iter([0.0, 181.0])

    def child(argv: Any, **kwargs: Any) -> Any:
        process = original([sys.executable, "-c", "import time; time.sleep(30)"], **kwargs)
        children.append(process)
        return process

    monkeypatch.setattr(subprocess, "Popen", child)
    monkeypatch.setattr(time, "monotonic", lambda: next(clock))
    with pytest.raises(ArtifactError, match="deadline"):
        GhActions().metadata(REPOSITORY)
    assert children[0].poll() is not None
    assert children[0].stdout.closed
