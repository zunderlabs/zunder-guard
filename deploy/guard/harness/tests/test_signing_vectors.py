import hashlib
import json
import os
import shlex
from pathlib import Path
from typing import Any

import pytest

from guard_harness import signing_vectors
from guard_harness.runner import RunResult
from guard_harness.testnet_run import ROOT


@pytest.mark.parametrize("system", ["Linux", "Darwin", "Windows"])
def test_vectors_execute_every_platform_contract_without_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, system: str
) -> None:
    monkeypatch.setattr("guard_harness.signing_vectors.platform.system", lambda: system)
    monkeypatch.setenv("GH_TOKEN", "secret-fixture")
    monkeypatch.setenv("E2E_TESTNET_OWNER_KEY", "private-fixture")
    calls: list[list[str]] = []

    class Release:
        commit = "a" * 40

        def asset(self, name: str) -> bytes:
            assert name == "release-manifest.json"
            return b"authenticated fixture"

    def run(argv: list[str], **kwargs: Any) -> RunResult:
        calls.append(argv)
        if argv[0] == "git":
            return RunResult(0, "a" * 40, kwargs["log"])
        assert kwargs["env"].get("GH_TOKEN") is None
        assert kwargs["env"].get("E2E_TESTNET_OWNER_KEY") is None
        assert argv[:3] == ["cargo", "test", "--locked"]
        return RunResult(0, "test result: ok. 2 passed; 0 failed;", kwargs["log"])

    monkeypatch.setattr(signing_vectors, "run", run)
    output = tmp_path / "proof"
    signing_vectors.execute(Release(), output)  # type: ignore[arg-type]
    predicate = json.loads((output / "signing.predicate.json").read_bytes())
    expected = list(signing_vectors.CHECKS)
    platform = signing_vectors.PLATFORMS[system]
    if platform != "linux":
        expected.append(f"guard.service.{platform}")
    assert predicate["checks"] == expected
    assert predicate["manifest_sha256"] == hashlib.sha256(b"authenticated fixture").hexdigest()
    assert len(calls) == len(expected) + 1


@pytest.mark.parametrize("failure", ["wrong-source", "empty-filter"])
def test_signing_never_attests_wrong_source_or_zero_tests(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    monkeypatch.setattr("guard_harness.signing_vectors.platform.system", lambda: "Linux")

    class Release:
        commit = "a" * 40

        def asset(self, name: str) -> bytes:
            return b"authenticated fixture"

    def run(argv: list[str], **kwargs: Any) -> RunResult:
        if argv[0] == "git":
            return RunResult(0, ("b" if failure == "wrong-source" else "a") * 40, kwargs["log"])
        return RunResult(0, "test result: ok. 0 passed; 0 failed;", kwargs["log"])

    monkeypatch.setattr(signing_vectors, "run", run)
    output = tmp_path / "proof"
    with pytest.raises(ValueError):
        signing_vectors.execute(Release(), output)  # type: ignore[arg-type]
    assert not (output / "signing.predicate.json").exists()


@pytest.mark.parametrize("windows_mode_ignored", [False, True])
def test_sdk_workflow_creates_fresh_homes_without_posix_chmod(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, windows_mode_ignored: bool
) -> None:
    workflow = ROOT / "github/workflows/journey.yml"
    if not workflow.exists():
        workflow = ROOT.parents[1] / ".github/workflows/journey.yml"
    setup = (
        workflow.read_text()
        .split("- name: Install the pinned SDK toolchain in fresh job-private homes", 1)[1]
        .split("- name: Run SDK vectors", 1)[0]
    )
    line = next(line.strip() for line in setup.splitlines() if "pathlib.Path" in line)
    argv = shlex.split(line)
    assert argv[:2] == ["python", "-c"] and len(argv) == 3
    homes = [tmp_path / "sdk-rustup", tmp_path / "sdk-cargo"]
    for name, home in zip(("RUSTUP_HOME", "CARGO_HOME"), homes, strict=True):
        monkeypatch.setenv(name, str(home))
    monkeypatch.setattr(os, "chmod", lambda *a, **k: pytest.fail("no POSIX chmod on NTFS"))
    original_mkdir = Path.mkdir
    if windows_mode_ignored:
        # Model native Windows accepting the creation mode without a POSIX chmod.
        monkeypatch.setattr(Path, "mkdir", lambda path, **kwargs: original_mkdir(path))
    exec(argv[2], {})
    assert all(home.is_dir() for home in homes)
    if not windows_mode_ignored:
        assert all(home.stat().st_mode & 0o777 == 0o700 for home in homes)
    sentinel = homes[0] / "existing-cache-fixture"
    sentinel.write_text("retain")
    with pytest.raises(FileExistsError):
        exec(argv[2], {})
    assert sentinel.read_text() == "retain"
    assert "rustup toolchain install --no-self-update" in setup
    assert 'tomllib.load(open("rust-toolchain.toml","rb"))' in setup
