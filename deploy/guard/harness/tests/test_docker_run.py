import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from guard_harness import docker_run
from guard_harness.runner import RunResult
from guard_harness.testnet_run import ROOT

TAG, COMMIT = "v1.0.0", "b" * 40
IMAGE = "ghcr.io/zunderlabs/zunder-guard@sha256:" + "a" * 64


def fixture_assets(path: Path, change: str = "") -> None:
    path.mkdir(mode=0o700)
    build = json.loads((ROOT / "release/examples/build-v2.json").read_text())
    build["distribution"]["docker"]["digest"] = "sha256:" + "a" * 64
    descriptor = IMAGE.replace("a" * 64, "c" * 64) if change == "descriptor" else IMAGE
    compose = (
        (ROOT / "compose.yaml").read_text().replace("ghcr.io/zunderlabs/zunder-guard:latest", IMAGE)
    )
    if change == "compose":
        compose = compose.replace("a" * 64, "c" * 64)
    payloads = {
        f"zunder-guard-{TAG}.image.txt": (descriptor + "\n").encode(),
        "compose.yaml": compose.encode(),
    }
    build["assets"] = {
        name: {
            "sha256": hashlib.sha256(data).hexdigest(),
            "url": f"https://github.com/zunderlabs/zunder-guard/releases/download/{TAG}/{name}",
        }
        for name, data in payloads.items()
    }
    manifest = json.dumps(build).encode()
    payloads["release-manifest.json"] = manifest
    for name, data in payloads.items():
        (path / name).write_bytes(data)
    (path / "SHA256SUMS").write_text(
        "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in payloads.items())
    )
    (path / ".verified-release-source.json").write_text(
        json.dumps({"tag": TAG, "source": "c" * 40 if change == "source" else COMMIT})
    )
    if change == "tampered":
        (path / "compose.yaml").write_text("changed")
    for file in path.iterdir():
        file.chmod(0o600)


@pytest.mark.parametrize("change", ["", "descriptor", "compose", "source", "tampered"])
def test_signed_subjects_agree_on_exact_image(tmp_path: Path, change: str) -> None:
    assets = tmp_path / "assets"
    fixture_assets(assets, change)
    if change:
        with pytest.raises((ValueError, RuntimeError)):
            docker_run.subjects(assets, tag=TAG, commit=COMMIT)
    else:
        image, compose, digest = docker_run.subjects(assets, tag=TAG, commit=COMMIT)
        assert image == IMAGE and compose == (assets / "compose.yaml").read_bytes()
        assert digest == hashlib.sha256((assets / "release-manifest.json").read_bytes()).hexdigest()


@pytest.mark.parametrize("failure", ["", "verify", "runtime"])
def test_runtime_requires_verifier_and_both_cleanup_results(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: str
) -> None:
    tmp_path.chmod(0o700)
    monkeypatch.setenv("GH_TOKEN", "fixture-token")
    work = tmp_path / "run"
    calls: list[str] = []

    def runner(argv: list[str], **kwargs: Any) -> RunResult:
        if argv[0] == "bash":
            calls.append("verify")
            assert argv[1] == str(ROOT / "github/verify-release-assets.sh")
            assert kwargs["env"]["GITHUB_REPOSITORY"] == "zunderlabs/zunder-guard"
            assert "fixture-token" in kwargs["secrets"]
            if failure == "verify":
                raise RuntimeError("verifier refused")
            fixture_assets(work / "assets")
        else:
            calls.append("pull")
            assert argv == ["docker", "pull", IMAGE]
            assert "GH_TOKEN" not in kwargs["env"]
        return RunResult(0, "", kwargs["log"])

    def lifecycle(image: str, account: str, *, work: Path, compose: Path | None = None) -> None:
        calls.append("compose" if compose else "docker")
        assert image == IMAGE and account == "0x" + "1" * 40
        if compose:
            assert compose.read_bytes() == (work.parent / "assets/compose.yaml").read_bytes()
            if failure == "runtime":
                raise RuntimeError("cleanup unconfirmed")

    monkeypatch.setattr(docker_run, "run", runner)
    monkeypatch.setattr(docker_run, "lifecycle", lifecycle)
    if failure:
        with pytest.raises(RuntimeError):
            docker_run.execute(tag=TAG, commit=COMMIT, account="0x" + "1" * 40, work=work)
        assert not (work / "receipt.json").exists()
        assert calls == (
            ["verify"] if failure == "verify" else ["verify", "pull", "docker", "compose"]
        )
    else:
        docker_run.execute(tag=TAG, commit=COMMIT, account="0x" + "1" * 40, work=work)
        assert calls == ["verify", "pull", "docker", "compose"]
        receipt = json.loads((work / "receipt.json").read_text())
        assert receipt["release_ready"] is False
        assert receipt["image"] == IMAGE
        assert "fixture-token" not in json.dumps(receipt)
