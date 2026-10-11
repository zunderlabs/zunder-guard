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


def fixture_assets(
    path: Path,
    change: str = "",
    *,
    tag: str = TAG,
    commit: str = COMMIT,
    image: str = IMAGE,
) -> None:
    path.mkdir(mode=0o700)
    build = json.loads((ROOT / "release/examples/build-v2.json").read_text())
    build.update(tag=tag, version=tag[1:], commit=commit)
    build["signing"]["identity"] = build["signing"]["identity"].replace(TAG, tag)
    build["distribution"]["aws_template"]["url"] = build["distribution"]["aws_template"][
        "url"
    ].replace(TAG, tag)
    build["distribution"]["docker"]["digest"] = image.split("@", 1)[1]
    descriptor = image.replace("a" * 64, "c" * 64) if change == "descriptor" else image
    compose = (
        (ROOT / "compose.yaml").read_text().replace("ghcr.io/zunderlabs/zunder-guard:latest", image)
    )
    if change == "compose":
        compose = compose.replace("a" * 64, "c" * 64)
    payloads = {
        f"zunder-guard-{tag}.image.txt": (descriptor + "\n").encode(),
        "compose.yaml": compose.encode(),
    }
    build["assets"] = {
        name: {
            "sha256": hashlib.sha256(data).hexdigest(),
            "url": f"https://github.com/zunderlabs/zunder-guard/releases/download/{tag}/{name}",
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
        json.dumps({"tag": tag, "source": "c" * 40 if change == "source" else commit})
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


@pytest.mark.parametrize("failure", ["", "previous-verifier", "same-image"])
def test_both_upgrade_subjects_admitted_before_any_docker_operation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failure: str,
) -> None:
    tmp_path.chmod(0o700)
    old_tag, old_commit = "v1.0.0-rc.1", "d" * 40
    old_image = IMAGE.replace("a" * 64, "e" * 64)
    calls: list[str] = []

    def runner(argv: list[str], **kwargs: Any) -> RunResult:
        if argv[0] == "bash":
            candidate = argv[2] == TAG
            calls.append("verify-current" if candidate else "verify-previous")
            if not candidate and failure == "previous-verifier":
                raise RuntimeError("previous admission refused")
            fixture_assets(
                Path(argv[3]),
                tag=argv[2],
                commit=COMMIT if candidate else old_commit,
                image=IMAGE if candidate or failure == "same-image" else old_image,
            )
        else:
            assert calls[:2] == ["verify-current", "verify-previous"]
            calls.append("pull")
            assert argv[:2] == ["docker", "pull"] and "GH_TOKEN" not in kwargs["env"]
        return RunResult(0, "", kwargs["log"])

    def lifecycle(image: str, account: str, **kwargs: Any) -> None:
        calls.append("compose" if kwargs.get("compose") else "docker")
        assert image == IMAGE and kwargs["previous_image"] == old_image
        if kwargs.get("compose"):
            assert (
                kwargs["previous_compose"].read_bytes()
                == (kwargs["work"].parent / "previous-assets/compose.yaml").read_bytes()
            )

    monkeypatch.setattr(docker_run, "run", runner)
    monkeypatch.setattr(docker_run, "lifecycle", lifecycle)
    work = tmp_path / "run"
    if failure:
        with pytest.raises((ValueError, RuntimeError)):
            docker_run.execute(
                tag=TAG,
                commit=COMMIT,
                account="0x" + "1" * 40,
                work=work,
                previous_tag=old_tag,
                previous_commit=old_commit,
            )
        assert calls == ["verify-current", "verify-previous"]
        assert not (work / "receipt.json").exists()
    else:
        docker_run.execute(
            tag=TAG,
            commit=COMMIT,
            account="0x" + "1" * 40,
            work=work,
            previous_tag=old_tag,
            previous_commit=old_commit,
        )
        assert calls == ["verify-current", "verify-previous", "pull", "pull", "docker", "compose"]
        receipt = json.loads((work / "receipt.json").read_bytes())
        assert receipt["previous_release"]["tag"] == old_tag
        assert receipt["previous_release"]["commit"] == old_commit
        assert receipt["release_ready"] is False


@pytest.mark.parametrize(
    "tag,commit",
    [
        ("v1.0.0-rc.1", None),
        (None, "d" * 40),
        (TAG, "d" * 40),
        ("v1.0.1", "d" * 40),
        ("v1.0.0-rc.1", COMMIT),
        ("bad", "d" * 40),
    ],
)
def test_previous_identity_must_be_complete_older_and_distinct(
    tmp_path: Path,
    tag: str | None,
    commit: str | None,
) -> None:
    with pytest.raises(ValueError):
        docker_run.execute(
            tag=TAG,
            commit=COMMIT,
            account="0x" + "1" * 40,
            work=tmp_path / "run",
            previous_tag=tag,
            previous_commit=commit,
        )
    assert not (tmp_path / "run").exists()


@pytest.mark.parametrize("failure", ["", "testnet-runtime", "previous-verifier"])
def test_testnet_both_channels_require_authenticated_previous_subjects(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: str
) -> None:
    tmp_path.chmod(0o700)
    monkeypatch.setenv("GUARD_C6_SERIALIZED", "1")
    monkeypatch.setenv("GITHUB_SHA", COMMIT)
    key = ("0" * 63 + "1\n").encode()
    calls: list[str] = []
    previous_tag, previous_commit = "v0.9.0", "c" * 40
    previous_image = IMAGE.replace("a" * 64, "d" * 64)

    def runner(argv: list[str], **kwargs: Any) -> RunResult:
        assert "E2E_TESTNET_API_WALLET_KEY" not in kwargs["env"]
        assert key.decode().strip() not in str(argv)
        if argv[0] == "bash":
            tag = argv[2]
            calls.append(tag)
            if tag == previous_tag and failure == "previous-verifier":
                raise RuntimeError("prior auth refused")
            fixture_assets(
                Path(argv[3]),
                tag=tag,
                commit=COMMIT if tag == TAG else previous_commit,
                image=IMAGE if tag == TAG else previous_image,
            )
        return RunResult(0, "", kwargs["log"])

    def paper(image: str, account: str, **kwargs: Any) -> None:
        assert calls[:2] == [TAG, previous_tag]
        calls.append(kwargs["work"].name)

    def testnet(image: str, account: str, **kwargs: Any) -> None:
        assert calls[:2] == [TAG, previous_tag]
        assert account == "0x" + "e" * 40 and kwargs["key"] == key
        assert kwargs["previous_image"] == previous_image
        assert kwargs["version"] == TAG[1:] and kwargs["previous_version"] == previous_tag[1:]
        calls.append(kwargs["work"].name)
        if kwargs["compose"] is not None:
            assert (
                kwargs["compose"].read_bytes()
                == (tmp_path / "run/assets/compose.yaml").read_bytes()
            )
        if failure == "testnet-runtime":
            raise RuntimeError("actual lifecycle refused")

    monkeypatch.setattr(docker_run, "run", runner)
    monkeypatch.setattr(docker_run, "lifecycle", paper)
    monkeypatch.setattr(docker_run, "testnet_lifecycle", testnet)
    args: dict[str, Any] = dict(
        tag=TAG,
        commit=COMMIT,
        account="0x" + "f" * 40,
        work=tmp_path / "run",
        previous_tag=previous_tag,
        previous_commit=previous_commit,
        testnet_account="0x" + "e" * 40,
        api_wallet="0x" + "b" * 40,
        testnet_key=key,
    )
    if failure:
        with pytest.raises(RuntimeError):
            docker_run.execute(**args)
        assert not (tmp_path / "run/receipt.json").exists()
    else:
        docker_run.execute(**args)
        receipt = json.loads((tmp_path / "run/receipt.json").read_text())
        assert receipt["checks"][-2:] == ["docker-testnet", "compose-testnet"]
        assert receipt["harness_commit"] == COMMIT and receipt["diagnostic"] is False
        assert receipt["release_ready"] is False  # Admission belongs to the independent adapter.
        assert calls[-2:] == ["docker-testnet", "compose-testnet"]
