import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from guard_harness import staged_state
from guard_harness.runner import RunResult
from guard_harness.testnet_run import ROOT

COMMIT = "b" * 40


def build_bytes(tag: str = "v1.0.0") -> bytes:
    build = json.loads((ROOT / "release/examples/build-v2.json").read_text())
    build["tag"], build["version"] = tag, tag[1:]
    build["signing"]["identity"] = (
        f"https://github.com/zunderlabs/zunder-guard/.github/workflows/release.yml@refs/tags/{tag}"
    )
    build["distribution"]["aws_template"]["url"] = (
        f"https://example.com/guard/{tag}/cloudformation.yaml"
    )
    build["assets"] = {
        "i": {
            "sha256": hashlib.sha256(b"loader").hexdigest(),
            "url": f"https://github.com/zunderlabs/zunder-guard/releases/download/{tag}/i",
        }
    }
    return json.dumps(build).encode()


@pytest.mark.parametrize("tag", ["v1.0.0", "v1.0.0-rc.1"])
def test_genesis_never_grants_channel_or_journey_credit(tag: str) -> None:
    original = build_bytes(tag)
    state = staged_state.genesis(original, commit=COMMIT, issued_at="2026-10-11T04:00:00Z")
    assert (state["revision"], state["previous"], state["stage"], state["evidence"]) == (
        1,
        None,
        "staged",
        {},
    )
    assert state["manifest_sha256"] == hashlib.sha256(original).hexdigest()
    build = json.loads(original)
    assert state["channels"] == {
        name: dict(descriptor, status="unavailable")
        for name, descriptor in build["distribution"].items()
    }
    assert (
        staged_state.genesis(original + b"\n", commit=COMMIT, issued_at="2026-10-11T04:00:00Z")[
            "manifest_sha256"
        ]
        != state["manifest_sha256"]
    )


@pytest.mark.parametrize("commit,time", [("c" * 40, "2026-10-11T04:00:00Z"), (COMMIT, "bad")])
def test_wrong_subject_or_timestamp_refused(commit: str, time: str) -> None:
    with pytest.raises(ValueError):
        staged_state.genesis(build_bytes(), commit=commit, issued_at=time)


@pytest.mark.parametrize("failure", ["", "verifier", "subject"])
def test_execute_authenticates_before_writing_predicate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: str
) -> None:
    tmp_path.chmod(0o700)
    work = tmp_path / "stage"

    def verifier(argv: list[str], **kwargs: Any) -> RunResult:
        assert argv == [
            "bash",
            str(ROOT / "github/verify-release-assets.sh"),
            "v1.0.0",
            str(work / "assets"),
        ]
        assert kwargs["env"]["GITHUB_REPOSITORY"] == "zunderlabs/zunder-guard"
        if failure == "verifier":
            raise RuntimeError("signature refused")
        assets = work / "assets"
        assets.mkdir(mode=0o700)
        manifest = build_bytes()
        (assets / "release-manifest.json").write_bytes(manifest)
        (assets / "i").write_bytes(b"loader")
        (assets / "SHA256SUMS").write_text(
            f"{hashlib.sha256(manifest).hexdigest()}  release-manifest.json\n"
            f"{hashlib.sha256(b'loader').hexdigest()}  i\n"
        )
        (assets / ".verified-release-source.json").write_text(
            json.dumps({"tag": "v1.0.0", "source": "c" * 40 if failure == "subject" else COMMIT})
        )
        for file in assets.iterdir():
            file.chmod(0o600)
        return RunResult(0, "", kwargs["log"])

    monkeypatch.setattr(staged_state, "run", verifier)
    if failure:
        with pytest.raises((RuntimeError, ValueError)):
            staged_state.execute(tag="v1.0.0", commit=COMMIT, work=work)
        assert not (work / "staged.predicate.json").exists()
    else:
        staged_state.execute(tag="v1.0.0", commit=COMMIT, work=work)
        state = json.loads((work / "staged.predicate.json").read_bytes())
        assert (
            state["manifest_sha256"]
            == hashlib.sha256((work / "assets/release-manifest.json").read_bytes()).hexdigest()
        )
        assert state["stage"] == "staged" and state["evidence"] == {}
        assert (work / "staged.predicate.json").stat().st_mode & 0o777 == 0o600
