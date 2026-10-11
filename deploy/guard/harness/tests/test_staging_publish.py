import json
import os
from pathlib import Path
from typing import Any

import pytest

from guard_harness import staging_publish
from guard_harness.publication import Publication


@pytest.mark.parametrize("failure", ["", "signature", "post"])
def test_admission_precedes_one_post_and_only_confirmed_post_has_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    tmp_path.chmod(0o700)
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir(mode=0o755)
    tmp_path = runner_temp / "guard-release"
    tmp_path.mkdir(mode=0o700)
    state = tmp_path / "staged.predicate.json"
    state.write_text(json.dumps({"stage": "staged", "revision": 1, "previous": None}))
    state.chmod(0o600)
    bundle = tmp_path / "action.bundle"
    bundle.write_bytes(b"authenticated elsewhere by gh")
    monkeypatch.setenv("INSTALLER_PUBLISH_TOKEN", "fixture-credential")
    monkeypatch.setattr(staging_publish, "read_head", lambda channel: (None, None))
    calls: list[str] = []

    def authenticate(*args: Any, **kwargs: Any) -> Publication:
        assert "INSTALLER_PUBLISH_TOKEN" not in os.environ
        assert args[2].read_bytes() == bundle.read_bytes()
        assert kwargs["previous"] is None and kwargs["expected"] is None
        assert kwargs["journeys"] == {} and kwargs["workflow"] == "verify.yml"
        calls.append("authenticate")
        if failure == "signature":
            raise ValueError("signature refused")
        return Publication(b"capsule", "a" * 64)

    def post(publication: Publication, *, token: str) -> str:
        assert calls == ["authenticate"] and token == "fixture-credential"
        calls.append("post")
        if failure == "post":
            raise ValueError("unknown outcome")
        return publication.digest

    monkeypatch.setattr(staging_publish, "prepare", authenticate)
    monkeypatch.setattr(staging_publish, "publish", post)
    arguments: dict[str, Any] = dict(
        tag="v1.0.0-rc.2", commit="b" * 40, work=tmp_path, bundle=bundle
    )
    if failure:
        with pytest.raises(ValueError):
            staging_publish.execute(**arguments)
        assert not (tmp_path / "publication.json").exists()
    else:
        staging_publish.execute(**arguments)
        assert json.loads((tmp_path / "publication.json").read_bytes()) == {
            "tag": "v1.0.0-rc.2",
            "commit": "b" * 40,
            "state_sha256": "a" * 64,
            "stage": "staged",
        }
    assert calls == (["authenticate"] if failure == "signature" else ["authenticate", "post"])
    # Even an unknown outcome cannot cause a second POST by replaying the command.
    monkeypatch.setenv("INSTALLER_PUBLISH_TOKEN", "fixture-credential")
    with pytest.raises((ValueError, FileExistsError)):
        staging_publish.execute(**arguments)
    assert calls.count("post") <= 1


@pytest.mark.parametrize(
    "predicate",
    [
        {"stage": "gated", "revision": 1, "previous": None},
        {"stage": "staged", "revision": 2, "previous": None},
        {"stage": "staged", "revision": 1, "previous": "a" * 64},
    ],
)
def test_non_genesis_cannot_reach_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, predicate: dict[str, object]
) -> None:
    tmp_path.chmod(0o700)
    state = tmp_path / "staged.predicate.json"
    state.write_text(json.dumps(predicate))
    state.chmod(0o600)
    monkeypatch.setenv("INSTALLER_PUBLISH_TOKEN", "fixture-credential")
    with pytest.raises(ValueError, match="initial staged genesis"):
        staging_publish.execute(tag="v1.0.0", commit="b" * 40, work=tmp_path, bundle=state)
    assert not (tmp_path / "staged.sigstore.json").exists()


def test_bundle_limit_refuses_before_any_verification_or_post(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tmp_path.chmod(0o700)
    state = tmp_path / "staged.predicate.json"
    state.write_text(json.dumps({"stage": "staged", "revision": 1, "previous": None}))
    state.chmod(0o600)
    bundle = tmp_path / "oversize.bundle"
    bundle.write_bytes(b"x" * (2 * 1024 * 1024 + 1))
    monkeypatch.setenv("INSTALLER_PUBLISH_TOKEN", "fixture-credential")
    with pytest.raises(ValueError, match="bundle size"):
        staging_publish.execute(tag="v1.0.0", commit="b" * 40, work=tmp_path, bundle=bundle)
    assert not (tmp_path / "staged.sigstore.json").exists()


def test_successor_release_compares_existing_channel_head(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tmp_path.chmod(0o700)
    state = tmp_path / "staged.predicate.json"
    state.write_text(
        json.dumps(
            {"stage": "staged", "revision": 1, "previous": None, "manifest_sha256": "b" * 64}
        )
    )
    state.chmod(0o600)
    bundle = tmp_path / "bundle.json"
    bundle.write_bytes(b"bundle")
    monkeypatch.setenv("INSTALLER_PUBLISH_TOKEN", "fixture")
    monkeypatch.setattr(
        staging_publish, "read_head", lambda channel: ("a" * 64, {"manifest_sha256": "c" * 64})
    )

    def authenticate(*args: Any, **kwargs: Any) -> Publication:
        assert kwargs["expected"] == "a" * 64 and kwargs["previous"] is None
        return Publication(b"capsule", "b" * 64)

    monkeypatch.setattr(staging_publish, "prepare", authenticate)
    monkeypatch.setattr(staging_publish, "publish", lambda publication, token: publication.digest)
    staging_publish.execute(tag="v1.0.0-rc.4", commit="b" * 40, work=tmp_path, bundle=bundle)
    assert (tmp_path / "publication.json").exists()


def test_same_build_genesis_is_not_replayed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tmp_path.chmod(0o700)
    state = tmp_path / "staged.predicate.json"
    state.write_text(
        json.dumps(
            {"stage": "staged", "revision": 1, "previous": None, "manifest_sha256": "b" * 64}
        )
    )
    state.chmod(0o600)
    bundle = tmp_path / "bundle.json"
    bundle.write_bytes(b"bundle")
    monkeypatch.setenv("INSTALLER_PUBLISH_TOKEN", "fixture")
    monkeypatch.setattr(
        staging_publish, "read_head", lambda channel: ("a" * 64, {"manifest_sha256": "b" * 64})
    )
    monkeypatch.setattr(
        staging_publish, "prepare", lambda *args, **kwargs: pytest.fail("replay admitted")
    )
    with pytest.raises(ValueError, match="already staged"):
        staging_publish.execute(tag="v1.0.0-rc.4", commit="b" * 40, work=tmp_path, bundle=bundle)
