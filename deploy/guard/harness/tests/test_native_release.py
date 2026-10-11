import io
import json
import tarfile
import zipfile
from pathlib import Path

import pytest
from test_testnet_run import COMMIT, NAME, TAG, assets

from guard_harness.native_paper import LifecycleError, retained, verify_retained
from guard_harness.native_release import Release, archive_binary, diagnostic_mode
from guard_harness.testnet_process import ProcessError


@pytest.mark.parametrize("value,expected", [("false", False), ("true", True)])
def test_diagnostic_identity_preserves_explicit_boolean(
    monkeypatch: pytest.MonkeyPatch, value: str, expected: bool
) -> None:
    monkeypatch.setenv("DIAGNOSTIC", value)
    assert diagnostic_mode() is expected


@pytest.mark.parametrize("value", ["", "True", "0", "False", "invalid"])
def test_diagnostic_identity_refuses_ambiguous_values(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv("DIAGNOSTIC", value)
    with pytest.raises(ProcessError, match="diagnostic boolean"):
        diagnostic_mode()


def test_snapshot_binds_exact_source_manifest_and_payload(tmp_path: Path) -> None:
    assets(tmp_path / "assets")
    release = Release(TAG, COMMIT, tmp_path / "assets")
    assert release.asset(NAME)
    assert archive_binary(release.asset(NAME), windows=False) == b"fixture"


@pytest.mark.parametrize("mutation", ["commit", "manifest", "payload", "duplicate", "link"])
def test_snapshot_refuses_changed_inputs(tmp_path: Path, mutation: str) -> None:
    source = tmp_path / "assets"
    assets(source)
    if mutation == "commit":
        (source / ".verified-release-source.json").write_text(
            json.dumps({"tag": TAG, "source": "a" * 40})
        )
    elif mutation == "manifest":
        manifest = json.loads((source / "release-manifest.json").read_bytes())
        manifest["commit"] = "a" * 40
        (source / "release-manifest.json").write_text(json.dumps(manifest))
    elif mutation == "payload":
        (source / NAME).write_bytes(b"different")
    elif mutation == "duplicate":
        with (source / "SHA256SUMS").open("a") as output:
            output.write(f"{'a' * 64}  {NAME}\n")
    else:
        archive = source / NAME
        archived = source / "original"
        archive.rename(archived)
        archive.symlink_to(archived)
    with pytest.raises((ProcessError, ValueError)):
        Release(TAG, COMMIT, source).asset(NAME)


@pytest.mark.parametrize("name", ["../key", "/key", "a\\key", "key\n", "a..b"])
def test_snapshot_refuses_paths_before_reading(tmp_path: Path, name: str) -> None:
    with pytest.raises(ProcessError):
        Release(TAG, COMMIT, tmp_path).asset(name)


@pytest.mark.parametrize("windows", [False, True])
@pytest.mark.parametrize("name", ["../zunder-guard", "zunder-guard/key", "guard.key", "NOTICE"])
def test_archive_refuses_paths_or_missing_binary(windows: bool, name: str) -> None:
    buffer = io.BytesIO()
    if windows:
        with zipfile.ZipFile(buffer, "w") as source:
            source.writestr(name, b"fixture")
    else:
        with tarfile.open(fileobj=buffer, mode="w:gz") as source:
            member = tarfile.TarInfo(name)
            member.size = 7
            source.addfile(member, io.BytesIO(b"fixture"))
    with pytest.raises(ProcessError):
        archive_binary(buffer.getvalue(), windows=windows)


def test_journal_prefix_and_exact_pairing_configuration(tmp_path: Path) -> None:
    for name in ("guard.toml", "risk-paper.jsonl", "decisions-paper.jsonl"):
        (tmp_path / name).write_bytes(b"original\n")
    before = retained(tmp_path)
    (tmp_path / "risk-paper.jsonl").write_bytes(b"original\nappended\n")
    verify_retained(before, tmp_path)
    (tmp_path / "guard.toml").write_bytes(b"lost pairing")
    with pytest.raises(LifecycleError, match="configuration"):
        verify_retained(before, tmp_path)
    (tmp_path / "guard.toml").write_bytes(b"original\n")
    (tmp_path / "risk-paper.jsonl").write_bytes(b"replacement\n")
    with pytest.raises(LifecycleError, match="journal"):
        verify_retained(before, tmp_path)


def test_missing_journal_does_not_count_as_empty_success(tmp_path: Path) -> None:
    with pytest.raises(LifecycleError, match="missing"):
        retained(tmp_path)


def test_manifest_authenticated_by_signed_checksum_without_recursive_asset_hash(
    tmp_path: Path,
) -> None:
    assets(tmp_path / "assets")
    release = Release(TAG, COMMIT, tmp_path / "assets")
    manifest = release.asset("release-manifest.json")
    assert "release-manifest.json" not in json.loads(manifest)["assets"]
    assert json.loads(manifest)["commit"] == COMMIT
    (tmp_path / "assets/release-manifest.json").write_bytes(manifest + b" ")
    with pytest.raises(ProcessError):
        release.asset("release-manifest.json")


@pytest.mark.parametrize("channel,route", [("staging", "i-staging"), ("canonical", "i")])
def test_staging_get_uses_descriptive_ua_and_no_authorization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, channel: str, route: str
) -> None:
    from typing import Any

    import guard_harness.native_release as native

    class Response:
        status = 200

        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *args: Any) -> None:
            pass

        def geturl(self) -> str:
            return "https://zunderlabs.com/" + route

        def read(self, limit: int) -> bytes:
            return b"authenticated loader"

    def request(value: Any, **kwargs: Any) -> Response:
        assert value.full_url == "https://zunderlabs.com/" + route
        assert value.get_header("User-agent") == "zunder-guard-release/1.0"
        assert value.get_header("Authorization") is None
        return Response()

    monkeypatch.setattr(native, "urlopen", request)
    monkeypatch.setattr(Release, "asset", lambda self, name: b"authenticated loader")
    assert (
        native.staged_loader(
            Release(TAG, COMMIT, tmp_path),
            windows=False,
            output=tmp_path / "loader",
            channel=channel,
        ).read_bytes()
        == b"authenticated loader"
    )
