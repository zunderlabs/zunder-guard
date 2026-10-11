import hashlib
from pathlib import Path
from typing import Any

import pytest

from guard_harness.build_manifest import PLATFORMS, generate
from guard_harness.manifest import ManifestError

SCHEMA = Path(__file__).parents[2] / "release/manifest.schema.json"


@pytest.fixture
def assets(tmp_path: Path) -> list[Path]:
    result = []
    for platform in PLATFORMS:
        extension = "zip" if platform == "windows-amd64" else "tar.gz"
        path = tmp_path / f"zunder-guard-v1.0.0-{platform}.{extension}"
        path.write_bytes(platform.encode())
        result.append(path)
    return result


def create(assets: list[Path]) -> dict[str, Any]:
    return generate(
        assets,
        tag="v1.0.0",
        commit="a" * 40,
        published_at="2026-10-10T10:00:00Z",
        docker_digest="sha256:" + "b" * 64,
        template_url="https://example.com/guard/v1.0.0/cloudformation.yaml",
        schema=SCHEMA,
    )


def test_hashes_exact_payload_bytes(assets: list[Path]) -> None:
    manifest = create(assets)
    assert manifest["platforms"] == list(PLATFORMS)
    assert manifest["assets"] == {
        path.name: {
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "url": f"https://github.com/zunderlabs/zunder-guard/releases/download/v1.0.0/{path.name}",
        }
        for path in assets
    }
    assert "stage" not in manifest
    assert "evidence" not in manifest


@pytest.mark.parametrize("index", range(len(PLATFORMS)))
def test_missing_platform_refused(assets: list[Path], index: int) -> None:
    del assets[index]
    with pytest.raises(ValueError, match="missing release archive"):
        create(assets)


def test_duplicate_basename_refused(assets: list[Path]) -> None:
    with pytest.raises(ValueError, match="duplicate"):
        create([*assets, assets[0]])


def test_symlink_refused(assets: list[Path], tmp_path: Path) -> None:
    link = tmp_path / "linked.tar.gz"
    link.symlink_to(assets[0])
    with pytest.raises(ValueError, match="symlinks"):
        create([*assets, link])


def test_no_self_checksum_cycle(assets: list[Path], tmp_path: Path) -> None:
    manifest = tmp_path / "release-manifest.json"
    manifest.write_text("{}")
    with pytest.raises(ManifestError, match="self-referential"):
        create([*assets, manifest])


def test_cli_refuses_overwriting_signed_manifest(assets: list[Path], tmp_path: Path) -> None:
    import os
    import subprocess
    import sys

    output = tmp_path / "release-manifest.json"
    arguments = [
        sys.executable,
        "-m",
        "guard_harness.build_manifest",
        "--tag",
        "v1.0.0",
        "--commit",
        "a" * 40,
        "--published-at",
        "2026-10-10T10:00:00Z",
        "--docker-digest",
        "sha256:" + "b" * 64,
        "--template-url",
        "https://example.com/guard/v1.0.0/cloudformation.yaml",
        "--schema",
        str(SCHEMA),
        "--output",
        str(output),
    ]
    for asset in assets:
        arguments.extend(["--asset", str(asset)])
    environment = {**os.environ, "PYTHONPATH": str(Path(__file__).parents[1] / "src")}
    first = subprocess.run(arguments, env=environment, capture_output=True, timeout=10, check=False)
    assert first.returncode == 0, first.stderr.decode()
    original = output.read_bytes()
    assets[0].write_bytes(b"modified payload")
    second = subprocess.run(
        arguments, env=environment, capture_output=True, timeout=10, check=False
    )
    assert second.returncode != 0
    assert output.read_bytes() == original


def test_sealed_checksums_cover_metadata_and_every_payload(
    assets: list[Path], tmp_path: Path
) -> None:
    import shutil
    import subprocess

    from guard_harness.build_manifest import write_release

    manifest = create(assets)
    output, checksums = tmp_path / "release-manifest.json", tmp_path / "SHA256SUMS"
    write_release(manifest, output, checksums)
    rows = dict(line.split("  ", 1)[::-1] for line in checksums.read_text().splitlines())
    assert set(rows) == {asset.name for asset in assets} | {output.name}
    for name, digest in rows.items():
        assert digest == hashlib.sha256((tmp_path / name).read_bytes()).hexdigest()
    verifier = shutil.which("sha256sum") or shutil.which("shasum")
    assert verifier is not None
    command = [verifier] if Path(verifier).name == "sha256sum" else [verifier, "-a", "256"]
    result = subprocess.run(
        [*command, "-c", checksums.name], cwd=tmp_path, capture_output=True, timeout=10
    )
    assert result.returncode == 0, result.stderr.decode()
    original = checksums.read_bytes()
    output.write_bytes(output.read_bytes() + b" ")
    result = subprocess.run(
        [*command, "-c", checksums.name], cwd=tmp_path, capture_output=True, timeout=10
    )
    assert result.returncode != 0
    assert checksums.read_bytes() == original


@pytest.mark.parametrize("unexpected", ["unsigned-payload", "SHA256SUMS.sigstore.json"])
def test_seal_refuses_unlisted_files(assets: list[Path], tmp_path: Path, unexpected: str) -> None:
    from guard_harness.build_manifest import write_release

    manifest = create(assets)
    (tmp_path / unexpected).write_bytes(b"not part of the payload inventory")
    with pytest.raises(ValueError, match="inventory"):
        write_release(manifest, tmp_path / "release-manifest.json", tmp_path / "SHA256SUMS")
    assert not (tmp_path / "release-manifest.json").exists()


def test_seal_refuses_missing_payload(assets: list[Path], tmp_path: Path) -> None:
    from guard_harness.build_manifest import write_release

    manifest = create(assets)
    assets[0].unlink()
    with pytest.raises(ValueError, match="inventory"):
        write_release(manifest, tmp_path / "release-manifest.json", tmp_path / "SHA256SUMS")
    assert not (tmp_path / "release-manifest.json").exists()


@pytest.mark.parametrize("linked", [False, True])
def test_seal_never_replaces_checksums(assets: list[Path], tmp_path: Path, linked: bool) -> None:
    from guard_harness.build_manifest import write_release

    manifest = create(assets)
    checksums = tmp_path / "SHA256SUMS"
    if linked:
        checksums.symlink_to(assets[0])
    else:
        checksums.write_bytes(b"existing signed checksum bytes")
    original = checksums.read_bytes()
    with pytest.raises(ValueError, match="overwrite"):
        write_release(manifest, tmp_path / "release-manifest.json", checksums)
    assert checksums.read_bytes() == original
    assert not (tmp_path / "release-manifest.json").exists()
