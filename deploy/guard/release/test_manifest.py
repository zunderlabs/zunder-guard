"""Behavioural contract tests for C2."""

from pathlib import Path
from typing import Any

import pytest

from guard_harness.manifest import (
    CHANNEL_JOURNEYS,
    IDENTITY_BASE,
    RELEASE_BASE,
    RELEASE_JOURNEYS,
    ManifestError,
    validate_manifest,
)

SCHEMA = Path(__file__).with_name("manifest-v1.schema.json")


@pytest.fixture
def manifest() -> dict[str, Any]:
    channels: dict[str, Any] = {name: {"status": "unavailable"} for name in CHANNEL_JOURNEYS}
    channels["unix_loader"]["command"] = "curl -fsSL https://zunderlabs.com/i | sh"
    channels["windows_loader"]["command"] = "irm https://zunderlabs.com/i.ps1 | iex"
    channels["homebrew"]["command"] = "brew install zunderlabs/tap/zunder-guard"
    channels["docker"].update(image="ghcr.io/zunderlabs/zunder-guard", digest="sha256:" + "a" * 64)
    channels["aws_template"]["url"] = "https://example.com/guard/v1.0.0/cloudformation.yaml"
    return {
        "schema": 1,
        "version": "1.0.0",
        "tag": "v1.0.0",
        "commit": "b" * 40,
        "published_at": "2026-10-10T10:00:00Z",
        "stage": "staged",
        "assets": {
            "guard.tar.gz": {
                "sha256": "c" * 64,
                "url": RELEASE_BASE + "/v1.0.0/guard.tar.gz",
            }
        },
        "signing": {
            "identity": IDENTITY_BASE + "@refs/tags/v1.0.0",
            "issuer": "https://token.actions.githubusercontent.com",
        },
        "channels": channels,
        "platforms": ["linux-amd64", "linux-arm64", "darwin-arm64", "windows-amd64"],
        "evidence": {},
    }


def promote(manifest: dict[str, Any]) -> None:
    manifest["stage"] = "promoted"
    for channel in manifest["channels"].values():
        channel["status"] = "verified"
    manifest["evidence"] = {
        journey: f"https://example.com/{journey}" for journey in RELEASE_JOURNEYS
    }


def test_staged(manifest: dict[str, Any]) -> None:
    validate_manifest(manifest, SCHEMA)


def test_promoted(manifest: dict[str, Any]) -> None:
    promote(manifest)
    validate_manifest(
        manifest, SCHEMA, verified_journeys=RELEASE_JOURNEYS, expected_commit="b" * 40
    )


@pytest.mark.parametrize("journey", sorted(RELEASE_JOURNEYS))
def test_every_release_journey_required(manifest: dict[str, Any], journey: str) -> None:
    promote(manifest)
    with pytest.raises(ManifestError, match="lacks verified journeys"):
        validate_manifest(
            manifest,
            SCHEMA,
            verified_journeys=RELEASE_JOURNEYS - {journey},
            expected_commit="b" * 40,
        )


@pytest.mark.parametrize("channel", list(CHANNEL_JOURNEYS))
def test_evidence_links_are_not_proof(manifest: dict[str, Any], channel: str) -> None:
    promote(manifest)
    for name in CHANNEL_JOURNEYS:
        manifest["channels"][name]["status"] = "verified" if name == channel else "unavailable"
    manifest["stage"] = "staged"
    with pytest.raises(ManifestError, match="lacks verified journeys"):
        validate_manifest(manifest, SCHEMA, expected_commit="b" * 40)


def test_commit_binding_required(manifest: dict[str, Any]) -> None:
    promote(manifest)
    with pytest.raises(ManifestError, match="expected release commit"):
        validate_manifest(manifest, SCHEMA, verified_journeys=RELEASE_JOURNEYS)
    with pytest.raises(ManifestError, match="commit differs"):
        validate_manifest(manifest, SCHEMA, expected_commit="d" * 40)


@pytest.mark.parametrize(
    "field,value",
    [
        ("tag", "v1.0.1"),
        ("version", "01.0.0"),
        ("commit", "short"),
        ("published_at", "2026-02-30T10:00:00Z"),
        ("published_at", "2026-10-10T10:00:00+01:00"),
        ("schema", 2),
        ("stage", "released"),
        ("platforms", ["linux-amd64", "linux-amd64"]),
        ("platforms", ["unknown"]),
    ],
)
def test_invalid_fields(manifest: dict[str, Any], field: str, value: Any) -> None:
    manifest[field] = value
    with pytest.raises(ManifestError):
        validate_manifest(manifest, SCHEMA)


def test_extra_fields_rejected(manifest: dict[str, Any]) -> None:
    manifest["operator_attestation"] = True
    with pytest.raises(ManifestError, match="Additional properties"):
        validate_manifest(manifest, SCHEMA)


def test_asset_tag_and_name_binding(manifest: dict[str, Any]) -> None:
    manifest["assets"]["guard.tar.gz"]["url"] = RELEASE_BASE + "/v1.0.1/guard.tar.gz"
    with pytest.raises(ManifestError, match="download URL"):
        validate_manifest(manifest, SCHEMA)


@pytest.mark.parametrize("name", ["release-manifest.json", "SHA256SUMS"])
def test_checksum_cycles_rejected(manifest: dict[str, Any], name: str) -> None:
    manifest["assets"] = {name: {"sha256": "c" * 64, "url": f"{RELEASE_BASE}/v1.0.0/{name}"}}
    with pytest.raises(ManifestError, match="self-referential"):
        validate_manifest(manifest, SCHEMA)


def test_signer_tag_binding(manifest: dict[str, Any]) -> None:
    manifest["signing"]["identity"] = IDENTITY_BASE + "@refs/tags/v1.0.1"
    with pytest.raises(ManifestError, match="identity"):
        validate_manifest(manifest, SCHEMA)


def test_rc_never_promoted(manifest: dict[str, Any]) -> None:
    manifest.update(version="1.0.0-rc.1", tag="v1.0.0-rc.1")
    manifest["signing"]["identity"] = IDENTITY_BASE + "@refs/tags/v1.0.0-rc.1"
    manifest["assets"]["guard.tar.gz"]["url"] = RELEASE_BASE + "/v1.0.0-rc.1/guard.tar.gz"
    manifest["channels"]["aws_template"]["url"] = (
        "https://example.com/guard/v1.0.0-rc.1/cloudformation.yaml"
    )
    validate_manifest(manifest, SCHEMA)
    promote(manifest)
    with pytest.raises(ManifestError, match="candidates"):
        validate_manifest(
            manifest,
            SCHEMA,
            verified_journeys=RELEASE_JOURNEYS,
            expected_commit="b" * 40,
        )


def test_withdrawal_hides_channels(manifest: dict[str, Any]) -> None:
    promote(manifest)
    manifest["stage"] = "withdrawn"
    with pytest.raises(ManifestError, match="withdrawn"):
        validate_manifest(
            manifest,
            SCHEMA,
            verified_journeys=RELEASE_JOURNEYS,
            expected_commit="b" * 40,
        )
    for channel in manifest["channels"].values():
        channel["status"] = "unavailable"
    validate_manifest(manifest, SCHEMA)


def test_evidence_reference_required(manifest: dict[str, Any]) -> None:
    promote(manifest)
    del manifest["evidence"]["P1"]
    with pytest.raises(ManifestError, match="P1"):
        validate_manifest(
            manifest,
            SCHEMA,
            verified_journeys=RELEASE_JOURNEYS,
            expected_commit="b" * 40,
        )
