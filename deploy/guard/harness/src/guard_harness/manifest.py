"""C2 validation. Evidence links are references, never proof by themselves.

The gate must authenticate attestations and their subject commit before it supplies
verified journeys to this validator. Schema-only validation cannot promote a release.
"""

import json
from collections.abc import Mapping, Set
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker

CHANNEL_JOURNEYS: Mapping[str, frozenset[str]] = {
    "unix_loader": frozenset({"I1", "I2", "I3", "T2"}),
    "windows_loader": frozenset({"I4"}),
    "homebrew": frozenset({"I3"}),
    "docker": frozenset({"I5"}),
    "archive": frozenset({"I1", "T1"}),
    "aws_template": frozenset({"I7"}),
    "container_native": frozenset({"I6"}),
}
RELEASE_JOURNEYS = frozenset(
    {f"P{i}" for i in range(1, 9)} | {f"I{i}" for i in range(1, 8)} | {"T1", "T2"}
)
RELEASE_BASE = "https://github.com/zunderlabs/zunder-guard/releases/download"
IDENTITY_BASE = "https://github.com/zunderlabs/zunder-guard/.github/workflows/release.yml"


class ManifestError(ValueError):
    """The release manifest violates C2."""


def validate_manifest(
    manifest: Mapping[str, Any],
    schema_path: Path,
    *,
    verified_journeys: Set[str] = frozenset(),
    expected_commit: str | None = None,
) -> None:
    """Validate structure and gate claims against independently verified journeys."""
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(manifest), key=lambda error: str(error.json_path))
    if errors:
        raise ManifestError("; ".join(f"{e.json_path}: {e.message}" for e in errors))

    try:
        datetime.fromisoformat(manifest["published_at"].replace("Z", "+00:00"))
    except ValueError as error:
        raise ManifestError("published_at must be a real UTC date-time") from error
    tag = manifest["tag"]
    if tag != f"v{manifest['version']}":
        raise ManifestError("tag must match version")
    if expected_commit is not None and manifest["commit"] != expected_commit:
        raise ManifestError("commit differs from the verified release subject")
    if manifest["signing"]["identity"] != f"{IDENTITY_BASE}@refs/tags/{tag}":
        raise ManifestError("signing identity must name this release tag")
    for name, asset in manifest["assets"].items():
        if name in {"SHA256SUMS", "release-manifest.json"}:
            raise ManifestError("manifest cannot include a self-referential checksum asset")
        if asset["url"] != f"{RELEASE_BASE}/{tag}/{name}":
            raise ManifestError(f"asset {name} must use this release's download URL")
    for url in manifest["evidence"].values():
        parsed = urlsplit(url)
        if not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise ManifestError("evidence URLs must have a host and no credentials or fragment")
    template = urlsplit(manifest["channels"]["aws_template"]["url"])
    if template.username or template.password or template.query or template.fragment:
        raise ManifestError("template URL cannot carry credentials, a query or a fragment")
    if not template.path.endswith(f"/guard/{tag}/cloudformation.yaml"):
        raise ManifestError("template URL must be versioned for this release")
    _validate_gate(manifest, verified_journeys, expected_commit)


def _validate_gate(
    manifest: Mapping[str, Any], verified: Set[str], expected_commit: str | None
) -> None:
    evidence = set(manifest["evidence"])
    for channel, required in CHANNEL_JOURNEYS.items():
        if manifest["channels"][channel]["status"] == "verified":
            if expected_commit is None:
                raise ManifestError("verified channels require an expected release commit")
            missing = required - (verified & evidence)
            if missing:
                raise ManifestError(f"{channel} lacks verified journeys: {sorted(missing)}")
    if manifest["stage"] == "withdrawn":
        if any(c["status"] == "verified" for c in manifest["channels"].values()):
            raise ManifestError("withdrawn releases cannot advertise verified channels")
    if manifest["stage"] == "promoted":
        if "-rc." in manifest["version"]:
            raise ManifestError("release candidates cannot be promoted")
        if expected_commit is None:
            raise ManifestError("promotion requires an expected release commit")
        missing = RELEASE_JOURNEYS - (verified & evidence)
        if missing:
            raise ManifestError(f"promotion lacks verified journeys: {sorted(missing)}")
        if any(c["status"] != "verified" for c in manifest["channels"].values()):
            raise ManifestError("promotion requires every v1.0 channel to be verified")
