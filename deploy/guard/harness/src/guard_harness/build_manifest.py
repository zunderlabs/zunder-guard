"""Generate C2 immutable metadata from an explicit set of staged payload files."""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from guard_harness.manifest import IDENTITY_BASE, RELEASE_BASE
from guard_harness.release_state import validate_build

PLATFORMS = ("linux-amd64", "linux-arm64", "darwin-arm64", "darwin-amd64", "windows-amd64")
COMMANDS = {
    "unix_loader": "curl -fsSL https://zunderlabs.com/i | sh",
    "windows_loader": "irm https://zunderlabs.com/i.ps1 | iex",
    "homebrew": "brew install zunderlabs/tap/zunder-guard",
}


def generate(
    assets: list[Path],
    *,
    tag: str,
    commit: str,
    published_at: str,
    docker_digest: str,
    template_url: str,
    schema: Path,
) -> dict[str, Any]:
    entries: dict[str, Any] = {}
    for asset in assets:
        if asset.is_symlink() or not asset.is_file():
            raise ValueError("release payloads must be regular files, never symlinks")
        if asset.name in entries:
            raise ValueError("duplicate payload file name")
        entries[asset.name] = {
            "sha256": hashlib.sha256(asset.read_bytes()).hexdigest(),
            "url": f"{RELEASE_BASE}/{tag}/{asset.name}",
        }
    for platform in PLATFORMS:
        extension = "zip" if platform == "windows-amd64" else "tar.gz"
        if f"zunder-guard-{tag}-{platform}.{extension}" not in entries:
            raise ValueError(f"missing release archive for {platform}")
    distribution: dict[str, Any] = {
        name: {"command": command} for name, command in COMMANDS.items()
    }
    distribution.update(
        {
            "docker": {"image": "ghcr.io/zunderlabs/zunder-guard", "digest": docker_digest},
            "aws_template": {"url": template_url},
            "archive": {},
            "container_native": {},
        }
    )
    manifest = {
        "schema": 2,
        "version": tag.removeprefix("v"),
        "tag": tag,
        "commit": commit,
        "published_at": published_at,
        "assets": entries,
        "signing": {
            "identity": f"{IDENTITY_BASE}@refs/tags/{tag}",
            "issuer": "https://token.actions.githubusercontent.com",
        },
        "platforms": list(PLATFORMS),
        "distribution": distribution,
    }
    validate_build(manifest, schema, expected_commit=commit)
    return manifest


def write_release(manifest: dict[str, Any], output: Path, checksums: Path | None = None) -> None:
    """Write immutable metadata, optionally sealing the complete flat payload set."""
    if checksums is not None:
        if output.name != "release-manifest.json" or checksums.name != "SHA256SUMS":
            raise ValueError("sealed metadata must use the canonical release file names")
        if output.parent.resolve() != checksums.parent.resolve():
            raise ValueError("manifest and checksums must share the release directory")
        if checksums.exists() or checksums.is_symlink():
            raise ValueError("refusing to overwrite release checksums")
        expected = set(manifest["assets"])
        if {path.name for path in output.parent.iterdir()} != expected:
            raise ValueError("release directory differs from the explicit payload inventory")
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    with output.open("xb") as stream:
        stream.write(encoded)
    if checksums is not None:
        hashes = {name: asset["sha256"] for name, asset in manifest["assets"].items()}
        hashes[output.name] = hashlib.sha256(encoded).hexdigest()
        with checksums.open("x", encoding="utf-8") as stream:
            stream.write("".join(f"{hashes[name]}  {name}\n" for name in sorted(hashes)))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ["tag", "commit", "published-at", "docker-digest", "template-url"]:
        parser.add_argument(f"--{argument}", required=True)
    parser.add_argument("--asset", type=Path, action="append", required=True)
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--checksums", type=Path)
    args = parser.parse_args()
    manifest = generate(
        args.asset,
        tag=args.tag,
        commit=args.commit,
        published_at=args.published_at,
        docker_digest=args.docker_digest,
        template_url=args.template_url,
        schema=args.schema,
    )
    write_release(manifest, args.output, args.checksums)


if __name__ == "__main__":
    main()
