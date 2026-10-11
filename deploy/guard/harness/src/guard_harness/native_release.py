"""Authenticate two immutable releases and snapshot the exact staged installer bytes."""

import argparse
import hashlib
import io
import json
import os
import re
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from urllib.request import Request, urlopen

from guard_harness.release_state import validate_build
from guard_harness.runner import run
from guard_harness.testnet_process import ProcessError
from guard_harness.testnet_run import ROOT


@dataclass(frozen=True)
class Release:
    tag: str
    commit: str
    assets: Path

    def asset(self, name: str) -> bytes:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name) or ".." in name:
            raise ProcessError("release asset name refused")
        marker = json.loads((self.assets / ".verified-release-source.json").read_bytes())
        if marker != {"tag": self.tag, "source": self.commit}:
            raise ProcessError("authenticated release source differs")
        build_bytes = (self.assets / "release-manifest.json").read_bytes()
        build = json.loads(build_bytes)
        validate_build(build, ROOT / "release/manifest.schema.json", expected_commit=self.commit)
        entries: dict[str, str] = {}
        for line in (self.assets / "SHA256SUMS").read_text().splitlines():
            match = re.fullmatch(r"([0-9a-f]{64}) [ *]([A-Za-z0-9][A-Za-z0-9._-]*)", line)
            if match is None or match[2] in entries:
                raise ProcessError("signed checksum inventory refused")
            entries[match[2]] = match[1]
        subject = self.assets / name
        if subject.is_symlink() or not subject.is_file() or subject.stat().st_nlink != 1:
            raise ProcessError("release asset must be a regular snapshot")
        if not 0 < subject.stat().st_size <= 128 * 1024 * 1024:
            raise ProcessError("release asset size refused")
        body = subject.read_bytes()
        if (
            build["tag"] != self.tag
            or entries.get("release-manifest.json") != hashlib.sha256(build_bytes).hexdigest()
            or entries.get(name) != hashlib.sha256(body).hexdigest()
            or (
                name != "release-manifest.json"
                and build["assets"].get(name, {}).get("sha256") != entries.get(name)
            )
        ):
            raise ProcessError("release snapshot differs from authenticated C2 bytes")
        return body

    def binary(self, target: str) -> bytes:
        suffix = "zip" if target == "windows-amd64" else "tar.gz"
        archive = self.asset(f"zunder-guard-{self.tag}-{target}.{suffix}")
        return archive_binary(archive, windows=suffix == "zip")


def archive_binary(archive: bytes, *, windows: bool) -> bytes:
    """Read only one flat regular binary; never extract archive-controlled paths."""
    binary_name = "zunder-guard.exe" if windows else "zunder-guard"
    names = {binary_name, "README.md", "LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.md"}
    if not windows:
        names.add("zunder-guard.service")
    files: dict[str, bytes] = {}
    if windows:
        with zipfile.ZipFile(io.BytesIO(archive)) as source:
            for item in source.infolist():
                if item.filename not in names or item.filename in files or item.is_dir():
                    raise ProcessError("release archive member refused")
                if item.external_attr >> 16 & 0o170000 == 0o120000:
                    raise ProcessError("release archive symlink refused")
                if not 0 <= item.file_size <= 128 * 1024 * 1024:
                    raise ProcessError("release archive size refused")
                files[item.filename] = source.read(item)
    else:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as source:
            for member in source:
                if member.name not in names or member.name in files or not member.isfile():
                    raise ProcessError("release archive member refused")
                if not 0 <= member.size <= 128 * 1024 * 1024:
                    raise ProcessError("release archive size refused")
                stream = source.extractfile(member)
                if stream is None:
                    raise ProcessError("release archive member missing")
                with stream:
                    files[member.name] = stream.read()
    if not files.get(binary_name) or sum(map(len, files.values())) > 256 * 1024 * 1024:
        raise ProcessError("release archive binary/size refused")
    return files[binary_name]


def authenticate(tag: str, commit: str, work: Path) -> Release:
    if not re.fullmatch(r"v\d+\.\d+\.\d+(?:-rc\.[1-9]\d*)?", tag) or not re.fullmatch(
        r"[0-9a-f]{40}", commit
    ):
        raise ProcessError("exact release identity required")
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    env = dict(os.environ)
    env["GITHUB_REPOSITORY"] = "zunderlabs/zunder-guard"
    run(
        ["bash", str(ROOT / "github/verify-release-assets.sh"), tag, str(work / "assets")],
        env=env,
        log=work / "authenticate.log",
        timeout=600,
        secrets=[env.get("GH_TOKEN", ""), env.get("GITHUB_TOKEN", "")],
    )
    release = Release(tag, commit, work / "assets")
    # Authentication marker alone is insufficient: recheck signed C2 identity and bytes.
    release.asset("install.sh")
    return release


def staged_loader(
    release: Release, *, windows: bool, output: Path, channel: str = "staging"
) -> Path:
    asset = "i.ps1" if windows else "i"
    if channel not in ("staging", "canonical"):
        raise ProcessError("unknown loader channel")
    route = "i-staging" if channel == "staging" else "i"
    url = "https://zunderlabs.com/" + route + (".ps1" if windows else "")
    with urlopen(
        Request(url, headers={"User-Agent": "zunder-guard-release/1.0"}), timeout=45
    ) as response:
        if response.geturl() != url or response.status != 200:
            raise ProcessError("staging loader redirect/status refused")
        body = response.read(2 * 1024 * 1024 + 1)
    if body != release.asset(asset):
        raise ProcessError("staged loader differs from authenticated release")
    output.write_bytes(body)
    output.chmod(0o600)
    return output


def diagnostic_mode() -> bool:
    value = os.environ.get("DIAGNOSTIC", "false")
    if value not in {"true", "false"}:
        raise ProcessError("explicit diagnostic boolean required")
    return value == "true"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("tag", "commit", "previous-tag", "previous-commit"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--loader-channel", choices=("staging", "canonical"), default="staging")
    args = parser.parse_args()
    diagnostic = diagnostic_mode()
    if not args.work.is_absolute() or args.work.exists() or args.previous_tag == args.tag:
        raise ProcessError("fresh workspace and distinct predecessor required")
    args.work.mkdir(mode=0o700)
    old_mask = os.umask(0o077)
    try:
        current = authenticate(args.tag, args.commit, args.work / "candidate")
        previous = authenticate(args.previous_tag, args.previous_commit, args.work / "previous")
        staged_loader(
            current, windows=False, output=args.work / "i-staging", channel=args.loader_channel
        )
        staged_loader(
            current, windows=True, output=args.work / "i-staging.ps1", channel=args.loader_channel
        )
        values = {
            "diagnostic": diagnostic,
            "loader_channel": args.loader_channel,
            "harness_commit": os.environ.get("GITHUB_SHA", ""),
            "tag": args.tag,
            "commit": args.commit,
            "previous_tag": args.previous_tag,
            "previous_commit": args.previous_commit,
            "installer_sha256": hashlib.sha256(current.asset("install.sh")).hexdigest(),
            "previous_installer_sha256": hashlib.sha256(previous.asset("install.sh")).hexdigest(),
        }
        (args.work / "input.json").write_text(json.dumps(values) + "\n")
    finally:
        os.umask(old_mask)


if __name__ == "__main__":
    main()
