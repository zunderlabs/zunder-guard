"""C1-bound, nongate rehearsal of one outer installer on unchanged C2 assets."""

import hashlib
import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from guard_harness.testnet_process import ProcessError
from guard_harness.testnet_run import ROOT

PATH = "deploy/guard/install.sh"
TOKEN = b'VERSION="@VERSION@"'
SHA = re.compile(r"[0-9a-f]{40}\Z")


def need(condition: bool) -> None:
    if not condition:
        raise ProcessError("C1 source installer diagnostic admission refused")


def enabled() -> bool:
    flag = os.environ.get("SOURCE_INSTALLER_DIAGNOSTIC", "false")
    need(flag in {"true", "false"})
    return flag == "true"


def verify_file(path: Path, digest: str) -> None:
    need(re.fullmatch(r"[0-9a-f]{64}", digest) is not None)
    need(not path.is_symlink() and path.is_file())
    stat = path.stat()
    need(stat.st_nlink == 1 and 0 < stat.st_size <= 512 * 1024)
    need(hashlib.sha256(path.read_bytes()).hexdigest() == digest)


def component_metadata(
    flag: bool, harness_commit: str, digest: str, *, scenario: str, actual_digest: str
) -> dict[str, object]:
    need(type(flag) is bool)
    if not flag and not harness_commit and not digest:
        return {}
    need(
        type(flag) is bool
        and flag
        and scenario == "fresh"
        and SHA.fullmatch(harness_commit) is not None
        and re.fullmatch(r"[0-9a-f]{64}", digest) is not None
        and digest == actual_digest
    )
    return {
        "source_component": True,
        "diagnostic": True,
        "gate_eligible": False,
        "installer_harness_commit": harness_commit,
        "installer_rendered_sha256": digest,
    }


def git(*args: str) -> bytes:
    result = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, timeout=5, check=False)
    need(result.returncode == 0 and len(result.stdout) <= 512 * 1024)
    return result.stdout


@dataclass(frozen=True)
class Candidate:
    rendered: bytes
    harness_commit: str
    template_sha256: str
    tag: str
    release_commit: str

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.rendered).hexdigest()

    def record(self) -> dict[str, object]:
        return {
            "source_component": True,
            "diagnostic": True,
            "gate_eligible": False,
            "installer_harness_commit": self.harness_commit,
            "installer_template_sha256": self.template_sha256,
            "installer_rendered_sha256": self.digest,
            "tag": self.tag,
            "release_commit": self.release_commit,
        }

    def stage(self, directory: Path) -> Path:
        path = directory / "source-install.sh"
        with path.open("xb") as stream:
            path.chmod(0o600)
            stream.write(self.rendered)
            stream.flush()
            os.fsync(stream.fileno())
        verify_file(path, self.digest)
        with (directory / "source-installer.json").open("x") as stream:
            stream.write(json.dumps(self.record(), sort_keys=True) + "\n")
        return path


def prepare(tag: str, release_commit: str, *, scenario: str, row: str) -> Candidate | None:
    if not enabled():
        return None
    env = os.environ
    head = env.get("GITHUB_SHA", "")
    ref = env.get("CALLER_REF", "")
    need(
        row in {"I1", "I6", "I3"}
        and scenario == env.get("SCENARIO") == "fresh"
        and env.get("INSTALL_MATRIX_TARGET") == "unix"
        and env.get("INSTALL_MATRIX_PROFILE") == "all"
        and env.get("DIAGNOSTIC") == "true"
        and env.get("CALLER_EVENT") == "workflow_dispatch"
        and env.get("CALLER_REPOSITORY") == "zunderlabs/zunder-guard"
        and env.get("CALLER_SHA") == head
        and SHA.fullmatch(head) is not None
        and re.fullmatch(r"refs/heads/(?:main|preview/[a-z0-9-]+)", ref) is not None
        and env.get("WORKFLOW_REF")
        == "zunderlabs/zunder-guard/.github/workflows/install-matrix.yml@" + ref
    )
    need(re.fullmatch(r"v\d+\.\d+\.\d+(?:-rc\.[1-9]\d*)?", tag) is not None)
    need(SHA.fullmatch(release_commit) is not None)
    need(git("rev-parse", "HEAD").decode().strip() == head)
    authors = git("show", "-s", "--format=%an <%ae>%n%cn <%ce>", head).decode().splitlines()
    need(authors == ["Zunder Labs <export@zunderlabs.com>"] * 2)
    message = git("show", "-s", "--format=%B", head).decode()
    source = re.findall(r"^Zunder-Source: ([0-9a-f]{40})$", message, re.M)
    tree = re.findall(r"^Zunder-Export-Tree: ([0-9a-f]{40})$", message, re.M)
    manifest = re.findall(r"^Zunder-Export-Manifest: ([0-9a-f]{64})$", message, re.M)
    need(len(source) == len(tree) == len(manifest) == 1)
    need(git("rev-parse", head + "^{tree}").decode().strip() == tree[0])
    template = git("show", head + ":" + PATH)
    verify_file(ROOT / "install.sh", hashlib.sha256(template).hexdigest())
    need(template.count(TOKEN) == 1)
    rendered = template.replace(TOKEN, ('VERSION="' + tag + '"').encode(), 1)
    return Candidate(rendered, head, hashlib.sha256(template).hexdigest(), tag, release_commit)
