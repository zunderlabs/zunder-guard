import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from guard_harness import aws_evidence
from guard_harness.aws_evidence import CONTEXT, predicate
from guard_harness.lifecycle_coverage import LIFECYCLE_COVERAGE
from guard_harness.testnet_run import ROOT, verified_asset

TAG, COMMIT = "v1.0.0-rc.7", "a" * 40
URL = f"https://example.invalid/guard/{TAG}/cloudformation.yaml"
TEMPLATE_SHA = "c" * 64
MANIFEST = json.dumps(
    {
        "tag": TAG,
        "commit": COMMIT,
        "distribution": {"aws_template": {"url": URL}},
        "assets": {"cloudformation.yaml": {"sha256": TEMPLATE_SHA}},
    }
).encode()


def receipt() -> dict[str, Any]:
    return dict(
        result="passed",
        cleanup_complete=True,
        diagnostic=False,
        tag=TAG,
        commit=COMMIT,
        harness_commit=COMMIT,
        coverage=sorted(LIFECYCLE_COVERAGE["I7"] - CONTEXT),
        template_launch=dict(
            channel="cloudformation",
            template_url=URL,
            template_sha256=TEMPLATE_SHA,
            installer_channel="staging",
            stack_create_complete=True,
            instance_online=True,
        ),
    )


def test_complete_literal_aws_channel_and_cleanup_coverage() -> None:
    value = predicate(receipt(), MANIFEST, tag=TAG, commit=COMMIT)
    assert set(value["coverage"]) == LIFECYCLE_COVERAGE["I7"]
    assert "D6:cloudformation" in value["coverage"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("result", "failed"),
        ("cleanup_complete", False),
        ("diagnostic", True),
        ("commit", "b" * 40),
        ("harness_commit", "b" * 40),
        ("tag", "v1.0.0"),
        ("coverage", []),
        ("coverage", ["signed-template-url"]),
        ("coverage", [None]),
    ],
)
def test_no_partial_or_unbound_aws_credit(field: str, value: object) -> None:
    record = receipt()
    record[field] = value
    with pytest.raises(ValueError):
        predicate(record, MANIFEST, tag=TAG, commit=COMMIT)


@pytest.mark.parametrize(
    "field",
    [
        "channel",
        "template_url",
        "template_sha256",
        "installer_channel",
        "stack_create_complete",
        "instance_online",
    ],
)
def test_literal_d6_cannot_be_derived_without_each_measured_launch_field(field: str) -> None:
    record = receipt()
    del record["template_launch"][field]
    with pytest.raises(ValueError):
        predicate(record, MANIFEST, tag=TAG, commit=COMMIT)


@pytest.mark.parametrize("mutation", ["absent", "token-only"])
def test_d6_cannot_replace_template_launch_with_a_coverage_token(mutation: str) -> None:
    record = receipt()
    record.pop("template_launch")
    if mutation == "token-only":
        record["coverage"].append("D6:cloudformation")
    with pytest.raises(ValueError):
        predicate(record, MANIFEST, tag=TAG, commit=COMMIT)


@pytest.mark.parametrize(
    "field,value",
    [
        ("stack_create_complete", 1),
        ("instance_online", 1),
        ("template_url", "https://wrong.invalid/template"),
        ("template_sha256", "d" * 64),
    ],
)
def test_d6_rejects_unmeasured_or_different_template_identity(field: str, value: object) -> None:
    record = receipt()
    record["template_launch"][field] = value
    with pytest.raises(ValueError):
        predicate(record, MANIFEST, tag=TAG, commit=COMMIT)


def public_assets(tmp_path: Path) -> tuple[Path, Path, bytes]:
    source, work = tmp_path / "subjects", tmp_path / "work"
    source.mkdir(mode=0o755)
    work.mkdir(mode=0o700)
    template = b"synthetic signed-template payload fixture\n"
    build = json.loads((ROOT / "release/examples/build-v2.json").read_bytes())
    build.update(tag=TAG, version=TAG.removeprefix("v"), commit=COMMIT)
    build["signing"]["identity"] = (
        "https://github.com/zunderlabs/zunder-guard/.github/workflows/release.yml@refs/tags/" + TAG
    )
    build["assets"] = {
        "cloudformation.yaml": {
            "sha256": hashlib.sha256(template).hexdigest(),
            "url": f"https://github.com/zunderlabs/zunder-guard/releases/download/{TAG}/cloudformation.yaml",
        }
    }
    build["distribution"]["aws_template"]["url"] = URL
    manifest = json.dumps(build).encode()
    files = {
        "cloudformation.yaml": template,
        "release-manifest.json": manifest,
        ".verified-release-source.json": json.dumps({"tag": TAG, "source": COMMIT}).encode(),
        "SHA256SUMS": (
            hashlib.sha256(template).hexdigest()
            + "  cloudformation.yaml\n"
            + hashlib.sha256(manifest).hexdigest()
            + "  release-manifest.json\n"
        ).encode(),
    }
    for name, body in files.items():
        (source / name).write_bytes(body)
        (source / name).chmod(0o644)  # Public artifact extraction normalizes file modes.
    return source, work, manifest


def test_public_artifact_is_verified_through_owned_private_copy_without_shared_chmod(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, work, manifest = public_assets(tmp_path)
    before = {path.name: (path.read_bytes(), path.stat().st_mode) for path in source.iterdir()}
    original = verified_asset
    snapshots: list[Path] = []

    def verify(assets: Path, name: str, *, tag: str, commit: str) -> tuple[bytes, str]:
        snapshots.append(assets)
        assert assets.parent == work and assets != source
        assert assets.stat().st_mode & 0o777 == 0o700
        assert all(path.stat().st_mode & 0o777 == 0o600 for path in assets.iterdir())
        return original(assets, name, tag=tag, commit=commit)

    monkeypatch.setattr(aws_evidence, "verified_asset", verify)
    assert aws_evidence.admitted_manifest(source, work, tag=TAG, commit=COMMIT) == manifest
    assert snapshots and not snapshots[0].exists()
    assert before == {
        path.name: (path.read_bytes(), path.stat().st_mode) for path in source.iterdir()
    }
    assert source.stat().st_mode & 0o777 == 0o755
    assert list(work.iterdir()) == []


@pytest.mark.parametrize(
    "mutation",
    [
        "source",
        "tag",
        "manifest",
        "template",
        "duplicate",
        "symlink",
        "hardlink",
        "parent-symlink",
        "writable",
        "oversize",
        "public-work",
    ],
)
def test_private_snapshot_rejects_relabel_tamper_links_and_unsafe_permissions(
    tmp_path: Path, mutation: str
) -> None:
    source, work, _ = public_assets(tmp_path)
    if mutation in {"source", "tag"}:
        value = {"tag": TAG, "source": COMMIT}
        value[mutation] = "b" * 40 if mutation == "source" else "v9.0.0"
        (source / ".verified-release-source.json").write_text(json.dumps(value))
    elif mutation in {"manifest", "template"}:
        name = "release-manifest.json" if mutation == "manifest" else "cloudformation.yaml"
        with (source / name).open("ab") as stream:
            stream.write(b" ")
    elif mutation == "duplicate":
        path = source / "SHA256SUMS"
        path.write_bytes(path.read_bytes() * 2)
    elif mutation in {"symlink", "hardlink"}:
        path = source / "cloudformation.yaml"
        other = tmp_path / "other-template"
        path.rename(other)
        if mutation == "symlink":
            path.symlink_to(other)
        else:
            path.hardlink_to(other)
    elif mutation == "parent-symlink":
        alias = tmp_path / "alias"
        alias.symlink_to(source, target_is_directory=True)
        source = alias
    elif mutation == "writable":
        (source / "cloudformation.yaml").chmod(0o666)
    elif mutation == "oversize":
        (source / ".verified-release-source.json").write_bytes(b" " * 257)
    else:
        work.chmod(0o755)
    with pytest.raises((ValueError, RuntimeError, OSError)):
        aws_evidence.admitted_manifest(source, work, tag=TAG, commit=COMMIT)
    assert list(work.iterdir()) == []


def test_i7_cli_admits_same_run_public_snapshot_without_rewriting_assets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, work, manifest = public_assets(tmp_path)
    value = receipt()
    value["template_launch"]["template_sha256"] = hashlib.sha256(
        (source / "cloudformation.yaml").read_bytes()
    ).hexdigest()
    (work / "aws.receipt.json").write_text(json.dumps(value))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "aws_evidence",
            "--assets",
            str(source),
            "--work",
            str(work),
            "--tag",
            TAG,
            "--commit",
            COMMIT,
        ],
    )
    assert aws_evidence.main() == 0
    proof = json.loads((work / "I7.predicate.json").read_bytes())
    assert proof["manifest_sha256"] == hashlib.sha256(manifest).hexdigest()
    assert proof["coverage"] == sorted(LIFECYCLE_COVERAGE["I7"])
    assert not list(work.glob("aws-evidence-*"))
    assert all(file.stat().st_mode & 0o777 == 0o644 for file in source.iterdir())
