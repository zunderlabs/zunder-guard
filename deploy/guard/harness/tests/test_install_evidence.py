import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from guard_harness.install_evidence import (
    DOCKER_PAPER,
    DOCKER_TESTNET,
    PAPER,
    ROWS,
    TESTNET,
    EvidenceError,
    predicate,
)
from guard_harness.native_release import Release
from guard_harness.testnet_process import ProcessError
from guard_harness.testnet_run import ROOT

COMMIT = "b" * 40
OLD_COMMIT = "c" * 40


def write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


def release(path: Path, *, old: bool = False) -> Release:
    build = json.loads((ROOT / "release/examples/build-v2.json").read_bytes())
    build.update(
        tag="v0.9.0" if old else "v1.0.0",
        version="0.9.0" if old else "1.0.0",
        commit=OLD_COMMIT if old else COMMIT,
    )
    build["distribution"]["docker"]["digest"] = "sha256:" + ("d" if old else "a") * 64
    build["signing"]["identity"] = (
        "https://github.com/zunderlabs/zunder-guard/.github/workflows/release.yml@refs/tags/"
        + build["tag"]
    )
    build["distribution"]["aws_template"]["url"] = (
        f"https://example.com/guard/{build['tag']}/cloudformation.yaml"
    )
    bodies = {
        "i": b"old loader" if old else b"candidate loader",
        "install.sh": b"old installer" if old else b"candidate installer",
        "compose.yaml": b"signed compose",
    }
    build["assets"] = {
        name: {
            "sha256": hashlib.sha256(body).hexdigest(),
            "url": f"https://github.com/zunderlabs/zunder-guard/releases/download/{build['tag']}/{name}",
        }
        for name, body in bodies.items()
    }
    path.mkdir(parents=True)
    bodies["release-manifest.json"] = json.dumps(build).encode()
    for name, body in bodies.items():
        (path / name).write_bytes(body)
    (path / "SHA256SUMS").write_text(
        "".join(f"{hashlib.sha256(body).hexdigest()}  {name}\n" for name, body in bodies.items())
    )
    write(path / ".verified-release-source.json", {"tag": build["tag"], "source": build["commit"]})
    return Release(build["tag"], build["commit"], path)


def fixture(tmp_path: Path, row: str) -> tuple[Path, Path, Path]:
    subjects, evidence = tmp_path / "subjects", tmp_path / "evidence"
    current = release(subjects / "candidate/assets")
    old = release(subjects / "previous/assets", old=True)
    write(
        subjects / "input.json",
        dict(
            tag=current.tag,
            commit=COMMIT,
            previous_tag=old.tag,
            previous_commit=OLD_COMMIT,
            harness_commit=COMMIT,
            diagnostic=False,
            loader_channel="staging",
        ),
    )
    (subjects / "i-staging").write_bytes(current.asset("i"))
    if row == "I5":
        image = "ghcr.io/zunderlabs/zunder-guard@sha256:" + "a" * 64
        old_image = "ghcr.io/zunderlabs/zunder-guard@sha256:" + "d" * 64
        write(
            evidence / "receipt.json",
            dict(
                tag=current.tag,
                commit=COMMIT,
                harness_commit=COMMIT,
                diagnostic=False,
                manifest_sha256=hashlib.sha256(current.asset("release-manifest.json")).hexdigest(),
                image=image,
                compose_sha256=hashlib.sha256(current.asset("compose.yaml")).hexdigest(),
                previous_release=dict(
                    tag=old.tag,
                    commit=OLD_COMMIT,
                    manifest_sha256=hashlib.sha256(old.asset("release-manifest.json")).hexdigest(),
                    image=old_image,
                ),
            ),
        )
        for channel in ("docker", "compose"):
            for mode, checks in (("paper", DOCKER_PAPER), ("testnet", DOCKER_TESTNET)):
                write(
                    evidence / f"{channel}-{mode}/receipt.json",
                    dict(
                        schema=1,
                        result="passed",
                        mode=mode,
                        channel=channel,
                        image=image,
                        previous_image=old_image,
                        checks=sorted(checks),
                        cleanup_complete=True,
                        state_preserved=True,
                        pairing_preserved=True,
                        journal_preserved=True,
                        no_exchange=True,
                        custody="documented-volume" if channel == "docker" else "compose-secret",
                    ),
                )
    else:
        for mode, checks, name in (
            ("paper", PAPER, "linux-lifecycle.json"),
            ("testnet", TESTNET, "testnet-lifecycle.json"),
        ):
            coverage = checks | ({"kernel-reboot"} if row != "I2" else set())
            write(
                evidence / mode / name,
                dict(
                    schema=1,
                    result="passed",
                    stage="passed",
                    mode=mode,
                    route=ROWS[row][0],
                    architecture=ROWS[row][1],
                    coverage=sorted(coverage),
                    cleanup_complete=True,
                    state_preserved=True,
                    pairing_preserved=True,
                    journal_preserved=True,
                    no_exchange=True,
                    custody="systemd-creds",
                    version=current.tag,
                    previous_version=old.tag,
                    installer_sha256=hashlib.sha256(current.asset("i")).hexdigest(),
                    previous_installer_sha256=hashlib.sha256(old.asset("install.sh")).hexdigest(),
                    reboot_required=row != "I2",
                    boot_id="11111111-1111-1111-1111-111111111111",
                    reboot_boot_id="22222222-2222-2222-2222-222222222222",
                    guest_acceleration="kvm",
                    gate_eligible=True,
                ),
            )
    return subjects, evidence, current.assets / "release-manifest.json"


@pytest.mark.parametrize("row", ["I1", "I2", "I5", "I6"])
def test_both_modes_on_exact_subjects_admit_only_complete_row(tmp_path: Path, row: str) -> None:
    subjects, evidence, manifest = fixture(tmp_path, row)
    value = predicate(row, evidence, subjects, manifest, COMMIT)
    assert set(value) == {
        "schema",
        "journey",
        "commit",
        "manifest_sha256",
        "result",
        "tier",
        "coverage",
    }
    assert value["journey"] == row and value["result"] == "passed"


@pytest.mark.parametrize("mutation", ["missing-uninstall", "retirement-only"])
def test_sending_container_requires_actual_uninstall_not_supervisor_retirement(
    tmp_path: Path, mutation: str
) -> None:
    subjects, evidence, manifest = fixture(tmp_path, "I6")
    path = evidence / "testnet/testnet-lifecycle.json"
    value = json.loads(path.read_bytes())
    checks = set(value["coverage"])
    checks.remove("uninstall")
    if mutation == "retirement-only":
        checks.add("supervisor-retired")
    value["coverage"] = sorted(checks)
    write(path, value)
    with pytest.raises(EvidenceError):
        predicate("I6", evidence, subjects, manifest, COMMIT)


@pytest.mark.parametrize(
    "mutation",
    [
        "paper-only",
        "diagnostic",
        "source",
        "channel",
        "loader",
        "previous",
        "architecture",
        "cleanup",
        "history",
        "same-boot",
        "fake-guest",
        "no-reboot-coverage",
        "exchange",
        "stage-only",
    ],
)
def test_linux_mutations_never_credit_partial_receipts(tmp_path: Path, mutation: str) -> None:
    subjects, evidence, manifest = fixture(tmp_path, "I1")
    target = evidence / "testnet/testnet-lifecycle.json"
    if mutation == "paper-only":
        target.unlink()
    elif mutation in {"diagnostic", "source", "channel"}:
        target = subjects / "input.json"
        value = json.loads(target.read_bytes())
        identity_patch: dict[str, Any] = (
            {"diagnostic": True}
            if mutation == "diagnostic"
            else {"harness_commit": OLD_COMMIT}
            if mutation == "source"
            else {"loader_channel": "canonical"}
        )
        value.update(identity_patch)
        write(target, value)
    elif mutation == "loader":
        (subjects / "i-staging").write_bytes(b"another candidate")
    else:
        value = json.loads(target.read_bytes())
        patch = {
            "previous": {"previous_installer_sha256": "f" * 64},
            "architecture": {"architecture": "arm64"},
            "cleanup": {"cleanup_complete": False},
            "history": {"journal_preserved": False},
            "same-boot": {"reboot_boot_id": value["boot_id"]},
            "fake-guest": {"guest_acceleration": "tcg"},
            "no-reboot-coverage": {"coverage": sorted(TESTNET)},
            "exchange": {"no_exchange": False},
            "stage-only": {"coverage": []},
        }[mutation]
        value.update(patch)
        write(target, value)
    with pytest.raises((EvidenceError, ProcessError)):
        predicate("I1", evidence, subjects, manifest, COMMIT)


@pytest.mark.parametrize(
    "mutation",
    ["paper-only", "wrong-compose", "wrong-image", "missing-upgrade", "cleanup", "custody"],
)
def test_docker_requires_both_channels_and_real_testnet_completion(
    tmp_path: Path, mutation: str
) -> None:
    subjects, evidence, manifest = fixture(tmp_path, "I5")
    target = evidence / "compose-testnet/receipt.json"
    if mutation == "paper-only":
        target.unlink()
    else:
        if mutation == "wrong-compose":
            target = evidence / "receipt.json"
        value = json.loads(target.read_bytes())
        value.update(
            {
                "wrong-compose": {"compose_sha256": "f" * 64},
                "wrong-image": {"image": "sha256:" + "f" * 64},
                "missing-upgrade": {"checks": sorted(DOCKER_TESTNET - {"upgrade"})},
                "cleanup": {"cleanup_complete": False},
                "custody": {"custody": "unsupported"},
            }[mutation]
        )
        write(target, value)
    with pytest.raises(EvidenceError):
        predicate("I5", evidence, subjects, manifest, COMMIT)
