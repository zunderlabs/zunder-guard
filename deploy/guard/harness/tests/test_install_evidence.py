import hashlib
import io
import json
import tarfile
import zipfile
from pathlib import Path
from typing import Any

import pytest

from guard_harness.channel_evidence import REQUIRED
from guard_harness.install_evidence import (
    DOCKER_PAPER,
    DOCKER_TESTNET,
    PAPER,
    ROWS,
    TESTNET,
    EvidenceError,
    predicate,
)
from guard_harness.lifecycle_coverage import LIFECYCLE_COVERAGE
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
        "i.ps1": b"old Windows loader" if old else b"candidate Windows loader",
        "install.sh": b"old installer" if old else b"candidate installer",
        "compose.yaml": b"signed compose",
    }
    for target in ("linux-amd64", "linux-arm64", "darwin-arm64", "windows-amd64"):
        binary = ("inert archive fixture " + build["tag"] + target).encode()
        buffer = io.BytesIO()
        if target == "windows-amd64":
            with zipfile.ZipFile(buffer, "w") as archive:
                archive.writestr("zunder-guard.exe", binary)
            suffix = "zip"
        else:
            with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
                info = tarfile.TarInfo("zunder-guard")
                info.size = len(binary)
                archive.addfile(info, io.BytesIO(binary))
            suffix = "tar.gz"
        bodies[f"zunder-guard-{build['tag']}-{target}.{suffix}"] = buffer.getvalue()
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
    for scenario in ("fresh", "upgrade"):
        initial = current if scenario == "fresh" else old
        if row == "I5":
            for channel in ("docker", "compose"):
                root = json.loads((evidence / "receipt.json").read_bytes())
                root.update(scenario=scenario, channel=channel)
                write(evidence / scenario / channel / "receipt.json", root)
                for mode in ("paper", "testnet"):
                    value = json.loads((evidence / f"{channel}-{mode}/receipt.json").read_bytes())
                    checks = set(value["checks"])
                    if scenario == "fresh":
                        checks -= {"upgrade", "upgrade-journal", "upgrade-pairing"}
                        checks.add("fresh-candidate-" + mode)
                    value.update(
                        scenario=scenario,
                        initial_image=image if scenario == "fresh" else old_image,
                        initial_version=initial.tag.removeprefix("v"),
                        version=current.tag.removeprefix("v"),
                        checks=sorted(checks),
                        previous_image=None if scenario == "fresh" else old_image,
                        decision_journal_sha256="e" * 64,
                    )
                    write(evidence / mode / scenario / channel / "receipt.json", value)
        else:
            for mode, filename in (
                ("paper", "linux-lifecycle.json"),
                ("testnet", "testnet-lifecycle.json"),
            ):
                value = json.loads((evidence / mode / filename).read_bytes())
                checks = set(value["coverage"])
                if scenario == "fresh":
                    checks.remove("upgrade")
                    checks.discard("paper-post-upgrade-allow-resize-veto")
                    checks.add("fresh-candidate-" + mode)
                if row == "I6" and mode == "testnet":
                    value["owned_software_inventory"] = {
                        "/usr/local/libexec/zunder-guard-container/" + name: "a" * 64
                        for name in (
                            "supervisor.py",
                            "operations.py",
                            "zunder-guard-container.service",
                        )
                    }
                    value["owned_software_inventory"].update(
                        {
                            "/etc/systemd/system/zunder-guard-container.service": "a" * 64,
                            "/etc/systemd/system/zunder-guard-setup-guardian.service": "a" * 64,
                            "/usr/local/libexec/zunder-guard-container": "directory",
                        }
                    )
                    checks.update(
                        {
                            "uninstall-live-stop",
                            "uninstall-transaction-refusal",
                            "owned-software-inventory",
                        }
                    )
                value.update(
                    scenario=scenario,
                    initial_release=dict(
                        version=initial.tag,
                        installer_sha256=hashlib.sha256(
                            current.asset("i") if scenario == "fresh" else old.asset("install.sh")
                        ).hexdigest(),
                    ),
                    coverage=sorted(checks),
                    exchange_requests=0,
                    exchange_evidence="complete-durable-decision-journal",
                    channel_coverage=["D7:container-native"] if row == "I6" else [],
                    installer_route=(
                        "curl -fsSL https://zunderlabs.com/i-staging | sh -s -- "
                        "--container --network paper"
                    )
                    if scenario == "fresh" and mode == "paper"
                    else "sh <authenticated-loader> --container --network " + mode,
                    binary_sha256=hashlib.sha256(
                        current.binary("linux-" + ROWS[row][1])
                    ).hexdigest(),
                    previous_binary_sha256=hashlib.sha256(
                        old.binary("linux-" + ROWS[row][1])
                    ).hexdigest(),
                    runtime_identity_evidence="native-file-sha256"
                    if row != "I6"
                    else "signed-immutable-prebuilt-image",
                    image="ghcr.io/zunderlabs/zunder-guard@sha256:" + "a" * 64,
                    previous_image="ghcr.io/zunderlabs/zunder-guard@sha256:" + "d" * 64,
                    initial_image="ghcr.io/zunderlabs/zunder-guard@sha256:"
                    + ("a" if scenario == "fresh" else "d") * 64,
                )
                if scenario == "fresh":
                    value.pop("previous_image", None)
                    value.pop("previous_binary_sha256", None)
                write(evidence / mode / scenario / filename, value)
    if row in {"I1", "I2"}:
        target = "linux-" + ROWS[row][1]
        for channel in ("D1", "D5") if row == "I1" else ("D1",):
            write(
                evidence / f"channels/{channel}.json",
                dict(
                    schema=1,
                    result="passed",
                    channel=channel,
                    scenario="fresh",
                    mode="paper",
                    tag=current.tag,
                    commit=COMMIT,
                    manifest_sha256=hashlib.sha256(
                        current.asset("release-manifest.json")
                    ).hexdigest(),
                    installed_binary_sha256=hashlib.sha256(current.binary(target)).hexdigest(),
                    version=current.tag.removeprefix("v"),
                    cleanup_complete=True,
                    executions=[
                        dict(
                            form=form,
                            command="curl -fsSL https://zunderlabs.com/i-staging | sh"
                            + (" -s -- --network paper" if form == "website-parameter" else ""),
                            result="passed",
                            installed_binary_sha256=hashlib.sha256(
                                current.binary(target)
                            ).hexdigest(),
                            version=current.tag.removeprefix("v"),
                            mode="paper",
                            account_network="testnet",
                            health=True,
                            paper_roundtrip=True,
                            owned_process_stopped=True,
                            cleanup_method="released-native-uninstall",
                            cleanup_complete=True,
                        )
                        for form in ("manifest-bare", "website-parameter")
                    ]
                    if channel == "D1"
                    else [],
                    coverage=sorted(REQUIRED[channel]),
                    command="curl -fsSL https://zunderlabs.com/i-staging | sh",
                    loader_sha256=hashlib.sha256(current.asset("i")).hexdigest(),
                    archive_sha256=hashlib.sha256(
                        current.asset(f"zunder-guard-{current.tag}-{target}.tar.gz")
                    ).hexdigest(),
                ),
            )
    return subjects, evidence, current.assets / "release-manifest.json"


@pytest.mark.parametrize("row", ["I1", "I2", "I5", "I6"])
def test_both_modes_on_exact_subjects_admit_only_complete_row(tmp_path: Path, row: str) -> None:
    subjects, evidence, manifest = fixture(tmp_path, row)
    value = predicate(row, evidence, subjects, manifest, COMMIT)
    assert value["coverage"] == sorted(LIFECYCLE_COVERAGE[row])
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
    path = evidence / "testnet/upgrade/testnet-lifecycle.json"
    value = json.loads(path.read_bytes())
    checks = set(value["coverage"])
    checks.remove("uninstall")
    if mutation == "retirement-only":
        checks.add("supervisor-retired")
    value["coverage"] = sorted(checks)
    write(path, value)
    with pytest.raises(EvidenceError):
        predicate("I6", evidence, subjects, manifest, COMMIT)


@pytest.mark.parametrize("row", ["I1", "I2", "I5", "I6"])
def test_unrecognized_lifecycle_claim_cannot_enter_attestation(tmp_path: Path, row: str) -> None:
    subjects, evidence, manifest = fixture(tmp_path, row)
    path = evidence / (
        "paper/fresh/docker/receipt.json" if row == "I5" else "paper/fresh/linux-lifecycle.json"
    )
    value = json.loads(path.read_bytes())
    field = "coverage" if "coverage" in value else "checks"
    value[field].append("unrecognized-runtime-claim")
    write(path, value)
    with pytest.raises(EvidenceError):
        predicate(row, evidence, subjects, manifest, COMMIT)


def test_unrecognized_documented_channel_claim_is_refused(tmp_path: Path) -> None:
    subjects, evidence, manifest = fixture(tmp_path, "I1")
    path = evidence / "channels/D1.json"
    value = json.loads(path.read_bytes())
    value["coverage"].append("unrecognized-runtime-claim")
    write(path, value)
    with pytest.raises(ProcessError):
        predicate("I1", evidence, subjects, manifest, COMMIT)


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
    target = evidence / "testnet/upgrade/testnet-lifecycle.json"
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
    target = evidence / "testnet/upgrade/compose/receipt.json"
    if mutation == "paper-only":
        target.unlink()
    else:
        if mutation == "wrong-compose":
            target = evidence / "upgrade/compose/receipt.json"
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


@pytest.mark.parametrize(
    "row,mode,key",
    [
        ("I1", "paper", "previous_binary_sha256"),
        ("I1", "testnet", "previous_binary_sha256"),
        ("I6", "paper", "previous_image"),
        ("I6", "testnet", "previous_image"),
        ("I5", "testnet", "previous_image"),
    ],
)
def test_fresh_runtime_cannot_relabel_unexecuted_predecessor(
    tmp_path: Path, row: str, mode: str, key: str
) -> None:
    subjects, evidence, manifest = fixture(tmp_path, row)
    path = (
        evidence
        / mode
        / "fresh"
        / (
            "docker/receipt.json"
            if row == "I5"
            else "testnet-lifecycle.json"
            if mode == "testnet"
            else "linux-lifecycle.json"
        )
    )
    value = json.loads(path.read_bytes())
    value[key] = "unmeasured predecessor"
    write(path, value)
    with pytest.raises(EvidenceError):
        predicate(row, evidence, subjects, manifest, COMMIT)


def test_managed_file_loader_cannot_claim_literal_d7_pipe(tmp_path: Path) -> None:
    subjects, evidence, manifest = fixture(tmp_path, "I6")
    path = evidence / "paper/fresh/linux-lifecycle.json"
    value = json.loads(path.read_bytes())
    value["installer_route"] = "sh <authenticated-loader> --container --network paper"
    write(path, value)
    with pytest.raises(EvidenceError, match="entry route"):
        predicate("I6", evidence, subjects, manifest, COMMIT)


@pytest.mark.parametrize("channel", ["docker", "compose"])
@pytest.mark.parametrize("scenario", ["fresh", "upgrade"])
@pytest.mark.parametrize("mode", ["paper", "testnet"])
def test_d4_requires_each_measured_channel_execution(
    tmp_path: Path, channel: str, scenario: str, mode: str
) -> None:
    subjects, evidence, manifest = fixture(tmp_path, "I5")
    # Other passed receipts cannot stand in for this channel/mode/scenario.
    (evidence / mode / scenario / channel / "receipt.json").unlink()
    with pytest.raises(EvidenceError, match="regular runtime receipt"):
        predicate("I5", evidence, subjects, manifest, COMMIT)


@pytest.mark.parametrize("mutation", ["absent", "upgrade-only", "token-in-lifecycle"])
def test_d7_requires_fresh_channel_measurement(tmp_path: Path, mutation: str) -> None:
    subjects, evidence, manifest = fixture(tmp_path, "I6")
    path = evidence / "paper/fresh/linux-lifecycle.json"
    value = json.loads(path.read_bytes())
    value.pop("channel_coverage")
    if mutation == "upgrade-only":
        value["channel_coverage"] = []
    elif mutation == "token-in-lifecycle":
        value["coverage"].append("D7:container-native")
    write(path, value)
    with pytest.raises(EvidenceError):
        predicate("I6", evidence, subjects, manifest, COMMIT)
