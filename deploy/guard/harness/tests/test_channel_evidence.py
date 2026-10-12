import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from test_install_evidence import release

from guard_harness.channel_evidence import admit, commands, required
from guard_harness.testnet_process import ProcessError


def fixture(tmp_path: Path, channel: str, target: str) -> tuple[Path, Any, dict[str, Any]]:
    current = release(tmp_path / "assets")
    sha = hashlib.sha256(current.binary(target)).hexdigest()
    forms = commands(channel)
    cleanup = (
        "owned-manual-cleanup"
        if target.startswith("darwin-")
        else "released-per-user-uninstall"
        if target.startswith("windows-")
        else "released-native-uninstall"
    )
    value = dict(
        schema=1,
        result="passed",
        channel=channel,
        scenario="fresh",
        mode="paper",
        tag=current.tag,
        commit=current.commit,
        manifest_sha256=hashlib.sha256(current.asset("release-manifest.json")).hexdigest(),
        installed_binary_sha256=sha,
        version=current.tag.removeprefix("v"),
        cleanup_complete=True,
        coverage=sorted(required(channel, target)),
        command=forms["manifest-bare"],
        loader_sha256=hashlib.sha256(
            current.asset("i.ps1" if channel == "D2" else "i")
        ).hexdigest(),
        executions=[
            dict(
                form=form,
                command=command,
                result="passed",
                installed_binary_sha256=sha,
                version="1.0.0",
                mode="paper",
                account_network="testnet",
                health=True,
                paper_roundtrip=True,
                owned_process_stopped=True,
                cleanup_complete=True,
                setup_identity="runner-user",
                configuration_home="user-default",
                cleanup_method=cleanup,
            )
            for form, command in forms.items()
        ],
    )
    path = tmp_path / "channel.json"
    path.write_text(json.dumps(value))
    return path, current, value


@pytest.mark.parametrize(
    "channel,target", [("D1", "darwin-arm64"), ("D1", "linux-amd64"), ("D2", "windows-amd64")]
)
def test_both_measured_literal_forms_and_correct_cleanup_admit(
    channel: str, target: str, tmp_path: Path
) -> None:
    path, current, value = fixture(tmp_path, channel, target)
    assert admit(path, channel, current, target).startswith(channel + ":")
    if target.startswith("darwin-"):
        assert "uninstall" not in value["coverage"]


@pytest.mark.parametrize(
    "mutation",
    [
        "bare-only",
        "wrong-parameter-command",
        "wrong-binary",
        "wrong-version",
        "testnet-mode",
        "wrong-read-network",
        "no-health",
        "no-roundtrip",
        "still-running",
        "no-cleanup",
        "root-setup",
        "custom-home",
        "fake-uninstall",
        "extra-coverage",
        "duplicate-form",
    ],
)
def test_missing_parameter_run_or_false_user_cleanup_is_refused(
    mutation: str, tmp_path: Path
) -> None:
    path, current, value = fixture(tmp_path, "D1", "darwin-arm64")
    form = value["executions"][1]
    if mutation == "bare-only":
        value["executions"] = value["executions"][:1]
    elif mutation == "extra-coverage":
        value["coverage"].append("uninstall")
    elif mutation == "duplicate-form":
        value["executions"][1] = value["executions"][0]
    else:
        changes: dict[str, dict[str, Any]] = {
            "wrong-parameter-command": {"command": "curl loader | sh"},
            "wrong-binary": {"installed_binary_sha256": "f" * 64},
            "wrong-version": {"version": "0.9.0"},
            "testnet-mode": {"mode": "testnet"},
            "wrong-read-network": {"account_network": "mainnet"},
            "no-health": {"health": False},
            "no-roundtrip": {"paper_roundtrip": False},
            "still-running": {"owned_process_stopped": False},
            "no-cleanup": {"cleanup_complete": False},
            "root-setup": {"setup_identity": "root"},
            "custom-home": {"configuration_home": "private-custom"},
            "fake-uninstall": {"cleanup_method": "product-uninstall"},
        }
        form.update(changes[mutation])
    path.write_text(json.dumps(value))
    with pytest.raises(ProcessError):
        admit(path, "D1", current, "darwin-arm64")
