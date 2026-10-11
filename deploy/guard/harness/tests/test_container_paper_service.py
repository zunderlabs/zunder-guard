"""Paper route cannot acquire sending custody or delete another Docker owner."""

import importlib.util
import json
import os
import subprocess
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "container/install-container-paper.py"
INSTALLER = SCRIPT.parents[1] / "install.sh"


def module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("container_paper", SCRIPT)
    assert spec is not None and spec.loader is not None
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


@pytest.mark.parametrize(
    "options",
    [
        ["--network", "mainnet"],
        ["--network", "testnet"],
        ["--key-stdin"],
        ["--key-file", "/unused"],
        ["--confirm-mainnet", "0x" + "1" * 40],
    ],
)
def test_paper_script_refuses_sending_input(options: list[str]) -> None:
    result = subprocess.run(
        ["python3", str(SCRIPT), *options], capture_output=True, timeout=10, check=False
    )
    assert result.returncode == 2
    assert b"Verified paper" not in result.stdout


def test_unit_always_recovers_owned_container_and_enforces_paper() -> None:
    value = module()
    image = "ghcr.io/zunderlabs/zunder-guard@sha256:" + "a" * 64
    unit = value.unit(image).decode()
    assert "ExecStartPre=/usr/bin/python3 -I " in unit
    assert "ExecStopPost=/usr/bin/python3 -I " in unit
    assert unit.count(" --recover") == 2
    assert "--network=host" in unit and "--env=ZUNDER_GUARD_LISTEN=127.0.0.1:8547" in unit
    assert "--user=65532:65532" in unit and "--cap-drop=ALL" in unit
    assert "--env=ZUNDER_GUARD_NETWORK=paper" in unit
    assert " run --network paper --container" in unit
    assert "LoadCredential" not in unit and "key-stdin" not in unit and "restart=always" not in unit
    assert "--restart=no" in unit and "Restart=on-failure" in unit


@pytest.mark.parametrize("alteration", ["label", "mode", "home", "extra-name", "none"])
def test_recovery_requires_exact_owner_route_and_home(
    monkeypatch: pytest.MonkeyPatch, alteration: str
) -> None:
    value = module()
    info: dict[str, Any] = {
        "Config": {
            "Labels": {"org.zunder.guard.managed": "container-paper"},
            "Cmd": ["run", "--network", "paper", "--container"],
        },
        "Mounts": [{"Source": str(value.HOME), "Destination": "/data"}],
    }
    if alteration == "label":
        info["Config"]["Labels"] = {}
    elif alteration == "mode":
        info["Config"]["Cmd"] = ["run", "--network", "mainnet"]
    elif alteration == "home":
        info["Mounts"][0]["Source"] = "/another-owner"
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **kwargs: Any) -> str:
        calls.append(argv)
        if "ps" in argv:
            return str(value.NAME) + ("\nanother" if alteration == "extra-name" else "")
        if "inspect" in argv:
            return json.dumps([info])
        return ""

    monkeypatch.setattr(value, "run", fake_run)
    if alteration == "none":
        value.recover()
        assert calls[-1][-3:] == ["rm", "-f", value.NAME]
    else:
        with pytest.raises(RuntimeError):
            value.recover()
        assert not any("rm" in call for call in calls)


@pytest.mark.parametrize(
    "options,reason",
    [
        (["--network", "mainnet", "--account-network", "testnet"], "paper mode"),
        (["--network", "testnet", "--account-network", "testnet"], "paper mode"),
        (["--account-network", "wrong"], "mainnet or testnet"),
        (["--uninstall", "--account-network", "testnet"], "accepts only"),
        (
            ["--container", "--network", "paper", "--non-interactive", "--key-stdin"],
            "without a key",
        ),
        (
            ["--container", "--network", "mainnet", "--account-network", "testnet"],
            "refuses --account-network",
        ),
    ],
)
def test_installer_refuses_cross_route_input_before_download(
    options: list[str], reason: str, tmp_path: Path
) -> None:
    uname = tmp_path / "uname"
    uname.write_text("#!/bin/sh\nprintf Linux\n")
    uname.chmod(0o700)
    result = subprocess.run(
        ["sh", str(INSTALLER), *options],
        capture_output=True,
        timeout=10,
        check=False,
        env={"PATH": str(tmp_path) + os.pathsep + os.defpath},
    )
    assert result.returncode != 0
    assert reason.encode() in result.stderr
    assert b"Downloading" not in result.stdout
