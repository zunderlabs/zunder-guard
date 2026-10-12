import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from guard_harness import testnet_service_owner as service
from guard_harness.runner import RunResult
from guard_harness.testnet_process import ProcessError


def test_service_pairs_as_owner_and_mcp_home_stays_private(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "binary"
    binary.write_bytes(b"authenticated released bytes")
    home = tmp_path / "service-home"
    home.mkdir(mode=0o750)
    account, wallet = "0x" + "1" * 40, "0x" + "2" * 40
    config = home / "guard.toml"
    config.write_text(
        f'mode="testnet"\nnetwork="testnet"\naccount="{account}"\napi_wallet="{wallet}"\n'
        'ip_share="0.4"\n'
    )
    original_mode = home.stat().st_mode
    calls: list[list[str]] = []
    controls: list[str] = []

    def loader(release: Any, *, windows: bool, output: Path) -> Path:
        output.write_bytes(b"signed loader")
        return output

    def setup(self: Any, key: bytes) -> dict[str, str]:
        assert key == b"a" * 64 + b"\n"
        assert self.ip_share == "0.4"
        return {
            "binary": str(binary),
            "home": str(home),
            "url": "http://127.0.0.1:18547",
            "unit": "zunder-guard-testnet.service",
        }

    def pair(argv: list[str], **kwargs: Any) -> RunResult:
        calls.append(argv)
        assert argv[:3] == ["runuser", "-u", "service-owner"]
        assert kwargs["sensitive_output"] is True
        return RunResult(
            0,
            json.dumps({"client_address": "0x" + "3" * 40, "client_key": "0x" + "4" * 64}),
            kwargs["log"],
        )

    monkeypatch.setattr(service, "staged_loader", loader)
    monkeypatch.setattr("guard_harness.linux_testnet_service.TestnetService.setup", setup)
    monkeypatch.setattr(service, "run", pair)
    monkeypatch.setattr(
        "guard_harness.testnet_service_owner.pwd.getpwuid",
        lambda uid: SimpleNamespace(pw_name="service-owner"),
    )
    monkeypatch.setattr(
        service.ServiceOwner, "_control", lambda self, action: controls.append(action)
    )
    monkeypatch.setattr(service.ServiceOwner, "_pid", lambda self: 123)
    owner = service.ServiceOwner(
        binary,
        sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        work=tmp_path / "work",
        account=account,
        api_wallet=wallet,
        port=18547,
        key_stdin=io.BytesIO(b"0x" + b"a" * 64 + b"\n"),
        assets=tmp_path,
        tag="v1.0.0-rc.4",
        commit="b" * 40,
        marker="c" * 32,
    )
    assert controls == ["stop", "start"] and len(calls) == 1
    assert home.stat().st_mode == original_mode
    assert owner.home != home and owner.home.stat().st_mode & 0o777 == 0o700
    assert (owner.home / "guard.toml").read_bytes() == config.read_bytes()
    assert owner.client_key.stat().st_mode & 0o777 == 0o600
    assert not (home / "client-key").exists()


def test_failed_identity_check_does_not_stop_protection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner = object.__new__(service.ServiceOwner)
    owner.work = tmp_path
    owner.log = tmp_path / "process.log"
    controls: list[str] = []
    monkeypatch.setattr(
        owner, "alive", lambda: (_ for _ in ()).throw(ProcessError("changed service"))
    )
    monkeypatch.setattr(owner, "_control", lambda action: controls.append(action))
    with pytest.raises(ProcessError):
        owner.stop_after_flat()
    assert controls == [] and not owner.log.exists()
