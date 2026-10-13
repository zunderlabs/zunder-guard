import hashlib
import io
import json
import subprocess
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
    monkeypatch.setenv("PATH", str(tmp_path / "caller-untrusted-bin"))
    monkeypatch.setenv("API_WALLET_KEY", "PRIVATE-KEY-FIXTURE")
    monkeypatch.setenv("GH_TOKEN", "PRIVATE-TOKEN-FIXTURE")
    tools = tmp_path / "tool-root"
    for directory in ("usr/sbin", "usr/bin", "sbin", "bin"):
        (tools / directory).mkdir(parents=True, exist_ok=True)
    runuser = tools / "usr/sbin/runuser"
    runuser.write_text("#!/bin/sh\nprintf 'safe utility lookup fixture\\n'\n")
    runuser.chmod(0o700)
    old_path = ":".join(str(tools / directory) for directory in ("bin", "usr/bin"))
    # An actual subprocess cannot locate an sbin-only utility under the old PATH.
    with pytest.raises(FileNotFoundError):
        subprocess.run(["runuser"], env={"PATH": old_path}, check=True, timeout=5)
    calls: list[list[str]] = []
    controls: list[str] = []
    phases: list[str] = []

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
        assert kwargs["env"] == {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": str(tmp_path / "work"),
            "LANG": "C.UTF-8",
        }
        lookup_path = ":".join(
            str(tools / directory.lstrip("/")) for directory in kwargs["env"]["PATH"].split(":")
        )
        found = subprocess.run(
            [argv[0]],
            env={"PATH": lookup_path},
            check=True,
            timeout=5,
            capture_output=True,
        )
        assert found.stdout == b"safe utility lookup fixture\n"
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
        observe_phase=phases.append,
    )
    assert phases == [
        "runtime-create",
        "staged-loader",
        "key-frame",
        "service-setup",
        "installed-binary",
        "service-stop",
        "service-config",
        "pair",
        "mcp-home",
        "service-start",
        "service-pid",
    ]
    assert set(phases) == service.STARTUP_PHASES
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


@pytest.mark.parametrize("failure", ["loader", "key-frame", "setup"])
def test_real_constructor_failure_retains_last_authored_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    binary = tmp_path / "binary"
    binary.write_bytes(b"authenticated fixture")
    phases: list[str] = []
    controls: list[str] = []
    setups: list[bytes] = []
    key = io.BytesIO(
        (b"a" * 32 + b" " + b"a" * 32) if failure == "key-frame" else b"a" * 64 + b"\n"
    )

    def loader(release: Any, *, windows: bool, output: Path) -> Path:
        if failure == "loader":
            raise RuntimeError("private provider body")
        output.write_bytes(b"signed fixture")
        return output

    def setup(self: Any, frame: bytes) -> dict[str, str]:
        setups.append(frame)
        raise RuntimeError("private installer output")

    monkeypatch.setattr(service, "staged_loader", loader)
    monkeypatch.setattr("guard_harness.linux_testnet_service.TestnetService.setup", setup)
    monkeypatch.setattr(
        service.ServiceOwner, "_control", lambda self, action: controls.append(action)
    )
    with pytest.raises((RuntimeError, ProcessError)):
        service.ServiceOwner(
            binary,
            sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
            work=tmp_path / "work",
            account="0x" + "1" * 40,
            api_wallet="0x" + "2" * 40,
            port=18547,
            key_stdin=key,
            assets=tmp_path,
            tag="v1.0.0-rc.14",
            commit="b" * 40,
            marker="c" * 32,
            observe_phase=phases.append,
        )
    assert (
        phases[-1]
        == {"loader": "staged-loader", "key-frame": "key-frame", "setup": "service-setup"}[failure]
    )
    assert controls == []
    assert bool(setups) is (failure == "setup")
    if failure == "loader":
        assert key.tell() == 0


def test_observation_failure_prevents_next_constructor_operation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "binary"
    binary.write_bytes(b"authenticated fixture")
    key = io.BytesIO(b"a" * 64 + b"\n")
    monkeypatch.setattr(
        service, "staged_loader", lambda *a, **k: pytest.fail("no loader after receipt failure")
    )

    def refuse(phase: str) -> None:
        assert phase == "runtime-create"
        raise OSError("private filesystem error")

    with pytest.raises(OSError):
        service.ServiceOwner(
            binary,
            sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
            work=tmp_path / "work",
            account="0x" + "1" * 40,
            api_wallet="0x" + "2" * 40,
            port=18547,
            key_stdin=key,
            assets=tmp_path,
            tag="v1.0.0-rc.14",
            commit="b" * 40,
            marker="c" * 32,
            observe_phase=refuse,
        )
    assert key.tell() == 0 and not (tmp_path / "work").exists()


@pytest.mark.parametrize(
    "framed",
    [
        b"a" * 64 + b"\n",
        b"a" * 64,
        b"a" * 64 + b"\r\n",
        b"0x" + b"a" * 64 + b"\n",
        b"0x" + b"a" * 64 + b"\n\n",
        b"a" * 64 + b"\n\n",
        b" \t\v\f" + b"a" * 64 + b"\r\n",
        b"a" * 64 + b" " * 192,
    ],
)
def test_bounded_outer_key_whitespace_becomes_one_protected_frame(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, framed: bytes
) -> None:
    frames: list[bytes] = []

    def setup(self: Any, key: bytes) -> dict[str, str]:
        frames.append(key)
        raise RuntimeError("setup fixture reached")

    monkeypatch.setattr("guard_harness.linux_testnet_service.TestnetService.setup", setup)
    _framing_constructor(tmp_path, monkeypatch, framed)
    assert frames == [b"a" * 64 + b"\n"]


@pytest.mark.parametrize(
    "framed",
    [
        b"a" * 64 + b"\n" + b"b" * 64 + b"\n",
        b"0x " + b"a" * 64,
        b"a" * 32 + b" " + b"a" * 32,
        b"a" * 63 + b"\x00",
        b"g" * 64,
        b"a" * 64 + b"x",
        b"a" * 256,
        b"a" * 64 + b" " * 193,
        b"a" * 257,
        b"a" * 4096,
        b"0X" + b"a" * 64,
        b"\xa0" + b"a" * 64,
        b" \n\t",
    ],
)
def test_malformed_or_overlong_outer_frame_refuses_before_service_setup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, framed: bytes
) -> None:
    monkeypatch.setattr(
        "guard_harness.linux_testnet_service.TestnetService.setup",
        lambda *a, **k: pytest.fail("key frame must refuse before custody"),
    )
    _framing_constructor(tmp_path, monkeypatch, framed)


def _framing_constructor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, framed: bytes) -> None:
    binary = tmp_path / "binary"
    binary.write_bytes(b"authenticated fixture")
    key = io.BytesIO(framed)
    phases: list[str] = []

    def loader(release: Any, *, windows: bool, output: Path) -> Path:
        output.write_bytes(b"signed fixture")
        return output

    monkeypatch.setattr(service, "staged_loader", loader)
    monkeypatch.setattr(
        service.ServiceOwner, "_control", lambda *a: pytest.fail("no service control")
    )
    with pytest.raises((RuntimeError, ProcessError)):
        service.ServiceOwner(
            binary,
            sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
            work=tmp_path / "work",
            account="0x" + "1" * 40,
            api_wallet="0x" + "2" * 40,
            port=18547,
            key_stdin=key,
            assets=tmp_path,
            tag="v1.0.0-rc.14",
            commit="b" * 40,
            marker="c" * 32,
            observe_phase=phases.append,
        )
    assert key.tell() <= 257
    assert phases[-1] in {"key-frame", "service-setup"}
