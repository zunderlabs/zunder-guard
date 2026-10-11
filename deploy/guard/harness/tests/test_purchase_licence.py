import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from guard_harness import purchase_licence as licence


@pytest.fixture
def setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    tmp_path.chmod(0o700)
    status: dict[str, Any] = {
        "mode": "paper",
        "account": "0x" + "1" * 40,
        "licence": {"state": "valid", "fee_free": True, "source": "file"},
        "journal": {"ok": True},
    }
    calls: list[str] = []

    def binary(assets: Path, output: Path, **kwargs: Any) -> tuple[str, str]:
        assert kwargs == {"tag": "v1.0.0-rc.2", "commit": "a" * 40}
        output.write_text("fake authenticated binary")
        calls.append("authenticated")
        return "b" * 64, "c" * 64

    def initialize(argv: Any, **kwargs: Any) -> None:
        assert "paper" in argv and "--no-key" in argv and "testnet" in argv
        assert kwargs["sensitive_output"] is True
        assert set(kwargs["env"]) == {"PATH", "HOME"}
        Path(kwargs["log"]).parent.mkdir()
        calls.append("init")

    class CLI:
        def __init__(self, *args: Any) -> None:
            pass

        def set_licence(self, key: str) -> None:
            assert key == "zgl1_synthetic"
            calls.append("licence")

        def status(self, **kwargs: Any) -> dict[str, Any]:
            return status

    class Process:
        def __init__(self, argv: Any, **kwargs: Any) -> None:
            assert "--network" in argv and argv[argv.index("--network") + 1] == "paper"
            assert set(kwargs["env"]) == {"PATH", "HOME"}
            assert kwargs["stdin"] == subprocess.DEVNULL
            calls.append("started")

        def poll(self) -> None:
            return None

        def terminate(self) -> None:
            calls.append("stopped")

        def wait(self, **kwargs: Any) -> int:
            return 0

    monkeypatch.setattr(licence, "signed_binary", binary)
    monkeypatch.setattr(licence, "run", initialize)
    monkeypatch.setattr(licence, "GuardCLI", CLI)
    monkeypatch.setattr("guard_harness.purchase_licence.subprocess.Popen", Process)
    return tmp_path, status, calls


def test_licence_install_receipt_only_after_owned_service_stops(setup: Any) -> None:
    work, status, calls = setup
    licence.install(
        work / "assets",
        work,
        tag="v1.0.0-rc.2",
        commit="a" * 40,
        account=status["account"],
        key="zgl1_synthetic",
    )
    assert calls == ["authenticated", "init", "licence", "started", "stopped"]
    receipt = (work / "licence-receipt.json").read_text()
    assert "synthetic" not in receipt and "service_stopped" in receipt
    assert (work / "licence-receipt.json").stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("failure", ["account", "mode", "expired", "fee", "journal"])
def test_bad_licensed_status_always_stops_and_cannot_receipt(setup: Any, failure: str) -> None:
    work, status, calls = setup
    account = status["account"]
    if failure == "account":
        status["account"] = "0x" + "2" * 40
    elif failure == "mode":
        status["mode"] = "testnet"
    elif failure == "expired":
        status["licence"]["state"] = "expired"
    elif failure == "fee":
        status["licence"]["fee_free"] = False
    else:
        status["journal"]["ok"] = False
    with pytest.raises(ValueError, match="admission failed"):
        licence.install(
            work / "assets",
            work,
            tag="v1.0.0-rc.2",
            commit="a" * 40,
            account=account,
            key="zgl1_synthetic",
        )
    assert calls[-1] == "stopped"
    assert not (work / "licence-receipt.json").exists()


@pytest.mark.parametrize("journey", ["P2", "P3"])
def test_paid_receipt_binds_selected_journey(setup: Any, journey: str) -> None:
    work, status, calls = setup
    licence.install(
        work / "assets",
        work,
        tag="v1.0.0-rc.2",
        commit="a" * 40,
        account=status["account"],
        key="zgl1_synthetic",
        journey=journey,
    )
    receipt = json.loads((work / "licence-receipt.json").read_bytes())
    assert receipt["journey"] == journey
    assert receipt["licensed"] is True and receipt["service_stopped"] is True
    assert calls[-1] == "stopped"


def test_unknown_journey_refuses_before_binary_or_licence_custody(setup: Any) -> None:
    work, status, calls = setup
    with pytest.raises(ValueError, match="paid purchase journey required"):
        licence.install(
            work / "assets",
            work,
            tag="v1.0.0-rc.2",
            commit="a" * 40,
            account=status["account"],
            key="zgl1_synthetic",
            journey="P5",
        )
    assert calls == []
    assert not (work / "licence-receipt.json").exists()
