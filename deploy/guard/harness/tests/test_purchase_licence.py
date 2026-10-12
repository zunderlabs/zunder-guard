import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from guard_harness import purchase_licence as licence

SIGNATURE = "A" * 86
SYNTHETIC = "zgl1_synthetic." + SIGNATURE
OLD = "zgl1_old." + SIGNATURE
NEW = "zgl1_new." + SIGNATURE
RENEWED = "zgl1_renewed." + SIGNATURE


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
            assert key == SYNTHETIC
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
        key=SYNTHETIC,
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
            key=SYNTHETIC,
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
        key=SYNTHETIC,
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
            key=SYNTHETIC,
            journey="P5",
        )
    assert calls == []
    assert not (work / "licence-receipt.json").exists()


def test_renewal_opt_in_preserves_policy_and_is_private(tmp_path: Path) -> None:
    import tomllib

    path = tmp_path / "guard.toml"
    path.write_text(f'licence = "{OLD}"\n[policy]\nrisk_per_trade = "0.01"\n')
    token = "a" * 43
    licence.enable_renewal(path, token)
    parsed = tomllib.loads(path.read_text())
    assert parsed["licence_auto_update"] is True and parsed["licence_renewal_token"] == token
    assert parsed["licence"] == OLD
    assert parsed["policy"] == {"risk_per_trade": "0.01"}
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError, match="fresh opt-in"):
        licence.enable_renewal(path, token)


@pytest.mark.parametrize(
    "renewal",
    [
        {
            "key": OLD,
            "token": "a" * 43,
        },
        {
            "key": NEW,
            "token": "short",
        },
    ],
)
def test_renewal_refuses_repeated_key_or_malformed_token(renewal: dict[str, str]) -> None:
    with pytest.raises(ValueError, match="distinct emailed"):
        licence.validate_renewal(
            renewal,
            OLD,
        )


@pytest.mark.parametrize("applied", [True, False])
def test_auto_update_requires_persistence_and_applied_newer_expiry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, applied: bool
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    logs = tmp_path / "logs"
    logs.mkdir()
    config = home / "guard.toml"
    config.write_text(f'licence = "{OLD}"\n')
    stopped: list[bool] = []
    ticks = iter([0.0, 1.0, 2.0, 3.0, 200.0])
    monkeypatch.setattr("guard_harness.purchase_licence.time.monotonic", lambda: next(ticks))
    monkeypatch.setattr("guard_harness.purchase_licence.time.sleep", lambda seconds: None)

    class CLI:
        reads = 0

        def status(self, **kwargs: Any) -> dict[str, Any]:
            self.reads += 1
            if self.reads == 2:
                config.write_text(f'licence = "{NEW}"\n')
            return {
                "mode": "paper",
                "account": "0x" + "1" * 40,
                "licence": {
                    "state": "valid",
                    "fee_free": True,
                    "source": "auto_update",
                    "expires_at_ms": 200 if self.reads >= 2 and applied else 100,
                },
                "journal": {"ok": True},
            }

    class Process:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            assert kwargs["env"] == {"PATH": "/bin", "HOME": str(home)}
            assert kwargs["stdin"] == subprocess.DEVNULL

        def poll(self) -> None:
            return None

        def terminate(self) -> None:
            stopped.append(True)

        def wait(self, **kwargs: Any) -> int:
            return 0

    monkeypatch.setattr("guard_harness.purchase_licence.subprocess.Popen", Process)
    from typing import cast

    from guard_harness.cli import GuardCLI

    def verify() -> None:
        licence.verify_auto_update(
            tmp_path / "binary",
            home,
            logs,
            cast(GuardCLI, CLI()),
            {"PATH": "/bin", "HOME": str(home)},
            "0x" + "1" * 40,
            OLD,
            NEW,
        )

    if applied:
        verify()
    else:
        with pytest.raises(ValueError, match="fetched, persisted and applied"):
            verify()
    assert stopped == [True]


@pytest.mark.parametrize(
    "origin",
    [
        None,
        "https://zunderlabs.com/api/licence/renewal",
        "https://staging.zunderlabs.com.evil/api/licence/renewal",
    ],
)
def test_p6_refuses_origin_before_token_opt_in_or_runtime(
    setup: Any, monkeypatch: pytest.MonkeyPatch, origin: str | None
) -> None:
    work, status, calls = setup

    def metadata(self: Any) -> dict[str, Any]:
        return {"renewal_origin": origin}

    monkeypatch.setattr("guard_harness.purchase_licence.GuardCLI.licence", metadata, raising=False)
    monkeypatch.setattr(licence, "enable_renewal", lambda *args: pytest.fail("token handed off"))
    with pytest.raises(ValueError, match="issuer-derived staging renewal origin"):
        licence.install(
            work / "assets",
            work,
            tag="v1.0.0-rc.2",
            commit="a" * 40,
            account=status["account"],
            key=SYNTHETIC,
            journey="P6",
            renewal={
                "key": RENEWED,
                "token": "a" * 43,
            },
        )
    assert calls == ["authenticated", "init", "licence"]
    assert not (work / "licence-receipt.json").exists()


@pytest.mark.parametrize(
    "key",
    [
        "zgl1_payload",
        "zgl1_payload." + "A" * 85,
        "zgl1_payload." + "A" * 87,
        "zgl1_payload." + "A" * 86 + ".extra",
        "zgl1_" + "A" * 4005 + "." + "A" * 86,
        "zgl1_payload." + "A" * 86 + "\n",
    ],
)
def test_complete_key_refuses_truncated_extended_or_oversized_wire_token(key: str) -> None:
    assert not licence.valid_licence_key(key)


def test_complete_key_preserves_signature_and_maximum_wire_size() -> None:
    key = "zgl1_" + "A" * 4004 + "." + "A" * 86
    assert len(key) == 4096
    assert licence.valid_licence_key(key)
