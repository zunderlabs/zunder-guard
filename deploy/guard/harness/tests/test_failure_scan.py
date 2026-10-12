import json
import os
import sys
from pathlib import Path

import pytest

from guard_harness import failure_scan
from guard_harness.testnet_scan import ScanError


@pytest.mark.parametrize("flat", [True, False])
def test_independent_scan_retains_outcome_without_repair(
    flat: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def scan(read: object, account: str) -> dict[str, object]:
        assert account == "explicit-public-account"
        if not flat:
            raise ScanError("account is not flat; unrelated state is never repaired")
        return {"network": "testnet", "observations": []}

    monkeypatch.setattr(failure_scan, "flat_scan", scan)
    work = tmp_path / "failure.json"
    if flat:
        failure_scan.observe(work, "explicit-public-account")
    else:
        with pytest.raises(ScanError):
            failure_scan.observe(work, "explicit-public-account")
    receipt = json.loads(work.read_text())
    assert receipt["flat"] is flat and receipt["repair_attempted"] is False
    assert "explicit-public-account" not in work.read_text()
    assert work.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("unsafe", ["symlink", "public-parent", "existing-output"])
def test_scan_refuses_unsafe_output_before_any_venue_read(
    unsafe: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    output = parent / "failure.json"
    if unsafe == "symlink":
        output.symlink_to(tmp_path / "untouched")
    elif unsafe == "public-parent":
        parent.chmod(0o755)
    else:
        output.write_text("retained outcome")
    monkeypatch.setattr(failure_scan, "flat_scan", lambda *a: pytest.fail("unsafe output"))
    with pytest.raises((ValueError, ScanError)):
        failure_scan.observe(output, "explicit-public-account")
    assert not (tmp_path / "untouched").exists()


@pytest.mark.parametrize(
    "message, category",
    [
        ("account is not flat; unrelated state is never repaired", "nonflat"),
        ("account has open orders; unrelated state is never repaired", "openorders"),
        ("unreadable holdings", "holdings"),
        ("complete bounded DEX inventory required", "inventory"),
        ("standard testnet account required", "mode"),
        ("refill the E2E testnet account", "equity"),
        ("testnet HTTP/JSON read failed", "transport"),
        ("scan deadline exhausted; no incomplete flat credit", "deadline"),
        ("account is not flat; unrelated state is never repaired SECRET", "unknown"),
    ],
)
def test_exact_finite_scan_diagnostic_never_propagates_exception_text(
    message: str,
    category: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def scan(*args: object) -> dict[str, object]:
        raise ScanError(message)

    monkeypatch.setattr(failure_scan, "flat_scan", scan)
    synced: list[int] = []
    monkeypatch.setattr(os, "fsync", lambda descriptor: synced.append(descriptor))
    work = tmp_path / "failed.json"
    with pytest.raises(ScanError, match="exposure unknown") as error:
        failure_scan.observe(work, "SYNTHETIC-PRIVATE-ACCOUNT")
    assert error.value.__cause__ is None and message not in str(error.value)
    receipt = json.loads(work.read_text())
    assert receipt == dict(
        flat=False,
        network="testnet",
        repair_attempted=False,
        failure_kind=category,
        last_read_phase="not-started",
    )
    assert synced and "SECRET" not in work.read_text()


@pytest.mark.parametrize(
    "error", [RuntimeError("SECRET"), ScanError("SECRET"), KeyboardInterrupt("SECRET")]
)
def test_actual_cli_unknown_failure_has_fixed_exit_and_private_negative_receipt(
    error: BaseException,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def scan(*args: object) -> dict[str, object]:
        raise error

    output = tmp_path / "cli.json"
    monkeypatch.setattr(failure_scan, "flat_scan", scan)
    monkeypatch.setattr(sys, "argv", ["failure_scan", "--work", str(output)])
    monkeypatch.setenv("E2E_ACCOUNT", "SYNTHETIC-PRIVATE-ACCOUNT")
    with pytest.raises(SystemExit) as stopped:
        failure_scan.main()
    assert str(stopped.value) == "C6 postfailure flat scan incomplete; human review required"
    assert "SECRET" not in str(stopped.value) + output.read_text()
    assert "SYNTHETIC-PRIVATE-ACCOUNT" not in output.read_text()
    assert json.loads(output.read_text())["failure_kind"] == "unknown"
    assert output.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "case",
    [
        "nonflat",
        "openorders",
        "mode",
        "inventory",
        "holdings",
        "equity",
        "transport",
        "deadline",
        "flat",
    ],
)
def test_actual_scan_retains_static_last_read_phase_and_finite_failure(
    case: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    account = "0x" + "a" * 40
    calls: list[str] = []

    def read(payload: dict[str, object]) -> object:
        kind = str(payload["type"])
        calls.append(kind)
        if kind == "userAbstraction":
            if case == "transport":
                raise ScanError("testnet HTTP/JSON read failed")
            if case == "deadline":
                raise ScanError("scan deadline exhausted after pacing; nothing sent")
            return "wrong-mode" if case == "mode" else "disabled"
        if kind == "perpDexs":
            return {} if case == "inventory" else [None]
        if kind == "clearinghouseState":
            if case == "holdings":
                return {}
            return dict(
                assetPositions=[dict(position=dict(coin="SECRET", szi="1"))]
                if case == "nonflat"
                else [],
                marginSummary=dict(accountValue="199" if case == "equity" else "400"),
            )
        assert kind == "frontendOpenOrders"
        return [{"oid": "SECRET"}] if case == "openorders" else []

    monkeypatch.setattr(failure_scan, "TestnetReads", lambda **kwargs: read)
    output = tmp_path / "actual.json"
    if case == "flat":
        failure_scan.observe(output, account)
    else:
        with pytest.raises(ScanError, match="exposure unknown"):
            failure_scan.observe(output, account)
    receipt = json.loads(output.read_text())
    assert receipt["flat"] is (case == "flat") and receipt["repair_attempted"] is False
    assert "SECRET" not in output.read_text() and account not in output.read_text()
    if case != "flat":
        assert receipt["failure_kind"] == case
    assert receipt["last_read_phase"] == (
        "inventory-after"
        if case == "flat"
        else "account-mode"
        if case in {"mode", "transport", "deadline"}
        else "inventory-before"
        if case == "inventory"
        else "open-orders"
    )
    assert len(calls) == (
        5
        if case == "flat"
        else 1
        if case in {"mode", "transport", "deadline"}
        else 2
        if case == "inventory"
        else 4
    )
