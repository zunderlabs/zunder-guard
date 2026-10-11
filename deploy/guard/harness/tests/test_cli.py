import json
from pathlib import Path
from typing import Any

import pytest

from guard_harness.cli import PAIR_SCHEMA, STATUS_SCHEMA, ContractError, Pair, decode_json


@pytest.fixture
def status() -> dict[str, Any]:
    return {
        "version": "1.0.0",
        "network": "paper",
        "account": "0x" + "a" * 40,
        "mode": "paper",
        "halted": False,
        "kill_switch": False,
        "licence": {
            "state": "none",
            "licensee": None,
            "expires_at_ms": None,
            "fee_free": False,
            "source": "file",
        },
        "journal": {"ok": True},
    }


def test_status_contract_accepts_extensions(status: dict[str, Any]) -> None:
    status["new_field"] = "forward compatible"
    assert decode_json(json.dumps(status), STATUS_SCHEMA) == status


@pytest.mark.parametrize("field", STATUS_SCHEMA["required"])
def test_every_status_field_required(status: dict[str, Any], field: str) -> None:
    del status[field]
    with pytest.raises(ContractError, match="missing or malformed"):
        decode_json(json.dumps(status), STATUS_SCHEMA)


@pytest.mark.parametrize("field", ["state", "licensee", "expires_at_ms", "fee_free", "source"])
def test_every_licence_field_required(status: dict[str, Any], field: str) -> None:
    del status["licence"][field]
    with pytest.raises(ContractError):
        decode_json(json.dumps(status), STATUS_SCHEMA)


@pytest.mark.parametrize(
    "field,value",
    [("halted", "false"), ("kill_switch", 0), ("network", "production"), ("account", "wrong")],
)
def test_invalid_status_types(status: dict[str, Any], field: str, value: Any) -> None:
    status[field] = value
    with pytest.raises(ContractError):
        decode_json(json.dumps(status), STATUS_SCHEMA)


def test_pair_errors_do_not_leak_key() -> None:
    secret = "synthetic-private-value"
    with pytest.raises(ContractError) as error:
        decode_json(
            json.dumps({"client_address": "0x" + "a" * 40, "client_key": secret}), PAIR_SCHEMA
        )
    assert secret not in str(error.value)


def test_pair_key_not_in_repr() -> None:
    pair = Pair("0x" + "a" * 40, "synthetic-sensitive-value")
    assert pair.key == "synthetic-sensitive-value"
    assert pair.key not in repr(pair)


def test_human_text_is_never_parsed() -> None:
    with pytest.raises(ContractError, match="not JSON"):
        decode_json("Guard running normally", STATUS_SCHEMA)


def test_pair_uses_explicit_sandbox_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import guard_harness.cli as cli
    from guard_harness.runner import RunResult

    secret = "0x" + "1" * 64

    def fake_run(argv: list[str], **kwargs: Any) -> RunResult:
        assert argv[1:3] == ["--home", str(tmp_path)]
        assert kwargs["sensitive_output"] is True
        return RunResult(
            0,
            json.dumps({"client_address": "0x" + "a" * 40, "client_key": secret}),
            tmp_path / "pair.log",
        )

    monkeypatch.setattr(cli, "run", fake_run)
    paired = cli.GuardCLI(tmp_path / "zunder-guard", tmp_path / "logs", tmp_path).pair()
    assert paired.key == secret


def test_licence_enters_only_stdin(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import guard_harness.cli as cli
    from guard_harness.runner import RunResult

    secret = "zgl1_fixture-sensitive-value"

    def fake_run(argv: list[str], **kwargs: Any) -> RunResult:
        assert argv == [
            str(tmp_path / "zunder-guard"),
            "--home",
            str(tmp_path),
            "licence",
            "set",
            "--stdin",
        ]
        assert all(secret not in arg for arg in argv)
        assert kwargs["stdin"] == (secret + "\n").encode()
        assert kwargs["secrets"] == [secret]
        return RunResult(0, "installed", tmp_path / "licence-set.log")

    monkeypatch.setattr(cli, "run", fake_run)
    cli.GuardCLI(tmp_path / "zunder-guard", tmp_path / "logs", tmp_path).set_licence(secret)


@pytest.mark.parametrize("key", ["", "other-prefix", "zgl1_first\nzgl1_second"])
def test_licence_rejects_invalid_multiline_input(tmp_path: Path, key: str) -> None:
    from guard_harness.cli import GuardCLI

    with pytest.raises(ContractError):
        GuardCLI(tmp_path / "missing-binary", tmp_path / "logs", tmp_path).set_licence(key)
    assert not (tmp_path / "logs").exists()
