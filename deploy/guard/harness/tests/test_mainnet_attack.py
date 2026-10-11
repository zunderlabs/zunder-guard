import tomllib
from pathlib import Path
from typing import Any

import pytest

import guard_harness.mainnet_attack as attacks
from guard_harness.mainnet_attack import configuration
from guard_harness.mainnet_evidence import MatrixError
from guard_harness.native_release import Release

CONFIG = """mode = "paper"
network = "mainnet"
allow_mainnet = false
account = "public-account-fixture"
[policy]
max_notional = "40"
[policy.risk]
max_daily_loss = "0.02"
[auth]
clients = ["public-client-fixture"]
"""


@pytest.mark.parametrize("network", ["mainnet", "testnet"])
def test_attack_fixture_changes_only_declared_admission_fields(network: str) -> None:
    parsed = tomllib.loads(
        configuration(CONFIG.replace('network = "mainnet"', f'network = "{network}"'))
    )
    assert parsed["mode"] == "mainnet" and parsed["allow_mainnet"] is True
    assert parsed["policy"]["max_trading_equity_usd"] == "100"
    assert parsed["policy"]["max_notional"] == "40"
    assert parsed["policy"]["risk"]["max_daily_loss"] == "0.02"
    assert parsed["account"] == "public-account-fixture"
    assert parsed["auth"] == {"clients": ["public-client-fixture"]}


@pytest.mark.parametrize(
    "mutation", ["sending", "mainnet-allowed", "missing-policy", "duplicate-mode"]
)
def test_attack_fixture_refuses_uncontrolled_source(mutation: str) -> None:
    source = CONFIG
    if mutation == "sending":
        source = source.replace('mode = "paper"', 'mode = "testnet"')
    elif mutation == "mainnet-allowed":
        source = source.replace("allow_mainnet = false", "allow_mainnet = true")
    elif mutation == "missing-policy":
        source = source.replace("[policy]\n", "[other]\n")
    else:
        source = source + '\nmode = "paper"\n'
    with pytest.raises((MatrixError, tomllib.TOMLDecodeError)):
        configuration(source)


@pytest.mark.parametrize("network", [None, "mainnet", "testnet"])
def test_real_paper_constructor_selects_only_explicit_read_network(
    network: str | None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "released-binary"
    binary.write_bytes(b"authenticated released bytes fixture")
    release = Release("v1.0.0-rc.5", "b" * 40, tmp_path / "assets")
    monkeypatch.setattr(Release, "binary", lambda self, target: binary.read_bytes())
    calls: list[list[str]] = []

    def constructor(argv: list[str], **kwargs: Any) -> None:
        calls.append(argv)
        assert argv[3:7] == ["init", "--non-interactive", "--network", "paper"]
        assert argv[argv.index("--account-network") + 1] == (network or "mainnet")
        assert "--no-key" in argv and "--key-stdin" not in argv
        assert kwargs["stdin"] == b"" and kwargs["sensitive_output"] is True
        raise RuntimeError("paper constructor boundary")

    monkeypatch.setattr(attacks, "run", constructor)
    options = {} if network is None else {"account_network": network}
    with pytest.raises(RuntimeError, match="paper constructor boundary"):
        attacks.execute(
            release,
            binary,
            account="0x" + "1" * 40,
            rules="zr1_fixture",
            work=tmp_path / "work",
            **options,
        )
    assert len(calls) == 1


@pytest.mark.parametrize("network", ["", "paper", "mainnet\ntestnet"])
def test_invalid_paper_read_network_refuses_before_subject_or_process(
    network: str, tmp_path: Path
) -> None:
    with pytest.raises(MatrixError, match="account network"):
        attacks.execute(
            Release("v1.0.0-rc.5", "b" * 40, tmp_path / "missing-assets"),
            tmp_path / "missing-binary",
            account="0x" + "1" * 40,
            rules="zr1_fixture",
            work=tmp_path / "work",
            account_network=network,
        )
    assert not (tmp_path / "work").exists()
