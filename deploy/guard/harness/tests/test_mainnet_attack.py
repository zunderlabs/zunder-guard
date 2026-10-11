import tomllib

import pytest

from guard_harness.mainnet_attack import configuration
from guard_harness.mainnet_evidence import MatrixError

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


def test_attack_fixture_changes_only_declared_admission_fields() -> None:
    parsed = tomllib.loads(configuration(CONFIG))
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
