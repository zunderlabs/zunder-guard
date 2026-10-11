"""Offline approval admission and cryptographic recovery; no wallet or venue I/O."""

import copy
from typing import Any

import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data

from guard_harness.builder_approval import sign, validate

BUILDER = "0x" + "2" * 40
NOW = 1_800_000_000_000
# Published deterministic test material only, never a venue wallet.
FIXTURE_KEY = "1" * 64


def typed() -> dict[str, Any]:
    return {
        "domain": {
            "name": "HyperliquidSignTransaction",
            "version": "1",
            "chainId": 421614,
            "verifyingContract": "0x" + "0" * 40,
        },
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "HyperliquidTransaction:ApproveBuilderFee": [
                {"name": "hyperliquidChain", "type": "string"},
                {"name": "maxFeeRate", "type": "string"},
                {"name": "builder", "type": "address"},
                {"name": "nonce", "type": "uint64"},
            ],
        },
        "primaryType": "HyperliquidTransaction:ApproveBuilderFee",
        "message": {
            "hyperliquidChain": "Testnet",
            "maxFeeRate": "0.02%",
            "builder": BUILDER,
            "nonce": NOW,
        },
    }


def test_signature_recovers_owner_only_for_the_admitted_testnet_message() -> None:
    value = typed()
    account = Account.from_key(FIXTURE_KEY).address
    signature = sign(
        {"key": FIXTURE_KEY, "account": account, "expected_builder": BUILDER, "typed": value},
        now_ms=NOW,
    )
    assert (
        Account.recover_message(encode_typed_data(full_message=value), signature=signature)
        == account
    )
    mainnet = copy.deepcopy(value)
    mainnet["message"]["hyperliquidChain"] = "Mainnet"
    assert (
        Account.recover_message(encode_typed_data(full_message=mainnet), signature=signature)
        != account
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("hyperliquidChain", "Mainnet"),
        ("maxFeeRate", "0.03%"),
        ("maxFeeRate", "0%"),
        ("builder", "0x" + "1" * 40),
        ("nonce", NOW - 60_001),
        ("nonce", NOW + 60_001),
        ("nonce", True),
        ("nonce", float(NOW)),
    ],
)
def test_unapproved_fields_fail_before_signing(field: str, value: Any) -> None:
    payload = typed()
    payload["message"][field] = value
    with pytest.raises(ValueError):
        validate(payload, expected_builder=BUILDER, now_ms=NOW)


@pytest.mark.parametrize("mutation", ["domain", "types", "extra", "owner"])
def test_other_domains_actions_extra_fields_and_wrong_owner_refuse(mutation: str) -> None:
    payload = typed()
    account = Account.from_key(FIXTURE_KEY).address
    if mutation == "domain":
        payload["domain"]["chainId"] = 42161
    if mutation == "types":
        payload["types"]["HyperliquidTransaction:ApproveBuilderFee"][0]["type"] = "bytes32"
    if mutation == "extra":
        payload["message"]["withdraw"] = True
    if mutation == "owner":
        account = "0x" + "1" * 40
    with pytest.raises(ValueError):
        sign(
            {"key": FIXTURE_KEY, "account": account, "expected_builder": BUILDER, "typed": payload},
            now_ms=NOW,
        )
