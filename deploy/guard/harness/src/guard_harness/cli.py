"""C3 machine-readable CLI boundary. Never parse human status output or log keys."""

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from guard_harness.runner import run

ADDRESS = {"type": "string", "pattern": "^0x[0-9a-fA-F]{40}$"}
LICENCE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["state", "licensee", "expires_at_ms", "fee_free", "source"],
    "properties": {
        "state": {"enum": ["valid", "expired", "invalid", "none"]},
        "licensee": {"type": ["string", "null"]},
        "expires_at_ms": {"type": ["integer", "null"], "minimum": 0},
        "fee_free": {"type": "boolean"},
        "source": {"enum": ["file", "auto_update"]},
    },
}
STATUS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": [
        "version",
        "network",
        "account",
        "mode",
        "halted",
        "kill_switch",
        "licence",
        "journal",
    ],
    "properties": {
        "version": {"type": "string", "minLength": 1},
        "network": {"enum": ["paper", "testnet", "mainnet"]},
        "account": ADDRESS,
        "mode": {"type": "string", "minLength": 1},
        "halted": {"type": "boolean"},
        "kill_switch": {"type": "boolean"},
        "licence": LICENCE_SCHEMA,
        "journal": {
            "type": "object",
            "required": ["ok"],
            "properties": {"ok": {"type": "boolean"}},
        },
    },
}
PAIR_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["client_address", "client_key"],
    "properties": {
        "client_address": ADDRESS,
        "client_key": {"type": "string", "pattern": "^0x[0-9a-fA-F]{64}$"},
    },
}


class ContractError(ValueError):
    """C3 is missing or malformed; diagnostics deliberately omit field values."""


@dataclass(frozen=True)
class Pair:
    address: str
    key: str = field(repr=False)


def decode_json(output: str, schema: Mapping[str, Any]) -> dict[str, Any]:
    try:
        value: Any = json.loads(output)
    except json.JSONDecodeError as error:
        raise ContractError("CLI output is not JSON") from error
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(value), key=lambda error: str(error.json_path))
    if errors:
        # jsonschema's message contains rejected values, including keys for pair output.
        paths = ", ".join(error.json_path for error in errors)
        raise ContractError(f"C3 CLI fields missing or malformed at: {paths}")
    if not isinstance(value, dict):
        raise ContractError("CLI output must be an object")
    return value


@dataclass(frozen=True)
class GuardCLI:
    binary: Path
    logs: Path
    cwd: Path

    def status(self, *, url: str | None = None) -> dict[str, Any]:
        args = ["status", "--json"]
        if url is not None:
            args.extend(["--url", url])
        return self._json(args, STATUS_SCHEMA, "status")

    def licence(self) -> dict[str, Any]:
        return self._json(["licence", "show", "--json"], LICENCE_SCHEMA, "licence")

    def set_licence(self, key: str) -> None:
        if not key.startswith("zgl1_") or "\n" in key or "\r" in key:
            raise ContractError("licence input must be a single zgl1 key")
        # The additive C3 stdin command keeps licence input off argv. Older binaries fail
        # with an unknown flag; the key never enters argv or command diagnostics.
        run(
            [str(self.binary), "--home", str(self.cwd), "licence", "set", "--stdin"],
            log=self.logs / "licence-set.log",
            cwd=self.cwd,
            timeout=30,
            stdin=(key + "\n").encode(),
            secrets=[key],
        )

    def pair(self) -> Pair:
        result = self._json(["pair", "--json"], PAIR_SCHEMA, "pair", sensitive=True)
        return Pair(result["client_address"], result["client_key"])

    def _json(
        self, args: list[str], schema: Mapping[str, Any], name: str, *, sensitive: bool = False
    ) -> dict[str, Any]:
        result = run(
            # Pin an explicit sandbox home; pairing must never mutate the operator
            # home just because a runner inherited ZUNDER_GUARD_HOME.
            [str(self.binary), "--home", str(self.cwd), *args],
            log=self.logs / f"{name}.log",
            cwd=self.cwd,
            timeout=30,
            sensitive_output=sensitive,
        )
        return decode_json(result.output, schema)
