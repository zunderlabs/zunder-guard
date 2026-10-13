"""Bounded durable ownership subset; never a reusable mutation or flat permit."""

import hashlib
import json
import os
import re
import uuid
from collections.abc import Sequence
from decimal import Decimal
from pathlib import Path
from typing import Any

from guard_harness.testnet_protection import (
    Entry,
    ProtectionError,
    _need,
    _object,
    _orders,
    _positive,
    prove_stop,
)
from guard_harness.testnet_reconcile import _oid, order_statuses

# Exact public Outcome codes emitted by tools.rs, including preview.rs sanity refusals
# and contract.rs known_reason/known_code (dynamic Guard preview and exchange vetoes).
# Never retain arbitrary strings or quoted text.
ENTRY_CODES = frozenset(
    {
        "invalid_arguments",
        "no_price",
        "unknown_market",
        "venue_unreadable",
        "not_a_guard",
        "guard_rules_unreadable",
        "guard_unreachable",
        "guard_timeout",
        "guard_http_error",
        "guard_unreadable",
        "preview_unsupported",
        "preview_unavailable",
        "preview_rate_limited",
        "preview_view_stale",
        "preview_refused",
        "preview_unreadable",
        "network_mismatch",
        "no_client_key",
        "expected_mode_unsupported",
        "client_not_registered",
        "mainnet_not_confirmed",
        "client_key_is_a_wallet",
        "unsignable",
        "check_first",
        "below_minimum",
        "max_unavailable",
        "rate_limited",
        "kill_switch",
        "journal",
        "daily_loss_stop",
        "drawdown_halt",
        "venue_reply_unreadable",
        "venue_refused",
        "partly_refused",
        "refused",
        "outcome_unknown",
        "not_an_entry",
        "absurd_price",
        "absurd_size",
        "account_unknown",
        "account_unreadable",
        "action_not_allowed",
        "allowed",
        "auth_bad_signature",
        "auth_expired",
        "auth_nonce_before_start",
        "auth_nonce_too_new",
        "auth_nonce_too_old",
        "auth_replay",
        "auth_too_large",
        "auth_unknown_signer",
        "client_builder",
        "client_not_allowed",
        "coin_not_allowed",
        "cross_margin",
        "dex_margin",
        "dex_not_allowed",
        "fee_not_approved",
        "flip",
        "funds_or_permissions",
        "guard_stop",
        "halted_for_day",
        "invalid",
        "invalid_request",
        "killed",
        "leverage",
        "leverage_exhausted",
        "liquidation_too_close",
        "malformed",
        "margin_not_set",
        "margin_removal",
        "market_halted",
        "market_not_allowed",
        "mode_mismatch",
        "modify_entry",
        "no_protective_stop",
        "nonce_reused",
        "one_entry_per_action",
        "open_interest_cap",
        "open_risk",
        "open_risk_exhausted",
        "position_cap",
        "position_cap_reached",
        "reduce_only_unjudged",
        "resized",
        "schedule_cancel",
        "stop_loosened",
        "stop_loosening_ignored",
        "stop_on_wrong_side",
        "stop_removed",
        "stop_required",
        "stop_wrong_side",
        "stopped",
        "thin_book",
        "unknown_order",
        "unprotected_order",
        "unprotected_position",
        "unsupported_action",
        "unsupported_market",
        "unsupported_order",
        "vault",
        "venue_refused_leverage",
        "venue_unreachable",
    }
)
ENTRY_OUTCOMES = frozenset(
    {
        "sent",
        "unknown",
        "venue_refused",
        "partly_refused",
        "vetoed_by_guard",
        "paper_mode_not_sent",
        "refused_or_unknown",
    }
)
RESPONSE_STAGES = {
    "entry-response": "mcp-result",
    "entry-call-unconfirmed": "mcp-call",
    "ownership-events": "guard-events",
    "ownership-events-unavailable": "guard-events",
    "ownership-validation": "ownership-validation",
    "ownership-validation-refused": "ownership-validation",
    "ownership-storage-failed": "ownership-storage",
    "ownership-captured": "ownership-validation",
    "venue-collection": "venue-collection",
}


def entry_response(result: object, error: bool | None) -> dict[str, object]:
    """Finite observations only, never mutation/ownership/flat evidence."""
    value = result if type(result) is dict else {}
    is_error = error if type(error) is bool else None
    detail = value.get("error")
    # Outcome::fail stores its code in error.code. A conflicting top-level field
    # never overrides that schema; malformed nested errors never fall back to it.
    code = detail.get("code") if is_error is True and type(detail) is dict else None
    if is_error is False and "error" not in value and value.get("outcome") == "paper_mode_not_sent":
        code = value.get("code")  # The shipped paper reply is the one top-level-code schema.
    outcome = value.get("outcome")
    code = code if type(code) is str and code in ENTRY_CODES else "unknown"
    http_status: int | None = None
    # GuardError::Http's exact public Display, never response bodies or free text.
    if code == "guard_http_error" and is_error is True and type(detail) is dict:
        reason = detail.get("reason")
        matched = (
            re.fullmatch(r"Guard answered with HTTP status ([1-5][0-9]{2})", reason)
            if type(reason) is str
            else None
        )
        if matched is not None:
            http_status = int(matched[1])
    outcome = outcome if type(outcome) is str and outcome in ENTRY_OUTCOMES else "unknown"
    sent = value.get("sent") if type(value.get("sent")) is bool else None
    ok = value.get("ok") if type(value.get("ok")) is bool else None
    category = "unknown"
    if code in {"preview_unsupported", "expected_mode_unsupported"}:
        category = "unsupported"
    elif outcome == "vetoed_by_guard":
        category = "vetoed"
    elif outcome in {"venue_refused", "partly_refused"}:
        category = "venue_refused"
    elif (
        (outcome == "unknown" and value.get("outcome") == "unknown")
        or outcome == "refused_or_unknown"
        or code in {"outcome_unknown", "venue_reply_unreadable"}
    ):
        category = "outcome_unknown"
    elif is_error is True and sent is False:
        category = "refused_before_send"
    elif outcome == "sent" and is_error is False and sent is True and ok is True:
        category = "reported_sent"
    return {
        "response_available": type(result) is dict,
        "isError": is_error,
        "ok": ok,
        "sent": sent,
        "code": code,
        "http_status": http_status,
        "outcome": outcome,
        "category": category,
    }


def _wire(value: object, entry: Entry) -> dict[str, Any]:
    wire = _object(value)
    _need(set(wire) == {"a", "b", "r", "p", "s", "c", "t"})
    _need(type(wire["a"]) is int and wire["a"] == entry.asset)
    _need(type(wire["b"]) is bool and type(wire["r"]) is bool)
    _need(
        isinstance(wire["c"], str)
        and re.fullmatch(r"0x7a(?:6d|67)[0-9a-f]{28}", wire["c"]) is not None
    )
    _need(_positive(wire["s"]) <= entry.size and _positive(wire["p"]) > 0)
    _need(
        _positive(wire["s"]) == _positive(wire["s"]).quantize(Decimal(1).scaleb(-entry.precision))
    )
    kind = _object(wire["t"])
    if set(kind) == {"limit"}:
        _need(kind == {"limit": {"tif": "Ioc"}})
    else:
        _need(set(kind) == {"trigger"})
        trigger = _object(kind["trigger"])
        _need(set(trigger) == {"triggerPx", "tpsl", "isMarket"})
        _need(trigger["tpsl"] == "sl" and trigger["isMarket"] is True)
        _positive(trigger["triggerPx"])
    return _object(
        json.loads(json.dumps(wire))
    )  # Separate bounded validated data from caller mutation.


def _action(value: object, entry: Entry) -> dict[str, Any]:
    action = _object(value)
    expected = {"type", "orders", "grouping"}
    if "builder" in action:
        expected.add("builder")
        builder = _object(action["builder"])
        _need(set(builder) == {"b", "f"})
        _need(
            isinstance(builder["b"], str)
            and re.fullmatch(r"0x[0-9a-fA-F]{40}", builder["b"]) is not None
        )
        _need(type(builder["f"]) is int and builder["f"] == 20)
    _need(set(action) == expected and action["type"] == "order")
    _need(action["grouping"] in {"na", "normalTpsl"})
    wires = _orders(action["orders"])
    _need(1 <= len(wires) <= 2)
    # Builder identity is proved separately by P8; omit all account addresses from this subset.
    return {
        "type": "order",
        "grouping": action["grouping"],
        "orders": [_wire(w, entry) for w in wires],
    }


def _leverage(value: object, entry: Entry) -> None:
    action = _object(value)
    _need(set(action) == {"type", "asset", "isCross", "leverage"})
    _need(action["type"] == "updateLeverage" and action["isCross"] is False)
    _need(type(action["asset"]) is int and action["asset"] == entry.asset)
    _need(type(action["leverage"]) is int and 1 <= action["leverage"] <= 100)


def _reply(value: object) -> dict[str, Any]:
    reply = _object(value)
    _need(set(reply) == {"status", "response"} and reply["status"] == "ok")
    response = _object(reply["response"])
    _need(set(response) == {"type", "data"} and response["type"] == "order")
    data = _object(response["data"])
    _need(set(data) == {"statuses"} and isinstance(data["statuses"], list))
    _need(1 <= len(data["statuses"]) <= 2)
    statuses: list[object] = []
    for value in data["statuses"]:
        if isinstance(value, str):
            _need(value in {"waitingForTrigger", "waitingForFill"})
            statuses.append(value)
            continue
        status = _object(value)
        _need(len(status) == 1 and next(iter(status)) in {"filled", "resting"})
        name = next(iter(status))
        ack = _object(status[name])
        _need(set(ack) <= {"oid", "cloid", "totalSz", "avgPx"})
        _oid(ack.get("oid"))
        if "cloid" in ack:
            _need(
                isinstance(ack["cloid"], str)
                and re.fullmatch(r"0x[0-9a-f]{32}", ack["cloid"]) is not None
            )
        for field in ("totalSz", "avgPx"):
            if field in ack:
                _positive(ack[field])
        statuses.append({name: dict(ack)})
    return {"status": "ok", "response": {"type": "order", "data": {"statuses": statuses}}}


def ownership_subset(
    events: Sequence[dict[str, Any]], client: str, entry: Entry
) -> list[dict[str, Any]]:
    """Validate run decisions, forwarded wires and sends before any paced venue read.

    This subset is insufficient for mutation: fresh twice-bound main exposure, exact
    fills/cloid lookups and original-account binding remain mandatory. No Started event,
    arbitrary diagnostic/body, credentials or signature is copied into durable output.
    """
    entry.validate()
    _need(entry.asset < 1000 and len(events) <= 10000)
    sequences = [_oid(event.get("seq")) for event in events]
    _need(len(sequences) == len(set(sequences)) and sequences == sorted(sequences))
    decisions: list[dict[str, Any]] = []
    for event in events:
        if event.get("kind") != "decision":
            continue
        _need(isinstance(event.get("client"), str) and event["client"].lower() == client.lower())
        _need(
            set(event)
            <= {
                "kind",
                "seq",
                "at_ms",
                "via",
                "client",
                "signed_as",
                "nonce",
                "action",
                "verdict",
                "code",
                "text",
                "changes",
                "request",
                "pre",
                "forward",
                "post",
            }
        )
        if "signed_as" in event:
            _need(event["signed_as"] == "testnet")
        request = _object(event.get("request"))
        if request.get("type") == "cancel":
            # Cancellation authority still comes only from the immediately fresh main proof.
            _need(event.get("action") == "cancel" and event.get("verdict") == "allow")
            _need(set(request) == {"type", "cancels"} and event.get("forward") == request)
            cancels = _orders(request["cancels"])
            _need(len(cancels) == 1 and set(cancels[0]) == {"a", "o"})
            _need(type(cancels[0]["a"]) is int and cancels[0]["a"] == entry.asset)
            _oid(cancels[0]["o"])
            continue
        _need(event.get("action") == "order" and event.get("verdict") in {"allow", "resize"})
        pre = event.get("pre", [])
        _need(isinstance(pre, list) and len(pre) <= 1 and not event.get("post"))
        for before in pre:
            _leverage(before, entry)
        changes = event.get("changes", [])
        _need(isinstance(changes, list) and len(changes) <= 8)
        subset_changes = [
            text
            for text in changes
            if isinstance(text, str)
            and re.fullmatch(
                r"a reduce-only stop at [0-9]+(?:\.[0-9]+)? "
                r"\(2% from [0-9]+(?:\.[0-9]+)?\) is attached",
                text,
            )
        ]
        decisions.append(
            {
                "kind": "decision",
                "seq": event["seq"],
                "client": client.lower(),
                "action": "order",
                "verdict": event["verdict"],
                "request": _action(request, entry),
                "forward": _action(event.get("forward"), entry),
                "changes": subset_changes,
            }
        )
    _need(1 <= len(decisions) <= 4)
    selected = {d["seq"] for d in decisions}
    subset = list(decisions)
    for event in events:
        if event.get("kind") == "intent" and event.get("of") in selected:
            _need(set(event) <= {"kind", "seq", "at_ms", "of", "action"})
            if "action" in event:
                if _object(event["action"]).get("type") == "updateLeverage":
                    _leverage(event["action"], entry)
                    continue
                _action(event["action"], entry)
            subset.append({"kind": "intent", "seq": event["seq"], "of": _oid(event["of"])})
    served = selected | {e["seq"] for e in subset if e["kind"] == "intent"}
    for event in events:
        if event.get("kind") == "sent" and event.get("decision") in served:
            _need(
                set(event)
                <= {"kind", "seq", "at_ms", "decision", "nonce", "ok", "reply", "action", "index"}
            )
            _need(event.get("ok") is True)
            if _object(_object(event.get("reply")).get("response")).get("type") != "order":
                continue
            if "action" in event:
                if _object(event["action"]).get("type") == "updateLeverage":
                    _leverage(event["action"], entry)
                    continue
                _action(event["action"], entry)
            subset.append(
                {
                    "kind": "sent",
                    "seq": event["seq"],
                    "decision": _oid(event["decision"]),
                    "ok": True,
                    "reply": _reply(event.get("reply")),
                }
            )
    subset.sort(key=lambda event: event["seq"])
    markets = [{"name": "unknown"}] * entry.asset + [{"name": "BTC", "szDecimals": entry.precision}]
    proof = prove_stop(subset, client, entry, markets=markets, filled=Decimal(0), mark=entry.limit)
    for decision in decisions:
        statuses = order_statuses(subset, decision["seq"])
        if decision["seq"] == proof.decision:
            _need(len(statuses) == 2)
            first = _object(statuses[0])
            _need(set(first) in ({"filled"}, {"resting"}))
            ack = _object(next(iter(first.values())))
            _need("cloid" not in ack or ack["cloid"] == proof.entry_cloid)
            if "totalSz" in ack:
                _need(_positive(ack["totalSz"]) <= entry.size)
            if "avgPx" in ack:
                _need(_positive(ack["avgPx"]) <= entry.limit)
            if isinstance(statuses[1], dict):
                second = _object(statuses[1])
                _need(set(second) == {"resting"})
                ack = _object(second["resting"])
                _need("cloid" not in ack or ack["cloid"] == proof.cloid)
        else:
            wire = decision["request"]["orders"]
            _need(decision["seq"] > proof.decision and decision["verdict"] == "allow")
            _need(decision["forward"] == decision["request"] and len(wire) == 1)
            _need(wire[0]["r"] is True and wire[0]["b"] is False)
            _need(wire[0]["t"] == {"limit": {"tif": "Ioc"}})
            _need(len(statuses) == 1)
    _need(len(json.dumps(subset).encode()) <= 65536)
    return subset


def _write(path: Path, value: dict[str, object], *, exclusive: bool) -> None:
    pending = path if exclusive else path.with_suffix(".pending")
    _need(not pending.exists() and not pending.is_symlink())
    with pending.open("x") as stream:
        pending.chmod(0o600)
        stream.write(json.dumps(value, sort_keys=True, allow_nan=False) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    if not exclusive:
        pending.replace(path)
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class OwnershipStore:
    def __init__(self, work: Path, *, account: str, client: str, source: str, version: str) -> None:
        _need(re.fullmatch(r"0x[0-9a-fA-F]{40}", account) is not None)
        _need(re.fullmatch(r"0x[0-9a-fA-F]{40}", client) is not None)
        _need(re.fullmatch(r"[0-9a-f]{64}", source) is not None)
        _need(re.fullmatch(r"\d+\.\d+\.\d+(?:-rc\.[1-9]\d*)?", version) is not None)
        self.work, self.client = work, client
        self.identity: dict[str, object] = {
            "schema": 1,
            "attempt_id": uuid.uuid4().hex,
            "network": "testnet",
            "gate_eligible": False,
            "account_sha256": hashlib.sha256(account.lower().encode()).hexdigest(),
            "client": client.lower(),
            "binary_sha256": source,
            "version": version,
        }
        self.attempt: dict[str, object] | None = None
        self.response_record: dict[str, object] | None = None

    def begin(self, entry: Entry, started_ms: int) -> None:
        entry.validate()
        _need(type(started_ms) is int and started_ms > 0 and self.attempt is None)
        self.attempt = dict(
            self.identity,
            entry={
                "asset": entry.asset,
                "size": str(entry.size),
                "limit": str(entry.limit),
                "precision": entry.precision,
            },
            started_ms=started_ms,
            tool="place_order",
            arguments={
                "coin": "BTC",
                "side": "buy",
                "stop": "guard_policy",
                "size": str(entry.size),
                "limit_price": str(entry.limit),
                "time_in_force": "ioc",
            },
            entry_outcome="unknown",
        )
        _write(self.work / "entry-attempt.json", self.attempt, exclusive=True)

    def response(self, result: object, error: bool | None, stage: str) -> None:
        """Fsync finite response/capture diagnostics, without granting any ownership credit."""
        _need(self.attempt is not None and stage in RESPONSE_STAGES)
        if stage in {"entry-response", "entry-call-unconfirmed"}:
            _need(self.response_record is None)
            self.response_record = {
                "schema": 1,
                "attempt_id": self.identity["attempt_id"],
                "binary_sha256": self.identity["binary_sha256"],
                "version": self.identity["version"],
                "gate_eligible": False,
                **entry_response(result, error),
            }
        _need(self.response_record is not None)
        assert self.response_record is not None
        self.response_record.update(stage=stage, origin=RESPONSE_STAGES[stage])
        _write(self.work / "entry-response.json", self.response_record, exclusive=False)

    def capture(self, events: Sequence[dict[str, Any]], entry: Entry, started_ms: int) -> None:
        attempt = self.attempt
        if attempt is None:
            raise ProtectionError("durable attempt required")
        _need(attempt["started_ms"] == started_ms)
        _need(
            attempt["entry"]
            == {
                "asset": entry.asset,
                "size": str(entry.size),
                "limit": str(entry.limit),
                "precision": entry.precision,
            }
        )
        subset = ownership_subset(events, self.client, entry)
        attempt = self.attempt
        if attempt is None:
            raise ProtectionError("durable attempt required")
        _write(self.work / "ownership.json", dict(attempt, events=subset), exclusive=False)
