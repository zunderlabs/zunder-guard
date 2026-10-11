"""SDK signatures, paper-only refusal and independent journal evidence assertions."""

import time
from collections.abc import Callable
from typing import Any, cast

import pytest
from eth_account import Account
from hyperliquid.utils.signing import recover_agent_or_user_from_l1_action

from guard_harness.cli import Pair
from guard_harness.paper_bot import LocalGuard, PaperBot, PaperError, Verdict

Recover = Callable[[dict[str, Any], dict[str, Any], None, int, None, bool], str]
recover = cast(Recover, recover_agent_or_user_from_l1_action)


class GuardFixture(LocalGuard):
    def __init__(self, pair: Pair, verdict: Verdict = "allow") -> None:
        self.pair = pair
        self.verdict = verdict
        self.mode = "paper"
        self.started_at_ms = time.time_ns() // 1_000_000 - 5_000
        self.capability = True
        self.replace_on_exchange = False
        self.replace_with_old = False
        self.submitted: list[dict[str, Any]] = []
        self.events: list[dict[str, Any]] = []
        self.corrupt = ""

    def request(self, path: str, body: dict[str, Any] | None = None) -> Any:
        if path == "/guard/status":
            return {
                "mode": self.mode,
                "started_at_ms": self.started_at_ms,
                "capabilities": {"exchange_expected_mode": self.capability},
            }
        if path.startswith("/guard/events"):
            since = int(path.split("=")[1])
            return [event for event in self.events if event["seq"] > since]
        assert path == "/exchange" and body is not None
        assert body["expectedMode"] == "paper"
        if self.replace_on_exchange:
            self.mode = "mainnet"
        if self.replace_with_old:
            # Current Guard's strict envelope rejects expectedMode as an unknown field.
            assert "expectedMode" in body
            return {"status": "err", "code": "malformed"}
        if self.mode != body["expectedMode"]:
            return {"status": "err", "code": "unexpected_mode"}
        # Use the official recovery implementation as the signature's independent consumer.
        assert recover(body["action"], body["signature"], None, body["nonce"], None, False)
        assert (
            recover(body["action"], body["signature"], None, body["nonce"], None, False).lower()
            == self.pair.address.lower()
        )
        self.submitted.append(body)
        decision: dict[str, Any] = {
            "seq": len(self.events) + 1,
            "kind": "decision",
            "client": self.pair.address,
            "nonce": body["nonce"],
            "verdict": self.verdict,
            "code": {"allow": "allowed", "resize": "resized", "veto": "unsupported_market"}[
                self.verdict
            ],
            "request": body["action"],
        }
        reply = {"status": "err", "code": decision["code"]}
        if self.verdict != "veto":
            reply["verdict"] = self.verdict
        if self.corrupt == "reply-status":
            reply["status"] = "ok"
        if self.corrupt in ("verdict", "code", "request", "client"):
            decision[self.corrupt] = "wrong"
        self.events.append(decision)
        if self.corrupt == "duplicate":
            self.events.append({**decision, "seq": decision["seq"] + 1})
        if self.corrupt == "sent":
            self.events.append(
                {"kind": "sent", "seq": decision["seq"] + 1, "decision": decision["seq"]}
            )
        return reply


@pytest.fixture
def pair() -> Pair:
    wallet = Account.create()
    return Pair(wallet.address, "0x" + wallet.key.hex())


def action() -> dict[str, Any]:
    return {
        "type": "order",
        "orders": [
            {"a": 0, "b": True, "p": "100", "s": "0.1", "r": False, "t": {"limit": {"tif": "Ioc"}}}
        ],
        "grouping": "na",
    }


@pytest.mark.parametrize("verdict", ["allow", "resize", "veto"])
def test_signed_request_matches_journal(pair: Pair, verdict: Verdict) -> None:
    guard = GuardFixture(pair, verdict)
    bot = PaperBot(guard, pair)
    first = bot.decide(
        action(),
        verdict,
        expected_code={"allow": "allowed", "resize": "resized", "veto": "unsupported_market"}[
            verdict
        ],
    )
    second = bot.decide(
        action(),
        verdict,
        expected_code={"allow": "allowed", "resize": "resized", "veto": "unsupported_market"}[
            verdict
        ],
    )
    assert first.verdict == verdict and second.verdict == verdict
    assert second.seq > first.seq and second.nonce > first.nonce
    assert len(guard.submitted) == 2


@pytest.mark.parametrize("mode", ["testnet", "mainnet", None])
def test_refuses_nonpaper_before_signing_or_exchange(pair: Pair, mode: Any) -> None:
    guard = GuardFixture(pair)
    guard.mode = mode
    with pytest.raises(PaperError, match="not in paper mode"):
        PaperBot(guard, pair).decide(action(), "allow", expected_code="allowed")
    assert guard.submitted == []


def test_rechecks_mode_for_each_order(pair: Pair) -> None:
    guard = GuardFixture(pair)
    bot = PaperBot(guard, pair)
    bot.decide(action(), "allow", expected_code="allowed")
    guard.mode = "testnet"
    with pytest.raises(PaperError):
        bot.decide(action(), "allow", expected_code="allowed")
    assert len(guard.submitted) == 1


@pytest.mark.parametrize("corrupt", ["verdict", "code", "request", "duplicate", "sent"])
def test_reply_is_insufficient_without_consistent_journal(pair: Pair, corrupt: str) -> None:
    guard = GuardFixture(pair)
    guard.corrupt = corrupt
    with pytest.raises(PaperError):
        PaperBot(guard, pair).decide(action(), "allow", expected_code="allowed")


def test_missing_client_decision_times_out(pair: Pair, monkeypatch: pytest.MonkeyPatch) -> None:
    guard = GuardFixture(pair)
    guard.corrupt = "client"
    ticks = iter([0, 6])
    monkeypatch.setattr("guard_harness.paper_bot.time.monotonic", lambda: next(ticks))
    with pytest.raises(PaperError, match="no matching journal"):
        PaperBot(guard, pair).decide(action(), "allow", expected_code="allowed")


def test_refuses_pair_address_mismatch(pair: Pair) -> None:
    with pytest.raises(PaperError, match="does not match"):
        PaperBot(GuardFixture(pair), Pair("0x" + "0" * 40, pair.key))


def test_refuses_permission_action(pair: Pair) -> None:
    guard = GuardFixture(pair)
    with pytest.raises(PaperError):
        PaperBot(guard, pair).decide(
            {"type": "approveAgent"}, "veto", expected_code="funds_or_permissions"
        )
    assert guard.submitted == []


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1",
        "http://localhost",
        "http://192.0.2.1",
        "http://example.com",
        "http://user:secret@127.0.0.1",
        "http://127.0.0.1/path",
        "http://127.0.0.1?key=secret",
        "http://127.0.0.1#fragment",
    ],
)
def test_refuses_nonliteral_loopback_origin(url: str) -> None:
    with pytest.raises(PaperError):
        LocalGuard(url)


@pytest.mark.parametrize("url", ["http://127.0.0.1:8787", "http://[::1]:8787/"])
def test_accepts_loopback(url: str) -> None:
    LocalGuard(url)


def test_refuses_old_guard_without_atomic_mode_capability(pair: Pair) -> None:
    guard = GuardFixture(pair)
    guard.capability = False
    with pytest.raises(PaperError, match="does not enforce"):
        PaperBot(guard, pair).decide(action(), "allow", expected_code="allowed")
    assert guard.submitted == []


def test_replacement_server_enforces_mode_condition(pair: Pair) -> None:
    guard = GuardFixture(pair)
    guard.replace_on_exchange = True
    with pytest.raises(PaperError, match="expected verdict"):
        PaperBot(guard, pair).decide(action(), "allow", expected_code="allowed")
    assert guard.submitted == []


def test_downgrade_server_rejects_unknown_envelope_field(pair: Pair) -> None:
    guard = GuardFixture(pair)
    guard.replace_with_old = True
    with pytest.raises(PaperError, match="expected verdict"):
        PaperBot(guard, pair).decide(action(), "allow", expected_code="allowed")
    assert guard.submitted == []


def test_waits_for_guard_restart_nonce_fence(pair: Pair, monkeypatch: pytest.MonkeyPatch) -> None:
    guard = GuardFixture(pair)
    guard.started_at_ms = 10_000
    sleeps: list[float] = []
    times = iter([12_000_000_000, 15_000_000_000])
    monkeypatch.setattr("guard_harness.paper_bot.time.time_ns", lambda: next(times))
    monkeypatch.setattr("guard_harness.paper_bot.time.sleep", sleeps.append)
    result = PaperBot(guard, pair).decide(action(), "allow", expected_code="allowed")
    assert sleeps == [3.0]
    assert result.nonce == 15_000


def test_refuses_ahead_of_clock_start_timestamp(pair: Pair) -> None:
    guard = GuardFixture(pair)
    guard.started_at_ms += 30_000
    with pytest.raises(PaperError, match="ahead of the local clock"):
        PaperBot(guard, pair).decide(action(), "allow", expected_code="allowed")
    assert guard.submitted == []


def test_veto_for_wrong_reason_does_not_pass_policy_case(pair: Pair) -> None:
    guard = GuardFixture(pair, "veto")
    with pytest.raises(PaperError, match="reason code"):
        PaperBot(guard, pair).decide(action(), "veto", expected_code="daily_loss")


def test_paper_reply_must_not_claim_venue_success(pair: Pair) -> None:
    guard = GuardFixture(pair)
    guard.corrupt = "reply-status"
    with pytest.raises(PaperError, match="expected verdict"):
        PaperBot(guard, pair).decide(action(), "allow", expected_code="allowed")
