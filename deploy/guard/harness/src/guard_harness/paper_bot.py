"""Signed paper decisions on a local Guard, using the official venue SDK signer."""

import ipaddress
import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal, cast
from urllib.parse import urlsplit

from eth_account import Account
from eth_account.signers.local import LocalAccount
from hyperliquid.utils.signing import sign_l1_action

from guard_harness.cli import Pair

Verdict = Literal["allow", "resize", "veto"]
# The SDK is untyped. Keep its boundary narrow rather than copying its signing protocol.
Signer = Callable[[LocalAccount, dict[str, Any], None, int, None, bool], dict[str, Any]]
_sign = cast(Signer, sign_l1_action)


class PaperError(RuntimeError):
    """A paper-only precondition or journal assertion failed."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        raise PaperError("Guard redirected a local request")


class LocalGuard:
    """Bounded HTTP client without proxies or redirects; literal loopback addresses only."""

    def __init__(self, url: str) -> None:
        parsed = urlsplit(url)
        try:
            loopback = ipaddress.ip_address(parsed.hostname or "").is_loopback
        except ValueError:
            loopback = False
        if (
            parsed.scheme != "http"
            or not loopback
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            raise PaperError("paper bot requires an HTTP literal-loopback Guard URL")
        self.url = url.rstrip("/")
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, path: str, body: dict[str, Any] | None = None) -> Any:
        if not path.startswith("/") or path.startswith("//"):
            raise PaperError("invalid local Guard path")
        data = None if body is None else json.dumps(body, allow_nan=False).encode()
        headers = {"Content-Type": "application/json"}
        request = urllib.request.Request(self.url + path, data=data, headers=headers)
        try:
            with self.opener.open(request, timeout=5) as response:
                payload = response.read(1_048_577)
            if len(payload) > 1_048_576:
                raise PaperError("Guard response exceeded the size bound")
            return json.loads(payload)
        except (urllib.error.URLError, json.JSONDecodeError, UnicodeDecodeError) as error:
            # Never include a response body, credentials or the request in diagnostics.
            raise PaperError("local Guard HTTP/JSON request failed") from error


@dataclass(frozen=True)
class Decision:
    nonce: int
    seq: int
    verdict: Verdict
    code: str


class PaperBot:
    def __init__(self, guard: LocalGuard, pair: Pair) -> None:
        self.guard = guard
        try:
            self.wallet = Account.from_key(pair.key)
        except (ValueError, TypeError) as error:
            raise PaperError("paired signing key is invalid") from error
        if self.wallet.address.lower() != pair.address.lower():
            raise PaperError("paired client address does not match its signing key")
        self.nonce = 0

    def decide(self, action: dict[str, Any], expected: Verdict, *, expected_code: str) -> Decision:
        if (
            action.get("type") != "order"
            or expected not in ("allow", "resize", "veto")
            or not expected_code
        ):
            raise PaperError("paper lifecycle cases must be orders with a known verdict")
        events = self._events(0)
        since = max((event["seq"] for event in events), default=0)
        status = self.guard.request("/guard/status")
        if not isinstance(status, dict) or status.get("mode") != "paper":
            raise PaperError("paper bot refused a Guard that is not in paper mode")
        capabilities = status.get("capabilities")
        if (
            not isinstance(capabilities, dict)
            or capabilities.get("exchange_expected_mode") is not True
        ):
            raise PaperError("Guard does not enforce expected exchange mode")
        started = status.get("started_at_ms")
        if type(started) is not int or started < 0:
            raise PaperError("Guard status lacks a valid start timestamp")
        # Guard fences old client requests for five seconds after every restart.
        # Wait for the fence rather than fabricating an ahead-of-clock nonce.
        wait_ms = started + 5_000 - time.time_ns() // 1_000_000
        if wait_ms > 5_000:
            raise PaperError("Guard start timestamp is ahead of the local clock")
        if wait_ms > 0:
            time.sleep(wait_ms / 1_000)
        self.nonce = max(time.time_ns() // 1_000_000, self.nonce + 1)
        signature = _sign(self.wallet, action, None, self.nonce, None, False)
        # The condition is in the strict request envelope: older Guard versions
        # reject unknown fields, so a replacement cannot silently ignore a header.
        reply = self.guard.request(
            "/exchange",
            {
                "action": action,
                "nonce": self.nonce,
                "signature": signature,
                "expectedMode": "paper",
            },
        )
        if (
            not isinstance(reply, dict)
            or reply.get("status") != "err"
            # Veto replies follow Hyperliquid's error shape without a verdict.
            # The independently matched journal decision must still say veto.
            or (
                reply.get("verdict") != expected
                and not (expected == "veto" and "verdict" not in reply)
            )
            or reply.get("code") != expected_code
        ):
            raise PaperError("paper response did not have the expected verdict and reason code")
        deadline = time.monotonic() + 5
        while True:
            events = self._events(since)
            matches = [
                event
                for event in events
                if event.get("kind") == "decision"
                and event.get("nonce") == self.nonce
                and str(event.get("client", "")).lower() == self.wallet.address.lower()
            ]
            if matches:
                if len(matches) != 1:
                    raise PaperError("paper request has duplicate journal decisions")
                decision = matches[0]
                if (
                    decision.get("verdict") != expected
                    or decision.get("code") != reply.get("code")
                    or decision.get("request") != action
                    or not isinstance(decision.get("code"), str)
                ):
                    raise PaperError("paper response and journal decision disagree")
                if any(
                    event.get("kind") == "sent" and event.get("decision") == decision["seq"]
                    for event in events
                ):
                    raise PaperError("paper request unexpectedly has a venue-send event")
                return Decision(self.nonce, decision["seq"], expected, decision["code"])
            if time.monotonic() >= deadline:
                raise PaperError("paper response has no matching journal decision")
            time.sleep(0.1)

    def _events(self, since: int) -> list[dict[str, Any]]:
        events = self.guard.request(f"/guard/events?since={since}")
        if not isinstance(events, list) or any(
            not isinstance(event, dict)
            or type(event.get("seq")) is not int
            or event["seq"] <= since
            for event in events
        ):
            raise PaperError("Guard events are malformed")
        return events
