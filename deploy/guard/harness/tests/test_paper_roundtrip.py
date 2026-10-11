from typing import Any

import pytest

import guard_harness.paper_roundtrip as lifecycle
from guard_harness.cli import Pair
from guard_harness.paper_bot import Decision, LocalGuard, PaperError


class Guard(LocalGuard):
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.bad_stop = False

    def request(self, path: str, body: dict[str, Any] | None = None) -> Any:
        if body == {"type": "meta"}:
            return {"universe": [{"name": "BTC", "szDecimals": 5}]}
        if body == {"type": "allMids"}:
            return {"BTC": "100000"}
        return self.events


def test_exact_paper_prices_and_resize_stop_binding(monkeypatch: pytest.MonkeyPatch) -> None:
    guard = Guard()
    actions: list[dict[str, Any]] = []
    pauses: list[float] = []

    class Bot:
        def __init__(self, local: LocalGuard, pair: Pair) -> None:
            assert local is guard

        def decide(self, action: dict[str, Any], verdict: str, *, expected_code: str) -> Decision:
            actions.append(action)
            seq = len(actions)
            if verdict != "veto":
                forwarded = "0.0002" if verdict == "allow" else "0.001"
                guard.events.append(
                    {
                        "seq": seq,
                        "forward": {
                            "orders": [
                                {"s": forwarded},
                                {"s": forwarded, "r": True},
                            ]
                        },
                    }
                )
            return Decision(seq, seq, verdict, expected_code)  # type: ignore[arg-type]

    monkeypatch.setattr(lifecycle, "PaperBot", Bot)
    result = lifecycle.round_trip(guard, Pair("unused", "unused"), pause=pauses.append)
    assert [d.code for d in result] == ["unsupported_market", "allowed", "resized"]
    assert pauses == [15, 15]
    entry, stop = actions[1]["orders"]
    assert (entry["p"], entry["s"], stop["p"], stop["s"]) == ("100000", "0.0002", "87220", "0.0002")
    assert stop["t"]["trigger"]["triggerPx"] == "98000"
    assert stop["r"] is True
    assert actions[2]["orders"][0]["s"] == "10000"


@pytest.mark.parametrize("forward", ["0", "10000", "10001"])
def test_resize_must_reduce_positive_quantity(
    monkeypatch: pytest.MonkeyPatch, forward: str
) -> None:
    guard = Guard()

    class Bot:
        def __init__(self, local: LocalGuard, pair: Pair) -> None:
            pass

        def decide(self, action: dict[str, Any], verdict: str, *, expected_code: str) -> Decision:
            if verdict != "veto":
                size = "0.0002" if verdict == "allow" else forward
                guard.events.append(
                    {
                        "seq": len(guard.events),
                        "forward": {
                            "orders": [
                                {"s": size},
                                {"s": size, "r": True},
                            ]
                        },
                    }
                )
                seq = guard.events[-1]["seq"]
            else:
                seq = -1
            return Decision(seq, seq, verdict, expected_code)  # type: ignore[arg-type]

    monkeypatch.setattr(lifecycle, "PaperBot", Bot)
    with pytest.raises(PaperError, match="quantity"):
        lifecycle.round_trip(guard, Pair("unused", "unused"), pause=lambda _: None)
