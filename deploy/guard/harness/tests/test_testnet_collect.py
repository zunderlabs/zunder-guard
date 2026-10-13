import copy
from typing import Any

import pytest
import test_testnet_ownership as reference

from guard_harness.testnet_collect import CollectionRace, collect_ownership
from guard_harness.testnet_scan import ScanError

ACCOUNT = "0x" + "12" * 20


class Reads:
    def __init__(self, fields: Any, mutation: str = "") -> None:
        self.fields, self.mutation = fields, mutation
        self.calls: list[dict[str, Any]] = []
        self.counts: dict[str, int] = {}

    def __call__(self, payload: dict[str, Any]) -> object:
        self.calls.append(payload)
        kind = payload["type"]
        self.counts[kind] = self.counts.get(kind, 0) + 1
        fields = self.fields
        if kind == "userAbstraction":
            return "unifiedAccount" if self.mutation == "abstraction" else "disabled"
        if kind == "perpDexs":
            name = (
                "changed" if self.mutation == "inventory" and self.counts[kind] == 2 else "fixture"
            )
            return [None, {"name": name}]
        if kind == "meta":
            return {"universe": copy.deepcopy(fields["markets"])}
        if kind == "orderStatus":
            if payload["oid"] in fields.get("exit_lookups", {}):
                return copy.deepcopy(fields["exit_lookups"][payload["oid"]])
            if payload["oid"] == fields["entry_lookup"]["order"]["order"]["cloid"]:
                return copy.deepcopy(fields["entry_lookup"])
            return copy.deepcopy(fields["stop_lookup"])
        if kind == "userFillsByTime":
            assert payload["user"] == ACCOUNT and payload["startTime"] == 1000
            fills = copy.deepcopy(fields["fills"])
            if self.mutation == "truncated":
                return fills * 500
            if self.mutation == "fills" and self.counts[kind] == 2:
                fills.append(dict(fills[0], tid=2, sz="0.0001"))
            return fills
        if kind == "clearinghouseState":
            positions = copy.deepcopy(fields["positions"])
            if payload.get("dex"):
                positions = (
                    positions
                    if self.mutation == "secondary-position"
                    or self.mutation == "secondary-position-race"
                    and self.counts[kind] == 4
                    else []
                )
            elif self.counts[kind] == 2:
                if self.mutation == "position":
                    positions[0]["szi"] = "0.0001"
                elif self.mutation == "mark":
                    positions[0]["positionValue"] = "12.1"
            return {"assetPositions": [{"position": p} for p in positions]}
        if kind == "frontendOpenOrders":
            orders = copy.deepcopy(fields["orders"])
            if payload.get("dex"):
                orders = (
                    orders
                    if self.mutation == "secondary-order"
                    or self.mutation == "secondary-order-race"
                    and self.counts[kind] == 4
                    else []
                )
            elif self.counts[kind] == 2 and self.mutation == "orders":
                orders = []
            return orders
        raise AssertionError("unexpected request")


@pytest.fixture
def case() -> Any:
    fixture: Any = reference.case
    return fixture.__wrapped__()


@pytest.mark.parametrize("mutation", ["", "mark"])
def test_fresh_complete_reads_bind_owned_exposure_without_keys(case: Any, mutation: str) -> None:
    reads = Reads(case[3], mutation)
    result = collect_ownership(reads, ACCOUNT, *case[:3], started_ms=1000)
    assert result.entry_oid == 41 and result.stop_oid == 42
    assert reads.counts["userFillsByTime"] == 2
    assert "perpDexs" not in reads.counts
    assert reads.counts["clearinghouseState"] == 2
    assert reads.counts["frontendOpenOrders"] == 2
    assert {
        call.get("dex", "") for call in reads.calls if call["type"] == "clearinghouseState"
    } == {""}


@pytest.mark.parametrize(
    "mutation",
    [
        "abstraction",
        "truncated",
        "fills",
        "position",
        "orders",
    ],
)
def test_incomplete_or_racing_main_exposure_refuses_observation(case: Any, mutation: str) -> None:
    with pytest.raises(RuntimeError):
        collect_ownership(Reads(case[3], mutation), ACCOUNT, *case[:3], started_ms=1000)


@pytest.mark.parametrize("mutation", ["fills", "position", "orders"])
def test_only_complete_snapshot_disagreement_has_the_settling_type(
    case: Any, mutation: str
) -> None:
    with pytest.raises(CollectionRace):
        collect_ownership(Reads(case[3], mutation), ACCOUNT, *case[:3], started_ms=1000)


def test_invalid_account_or_window_refuses_before_read(case: Any) -> None:
    reads = Reads(case[3])
    for account, started in [("invalid", 1000), (ACCOUNT, True), (ACCOUNT, 0)]:
        with pytest.raises(RuntimeError):
            collect_ownership(reads, account, *case[:3], started_ms=started)
    assert reads.calls == []


def test_unreadable_response_never_becomes_empty_holdings(case: Any) -> None:
    reads = Reads(case[3])

    def broken(payload: dict[str, Any]) -> object:
        if payload["type"] == "clearinghouseState":
            return {"assetPositions": None}
        return reads(payload)

    with pytest.raises(RuntimeError):
        collect_ownership(broken, ACCOUNT, *case[:3], started_ms=1000)


def test_fixed_transport_reserves_full_fill_weight_even_when_read_fails() -> None:
    from unittest.mock import Mock

    from guard_harness.testnet_scan import TestnetReads as Transport

    now = [0.0]
    sleeps: list[float] = []

    def sleep(seconds: float) -> None:
        sleeps.append(seconds)
        now[0] += seconds

    transport = Transport(clock=lambda: now[0], sleep=sleep, timeout=100)
    transport.opener = Mock()
    transport.opener.open.side_effect = ValueError("body withheld")
    for _ in range(2):
        with pytest.raises(ScanError, match="HTTP/JSON"):
            transport({"type": "userFillsByTime", "user": ACCOUNT, "startTime": 1000})
    assert sleeps == [12, 12]


@pytest.mark.parametrize(
    "payload",
    [
        {"type": "userFillsByTime", "user": ACCOUNT, "startTime": True},
        {"type": "userFillsByTime", "user": ACCOUNT, "startTime": 0},
        {"type": "orderStatus", "user": ACCOUNT, "oid": 41},
        {"type": "orderStatus", "user": ACCOUNT, "oid": "bad"},
        {"type": "frontendOpenOrders", "user": "invalid"},
    ],
)
def test_malformed_extended_reads_refuse_before_transport(payload: dict[str, Any]) -> None:
    from unittest.mock import Mock

    from guard_harness.testnet_scan import TestnetReads as Transport

    transport = Transport()
    transport.opener = Mock()
    with pytest.raises(ScanError):
        transport(payload)
    assert not transport.opener.open.called


@pytest.mark.parametrize(
    "payload",
    [
        {"type": "meta"},
        {"type": "orderStatus", "user": ACCOUNT, "oid": "0x7a6d" + "a" * 28},
        {"type": "userFillsByTime", "user": ACCOUNT, "startTime": 1000},
    ],
)
def test_extended_transport_keeps_fixed_url_and_integer_fill_window(
    payload: dict[str, Any],
) -> None:
    import json
    from unittest.mock import MagicMock, Mock

    from guard_harness.testnet_scan import TestnetReads as Transport

    transport = Transport(sleep=lambda _: None)
    transport.opener = MagicMock()
    response = Mock()
    transport.opener.open.return_value.__enter__.return_value = response
    response.read.return_value = b"[]"
    assert transport(payload) == []
    request = transport.opener.open.call_args.args[0]
    assert request.full_url == "https://api.hyperliquid-testnet.xyz/info"
    assert json.loads(request.data) == payload
    response.read.assert_called_once_with(1_048_577)


def test_collector_preserves_unfilled_entry_only_cleanup_rule(case: Any) -> None:
    fields = case[3]
    opening = fields["entry_lookup"]["order"]["order"]
    opening["sz"] = "0.0002"
    fields["entry_lookup"]["order"]["status"] = "open"
    fields.update(fills=[], positions=[], orders=[copy.deepcopy(opening)], stop_lookup=None)
    case[0][-1]["reply"]["response"]["data"]["statuses"] = [
        {"resting": {"oid": 41}},
        "waitingForFill",
    ]
    result = collect_ownership(Reads(fields), ACCOUNT, *case[:3], started_ms=1000, cleanup=True)
    assert result.resting_entry and result.stop_oid is None


@pytest.fixture
def closed_case(case: Any) -> Any:
    fixture: Any = reference.closed_case
    return fixture.__wrapped__(case)


def test_collector_fetches_own_close_and_historical_stop_to_prove_flat(closed_case: Any) -> None:
    reads = Reads(closed_case[3])
    result = collect_ownership(reads, ACCOUNT, *closed_case[:3], started_ms=1000, cleanup=True)
    assert result.remaining == 0 and result.stop_oid is None
    assert reads.counts["orderStatus"] == 3
    assert {call["oid"] for call in reads.calls if call["type"] == "orderStatus"} == {
        closed_case[3]["entry_lookup"]["order"]["order"]["cloid"],
        closed_case[3]["stop_lookup"]["order"]["order"]["cloid"],
        *closed_case[3]["exit_lookups"],
    }


@pytest.mark.parametrize("mutation", ["missing-lookup", "missing-fill", "fills"])
def test_collector_cannot_credit_incomplete_or_racing_flat_close(
    closed_case: Any, mutation: str
) -> None:
    fields = closed_case[3]
    if mutation == "missing-lookup":
        fields["exit_lookups"].clear()
    elif mutation == "missing-fill":
        fields["fills"].pop()
    with pytest.raises(RuntimeError):
        collect_ownership(
            Reads(fields, mutation), ACCOUNT, *closed_case[:3], started_ms=1000, cleanup=True
        )


@pytest.mark.parametrize("mutation", ["inventory", "secondary-position", "secondary-order"])
def test_main_mutation_observation_does_not_grant_secondary_flatness(
    case: Any, mutation: str
) -> None:
    reads = Reads(case[3], mutation)
    observed = collect_ownership(reads, ACCOUNT, *case[:3], started_ms=1000)
    assert observed.remaining == case[2].size
    assert all(not call.get("dex") for call in reads.calls)
    assert all(call["type"] != "perpDexs" for call in reads.calls)


def test_three_partial_closes_keep_exact_quantity_and_at_most_13_main_reads(case: Any) -> None:
    from decimal import Decimal

    import test_testnet_exits as exits_reference

    fixture: Any = exits_reference.case
    template = fixture.__wrapped__()
    events, client, entry, fields = case
    fields["stop_lookup"]["order"]["order"].update(origSz="0.0002", timestamp=1000)
    fields["exit_lookups"] = {}
    remaining = entry.size
    for index, filled in enumerate(("0.00006", "0.00006", "0.00008")):
        cloid = "0x7a6d" + str(index + 1) * 28
        decision, sent = copy.deepcopy(template[3][-2:])
        decision["seq"] = 4 + index * 2
        sent.update(seq=5 + index * 2, decision=decision["seq"])
        # Each close requested the complete then-owned quantity; venue partially fills it.
        for action in (decision["request"], decision["forward"]):
            action["orders"][0].update(c=cloid, s=str(remaining))
        oid = 43 + index
        sent["reply"]["response"]["data"]["statuses"] = [{"filled": {"oid": oid, "cloid": cloid}}]
        events.extend((decision, sent))
        lookup = copy.deepcopy(next(v for k, v in template[4].items() if k != template[2].cloid))
        lookup["order"]["order"].update(
            oid=oid, cloid=cloid, origSz=str(remaining), timestamp=1001 + index
        )
        fields["exit_lookups"][cloid] = lookup
        fields["fills"].append(
            {
                "oid": oid,
                "tid": 2 + index,
                "time": 1001 + index,
                "coin": "BTC",
                "side": "A",
                "sz": filled,
                "px": "60000",
            }
        )
        remaining -= Decimal(filled)
        fields["positions"] = (
            [
                {
                    "coin": "BTC",
                    "szi": str(remaining),
                    "positionValue": str(remaining * 60000),
                    "leverage": {"type": "isolated"},
                }
            ]
            if remaining
            else []
        )
        reads = Reads(fields)
        observed = collect_ownership(
            reads, ACCOUNT, events, client, entry, started_ms=1000, cleanup=True
        )
        assert observed.remaining == remaining and observed.stop_oid == 42
        assert len(reads.calls) == 11 + index  # 10 base reads + prior close lookups.
        assert all(not payload.get("dex") for payload in reads.calls)
    fields["orders"] = []
    fields["stop_lookup"]["order"]["status"] = "canceled"
    observed = collect_ownership(
        Reads(fields), ACCOUNT, events, client, entry, started_ms=1000, cleanup=True
    )
    assert observed.remaining == 0 and observed.stop_oid is None


@pytest.mark.parametrize("mutation", ["", "abstraction", "position", "orders", "fills"])
def test_failure_observer_preserves_original_reads_and_short_circuit(
    case: Any, mutation: str
) -> None:
    observations: list[dict[str, object]] = []
    plain, observed = Reads(case[3], mutation), Reads(case[3], mutation)
    failures: list[BaseException | None] = []
    for reads, callback in ((plain, lambda _: None), (observed, observations.append)):
        try:
            collect_ownership(reads, ACCOUNT, *case[:3], started_ms=1000, observe_failure=callback)
        except Exception as error:
            failures.append(error)
        else:
            failures.append(None)
    assert plain.calls == observed.calls
    assert type(failures[0]) is type(failures[1]) and str(failures[0]) == str(failures[1])
    assert len(observations) == (0 if mutation == "" else 1)
    if observations and mutation in {"position", "orders", "fills"}:
        facts = observations[0]
        assert facts["family"] == "collection-race" and facts["subphase"] == "stability"
        assert facts["positions_equal"] is (mutation != "position")
        assert facts["orders_equal"] is (None if mutation == "position" else mutation != "orders")
        assert facts["fills_equal"] is (False if mutation == "fills" else None)
        assert facts["net_vs_remaining"] is None


@pytest.mark.parametrize("observer_failure", [False, True])
@pytest.mark.parametrize("family", ["unknown", "timeout", "interrupted"])
def test_failed_collector_preserves_exception_identity_without_private_diagnostics(
    case: Any, observer_failure: bool, family: str
) -> None:
    import json

    classes = {"unknown": RuntimeError, "timeout": TimeoutError, "interrupted": KeyboardInterrupt}
    original = classes[family]("PRIVATE-KEY-" + "d" * 64)
    seen: list[dict[str, object]] = []
    calls = 0

    def read(payload: dict[str, Any]) -> object:
        nonlocal calls
        calls += 1
        raise original

    def observer(facts: dict[str, object]) -> None:
        seen.append(facts)
        if observer_failure:
            raise KeyboardInterrupt("PRIVATE-OBSERVER-ERROR")

    with pytest.raises(type(original)) as caught:
        collect_ownership(read, ACCOUNT, *case[:3], started_ms=1000, observe_failure=observer)
    assert caught.value is original and calls == 1
    assert seen[0]["family"] == family and seen[0]["subphase"] == "account-mode"
    assert "PRIVATE" not in json.dumps(seen) and ACCOUNT not in json.dumps(seen)


def test_terminal_collection_writer_is_exclusive_fsynced_private_and_finite(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    import json
    import os
    import stat

    from guard_harness.testnet_collect import retain_failure

    tmp_path.chmod(0o700)
    syncs: list[str] = []
    original = os.fsync

    def fsync(descriptor: int) -> None:
        syncs.append("directory" if stat.S_ISDIR(os.fstat(descriptor).st_mode) else "file")
        original(descriptor)

    monkeypatch.setattr(os, "fsync", fsync)
    retain_failure(
        tmp_path,
        {
            "family": "PRIVATE-KEY",
            "subphase": "PRIVATE-ACCOUNT",
            "entry_status": "PRIVATE-BODY",
            "stop_status": "reduceOnlyCanceled",
            "exit_statuses": ["filled", "PRIVATE-CLOID"],
            "positions_equal": "PRIVATE-BOOL",
            "orders_equal": True,
            "fills_equal": False,
            "net_vs_remaining": "PRIVATE-NET",
            "settling_enabled": True,
            "attempt": 3,
            "body": "PRIVATE-KEY-" + "a" * 64,
        },
    )
    path = tmp_path / "collection-failure.json"
    body = path.read_text()
    facts = json.loads(body)
    assert "PRIVATE" not in body
    assert facts["family"] == facts["subphase"] == facts["entry_status"] == "unknown"
    assert facts["exit_statuses"] == ["filled", "unknown"]
    assert facts["positions_equal"] is facts["net_vs_remaining"] is None
    assert facts["diagnostic"] is True and facts["gate_eligible"] is False
    assert path.stat().st_mode & 0o777 == 0o600 and syncs == ["file", "directory"]
    with pytest.raises(FileExistsError):
        retain_failure(tmp_path, {"family": "protection", "subphase": "reconcile"})
    assert path.read_text() == body and syncs == ["file", "directory"]


@pytest.mark.parametrize("stage", ["before-holdings", "partial-holdings", "complete-holdings"])
def test_empty_flags_describe_only_complete_first_holdings_snapshot(case: Any, stage: str) -> None:
    seen: list[dict[str, object]] = []
    reads = Reads(case[3])
    original = RuntimeError("PRIVATE-KEY-ORIGIN")

    def read(payload: dict[str, Any]) -> object:
        kind = payload["type"]
        if stage == "before-holdings" and kind == "userFillsByTime":
            raise original
        if stage == "partial-holdings" and kind == "frontendOpenOrders":
            raise original
        if stage == "complete-holdings" and kind == "orderStatus" and reads.counts.get(kind) == 1:
            raise original
        return reads(payload)

    with pytest.raises(RuntimeError) as caught:
        collect_ownership(read, ACCOUNT, *case[:3], started_ms=1000, observe_failure=seen.append)
    assert caught.value is original
    expected = False if stage == "complete-holdings" else None
    assert seen[0]["positions_empty"] is expected and seen[0]["orders_empty"] is expected
    frames = seen[0]["source_frames"]
    assert type(frames) is list
    assert all(set(frame) == {"file", "line"} for frame in frames)


@pytest.mark.parametrize("origin_failure", [False, True])
def test_origin_processing_never_masks_original_or_copies_private_trace_data(
    case: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Any, origin_failure: bool
) -> None:
    import json

    from guard_harness import testnet_collect as module

    namespace: dict[str, Any] = {}
    exec(
        compile(
            "def PRIVATE_HANDLER(payload):\n raise RuntimeError('PRIVATE-KEY-BODY')\n",
            str(tmp_path / "PRIVATE" / "testnet_exits.py"),
            "exec",
        ),
        namespace,
    )
    seen: list[dict[str, object]] = []
    if origin_failure:

        def broken(error: BaseException) -> list[dict[str, object]]:
            raise KeyboardInterrupt("PRIVATE-ORIGIN-ERROR")

        monkeypatch.setattr(module, "failure_origin", broken)
    with pytest.raises(RuntimeError, match="PRIVATE-KEY-BODY"):
        collect_ownership(
            namespace["PRIVATE_HANDLER"],
            ACCOUNT,
            *case[:3],
            started_ms=1000,
            observe_failure=seen.append,
        )
    assert len(seen) == 1 and seen[0]["family"] == "unknown"
    body = json.dumps(seen)
    assert "PRIVATE" not in body and str(tmp_path) not in body
    expected = [] if origin_failure else ["testnet_collect.py"]
    frames = seen[0]["source_frames"]
    assert type(frames) is list
    assert [frame["file"] for frame in frames] == expected


@pytest.mark.parametrize("depth", [12, 129])
def test_origin_excerpt_has_eight_innermost_frames_and_bounded_total_traversal(depth: int) -> None:
    from guard_harness.testnet_collect import OWNED_SOURCES, failure_origin

    namespace: dict[str, Any] = {}
    source = next(path for path, name in OWNED_SOURCES.items() if name == "testnet_exits.py")
    exec(
        compile(
            "def PRIVATE_RECURSOR(depth):\n"
            " if depth: return PRIVATE_RECURSOR(depth-1)\n"
            " raise RuntimeError('PRIVATE-BODY')\n",
            source,
            "exec",
        ),
        namespace,
    )
    try:
        namespace["PRIVATE_RECURSOR"](depth)
    except RuntimeError as error:
        frames = failure_origin(error)
    assert len(frames) == (8 if depth == 12 else 0)
    if frames:
        assert all(frame == {"file": "testnet_exits.py", "line": 2} for frame in frames[:-1])
        assert frames[-1] == {"file": "testnet_exits.py", "line": 3}


@pytest.mark.parametrize(
    "frames",
    [
        [{"file": "PRIVATE.py", "line": 10}],
        [{"file": "testnet_exits.py", "line": True}],
        [{"file": "testnet_exits.py", "line": 0}],
        [{"file": "testnet_exits.py", "line": 2001}],
        [{"file": "/PRIVATE/testnet_exits.py", "line": 10}],
        [{"file": "testnet_exits.py", "line": 10, "function": "PRIVATE"}],
        [{"file": "testnet_exits.py", "line": 10}] * 9,
    ],
    ids=["unknown", "bool", "zero", "high", "path", "extra", "oversized"],
)
def test_writer_revalidates_origin_and_empty_flag_types_without_private_fragments(
    tmp_path: Any, frames: list[dict[str, object]]
) -> None:
    import json

    from guard_harness.testnet_collect import retain_failure

    tmp_path.chmod(0o700)
    retain_failure(
        tmp_path, {"source_frames": frames, "positions_empty": "PRIVATE", "orders_empty": 0}
    )
    path = tmp_path / "collection-failure.json"
    body = path.read_text()
    facts = json.loads(body)
    assert facts["source_frames"] == []
    assert facts["positions_empty"] is facts["orders_empty"] is None
    assert "PRIVATE" not in body and path.stat().st_mode & 0o777 == 0o600


def test_unknown_trace_filename_never_causes_filesystem_resolution(
    case: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    from pathlib import Path

    from guard_harness import testnet_collect as module

    namespace: dict[str, Any] = {}
    exec(
        compile(
            "def reader(payload):\n raise RuntimeError('PRIVATE-BODY')\n",
            str(tmp_path / "unavailable-mount" / "testnet_exits.py"),
            "exec",
        ),
        namespace,
    )
    resolutions = 0
    seen: list[dict[str, object]] = []

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        nonlocal resolutions
        resolutions += 1
        raise OSError("PRIVATE-MOUNT")

    with monkeypatch.context() as patch:
        patch.setattr(Path, "resolve", forbidden)
        with pytest.raises(RuntimeError, match="PRIVATE-BODY"):
            module.collect_ownership(
                namespace["reader"],
                ACCOUNT,
                *case[:3],
                started_ms=1000,
                observe_failure=seen.append,
            )
    assert resolutions == 0 and len(seen) == 1
    frames = seen[0]["source_frames"]
    assert type(frames) is list
    assert [frame["file"] for frame in frames] == ["testnet_collect.py"]
