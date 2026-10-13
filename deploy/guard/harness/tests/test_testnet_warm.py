import pytest

from guard_harness.testnet_protection import ProtectionError
from guard_harness.testnet_warm import warm

CLIENT = "0x" + "1" * 40


class Clock:
    def __init__(self) -> None:
        self.now = 100.0
        self.waits: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.waits.append(seconds)
        self.now += seconds


class Reads:
    def __init__(self, clock: Clock, *, rate: str = "0.639", burst: int = 60) -> None:
        self.clock = clock
        self.status: object = {
            "ip_share": "0.4",
            "budgets": {"info": {"per_second": rate, "burst": burst}},
        }
        self.meta: object = {"universe": [{"name": "BTC"}]}
        self.role: object = {"role": "missing"}
        self.calls: list[tuple[str, object, float, float]] = []
        self.delays = {"meta": 0.0, "userRole": 0.0}

    def __call__(self, path: str, body: dict[str, object] | None, timeout: float) -> object:
        self.calls.append((path, body, timeout, self.clock.now))
        assert 0 < timeout <= 5
        if path == "/guard/status":
            assert body is None
            return self.status
        assert path == "/info" and body is not None
        if body == {"type": "meta"}:
            self.clock.now += self.delays["meta"]
            return self.meta
        assert body == {"type": "userRole", "user": CLIENT}
        self.clock.now += self.delays["userRole"]
        return self.role


@pytest.mark.parametrize(
    "rate,burst,waits",
    [
        ("0.639", 60, [31.299, 12.520]),
        ("0.856", 68, [14.019, 9.346]),
        ("2", 160, []),
    ],
)
def test_cold_bucket_ceil_deficits_generalize_without_changing_budgets(
    rate: str, burst: int, waits: list[float]
) -> None:
    clock = Clock()
    read = Reads(clock, rate=rate, burst=burst)
    result = warm(read, CLIENT, deadline=1000, clock=clock, sleep=clock.sleep)
    # Cold .4 burst60 cannot fit meta20 then role60:40<60. Warm pays it separately,
    # ceil(20e6/639)=31,299ms then ceil(8e6/639)=12,520ms for four light reads.
    assert clock.waits == waits
    assert [call[1] for call in read.calls] == [
        None,
        {"type": "meta"},
        {"type": "userRole", "user": CLIENT},
    ]
    assert result.meta_started == 100000
    result.check()


def test_delayed_http_completion_never_credits_unknown_server_io_interval() -> None:
    clock = Clock()
    read = Reads(clock)
    read.delays.update(meta=2.0, userRole=3.0)
    result = warm(read, CLIENT, deadline=1000, clock=clock, sleep=clock.sleep)
    assert clock.waits == [31.299, 12.520]
    assert read.calls[2][3] == pytest.approx(133.299)  # Role wait starts after meta completion102.
    assert result.meta_started == 100000 and result.role_started == 133299
    assert clock.now == pytest.approx(148.819)
    result.check()


@pytest.mark.parametrize(
    "status",
    [
        None,
        [],
        {"ip_share": "1"},
        {"ip_share": 0.4},
        {"ip_share": "0.40"},
        {"ip_share": "0.4", "budgets": None},
        {"ip_share": "0.4", "budgets": {"info": {"per_second": 0.639, "burst": 60}}},
        {"ip_share": "0.4", "budgets": {"info": {"per_second": "NaN", "burst": 60}}},
        {"ip_share": "0.4", "budgets": {"info": {"per_second": "0", "burst": 60}}},
        {"ip_share": "0.4", "budgets": {"info": {"per_second": "0.6391", "burst": 60}}},
        {"ip_share": "0.4", "budgets": {"info": {"per_second": "2.001", "burst": 60}}},
        {"ip_share": "0.4", "budgets": {"info": {"per_second": "0.639", "burst": True}}},
        {"ip_share": "0.4", "budgets": {"info": {"per_second": "0.639", "burst": 59}}},
        {"ip_share": "0.4", "budgets": {"info": {"per_second": "0.639", "burst": 161}}},
    ],
)
def test_malformed_budget_or_shared_ip_refuses_before_any_passthrough(status: object) -> None:
    clock = Clock()
    read = Reads(clock)
    read.status = status
    with pytest.raises(ProtectionError, match="owned Guard info warm prerequisite refused"):
        warm(read, CLIENT, deadline=1000, clock=clock, sleep=clock.sleep)
    assert len(read.calls) == 1 and not clock.waits


@pytest.mark.parametrize(
    "role",
    [None, [], {}, {"role": "agent"}, {"role": "user"}, {"role": "vault"}, {"role": "PRIVATE-KEY"}],
)
def test_unknown_or_registered_client_role_never_retries(role: object) -> None:
    clock = Clock()
    read = Reads(clock)
    read.role = role
    with pytest.raises(ProtectionError) as caught:
        warm(read, CLIENT, deadline=1000, clock=clock, sleep=clock.sleep)
    assert "PRIVATE" not in str(caught.value)
    assert len(read.calls) == 3 and clock.waits == [31.299]


@pytest.mark.parametrize("deadline,rate", [(110.0, "0.639"), (1000.0, "0.1")])
def test_job_deadline_or_ttl_refuses_required_wait_before_role(deadline: float, rate: str) -> None:
    clock = Clock()
    read = Reads(clock, rate=rate)
    with pytest.raises(ProtectionError):
        warm(read, CLIENT, deadline=deadline, clock=clock, sleep=clock.sleep)
    assert len(read.calls) == 2 and not clock.waits


@pytest.mark.parametrize("offset", [-0.001, -60.0])
def test_undersleep_or_backwards_clock_refuses_without_role(offset: float) -> None:
    clock = Clock()
    read = Reads(clock)

    def sleep(seconds: float) -> None:
        clock.now += seconds + offset

    with pytest.raises(ProtectionError):
        warm(read, CLIENT, deadline=1000, clock=clock, sleep=sleep)
    assert len(read.calls) == 2


@pytest.mark.parametrize("during", ["meta", "userRole"])
def test_whole_read_deadline_cannot_be_spent_before_next_warm_read(during: str) -> None:
    clock = Clock()
    read = Reads(clock)
    read.delays[during] = 5.001
    with pytest.raises(ProtectionError):
        warm(read, CLIENT, deadline=1000, clock=clock, sleep=clock.sleep)
    assert len(read.calls) == (2 if during == "meta" else 3)


def test_post_warm_clock_reversal_or_ttl_expiry_is_not_a_performance_readiness_permit() -> None:
    clock = Clock()
    read = Reads(clock)
    result = warm(read, CLIENT, deadline=1000, clock=clock, sleep=clock.sleep)
    clock.now -= 0.001
    with pytest.raises(ProtectionError):
        result.check()
    clock.now = 159.0
    with pytest.raises(ProtectionError):
        result.check()  # Exactly1s margin left already refuses.
