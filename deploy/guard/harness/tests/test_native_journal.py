import hashlib
import json
from pathlib import Path

import pytest

from guard_harness.linux_lifecycle import LifecycleError as LinuxError
from guard_harness.linux_testnet_lifecycle import no_exchange
from guard_harness.native_journal import audit
from guard_harness.native_paper import LifecycleError


def journal(kind: str = "risk") -> bytes:
    previous = ""
    lines = []
    for event in (
        dict(seq=1, kind="started", mode="testnet"),
        dict(seq=2, kind=kind, open_positions=0, discrepancies=0, journal_error=None),
    ):
        text = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        check = hashlib.sha3_256((previous + text).encode()).hexdigest()
        lines.append(json.dumps(dict(prev=previous, check=check, event=event)).encode())
        previous = check
    return b"\n".join(lines) + b"\n"


def test_complete_chain_is_measured_and_temporary_evidence_is_private(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from guard_harness import native_journal

    paths: list[Path] = []
    original = no_exchange

    def inspect(home: Path) -> int:
        assert home.stat().st_mode & 0o077 == 0
        path = home / "decisions.jsonl"
        assert path.stat().st_mode & 0o077 == 0
        paths.append(home)
        return original(home)

    monkeypatch.setattr(native_journal, "no_exchange", inspect)
    body = journal()
    assert audit(body, emergency_present=False) == hashlib.sha256(body).hexdigest()
    assert paths and not paths[0].exists()


@pytest.mark.parametrize(
    "kind", ["decision", "intent", "sent", "recovered", "protect", "flatten", "error", "unknown"]
)
def test_any_action_or_uncertain_event_refuses_no_exchange(kind: str) -> None:
    with pytest.raises(LinuxError, match="action-bearing or unknown"):
        audit(journal(kind), emergency_present=False)


@pytest.mark.parametrize(
    "mutation", ["emergency", "checksum", "prefix", "partial", "empty", "oversize"]
)
def test_uncertain_native_journal_never_proves_no_exchange(mutation: str) -> None:
    body = journal()
    if mutation == "checksum":
        body = body.replace(b'"check": "', b'"check": "invalid', 1)
    elif mutation == "prefix":
        body = body.split(b"\n", 1)[1]
    elif mutation == "partial":
        body = body[:-1]
    elif mutation == "empty":
        body = b""
    elif mutation == "oversize":
        body = b"x" * (8 * 1024 * 1024 + 1)
    with pytest.raises((LinuxError, LifecycleError, ValueError)):
        audit(body, emergency_present=mutation == "emergency")
