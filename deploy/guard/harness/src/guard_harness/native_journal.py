"""Native complete-chain audit, without Linux service imports unavailable on Windows."""

import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from guard_harness.journal_diagnostics import error_category, valid_fee_approval
from guard_harness.native_paper import LifecycleError


def require(condition: bool, message: str) -> None:
    if not condition:
        raise LifecycleError(message)


def no_exchange(home: Path) -> int:
    """Every sending path records an action-bearing event before sending.

    Reject emergency recovery, broken journals, all action-bearing events and every
    unknown event. Verify the complete decision hash chain including startup events.
    This is a durable-journal observation, not a claim of packet capture.
    """
    journal = home / "decisions.jsonl"
    require(journal.is_file() and not journal.is_symlink(), "decision journal missing")
    require(journal.stat().st_size <= 8 * 1024 * 1024, "decision journal exceeds audit bound")
    require(not any((home / "emergency").glob("**/*")), "emergency evidence needs human review")
    body = journal.read_bytes().rstrip(b"\x00")
    require(bool(body) and body.endswith(b"\n"), "decision journal incomplete")
    previous = ""
    sequence = 0
    started = 0
    for line in body.splitlines():
        record = json.loads(line)
        require(isinstance(record, dict), "decision record malformed")
        event = record.get("event")
        require(isinstance(event, dict), "decision event malformed")
        require(
            set(record) in ({"prev", "check", "event"}, {"prev", "check", "durable", "event"}),
            "decision record shape differs",
        )
        require(
            type(event.get("seq")) is int and event["seq"] == sequence + 1,
            "decision sequence incomplete",
        )
        require(record.get("prev") == previous, "decision chain differs")
        text = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        check = hashlib.sha3_256((previous + text).encode()).hexdigest()
        require(record.get("check") == check, "decision checksum differs")
        kind = event.get("kind")
        category = (
            kind
            if isinstance(kind, str)
            and kind
            in {
                "started",
                "risk",
                "stopped",
                "fee_approval",
                "decision",
                "sent",
                "intent",
                "done",
                "recovered",
                "flatten",
                "protect",
                "kill",
                "error",
            }
            else "unknown"
        )
        require(
            category != "fee_approval" or valid_fee_approval(event),
            "fee approval journal event differs",
        )
        diagnostic_seq = str(sequence + 1) if sequence < 4096 else "unknown"
        detail = (
            f"; error_category={error_category(event.get('text'))} " if category == "error" else " "
        )
        require(
            category in {"started", "risk", "stopped", "fee_approval"},
            "action-bearing or unknown event; no exchange credit"
            + detail
            + f"(kind={category}, seq={diagnostic_seq})",
        )
        if event["kind"] == "started":
            require(event.get("mode") == "testnet", "journal contains another runtime mode")
            started += 1
        if event["kind"] == "risk":
            require(
                event.get("open_positions") == 0
                and event.get("discrepancies") == 0
                and event.get("journal_error") is None,
                "risk evidence not flat or journal unhealthy",
            )
        previous, sequence = check, event["seq"]
    require(started > 0, "startup audit positive control missing")
    return sequence


def audit(journal: bytes, *, emergency_present: bool) -> str:
    if emergency_present or not 0 < len(journal) <= 8 * 1024 * 1024:
        raise LifecycleError("complete bounded native journal without emergency evidence required")
    # This is decision evidence only. Config, pairing material and wallet credentials
    # never enter this private temporary directory or the artifact tree.
    with TemporaryDirectory(prefix="guard-native-journal-") as directory:
        home = Path(directory)
        path = home / "decisions.jsonl"
        path.write_bytes(journal)
        path.chmod(0o600)
        no_exchange(home)
    return hashlib.sha256(journal.rstrip(b"\x00")).hexdigest()
