"""Measure native Testnet no-exchange evidence using the complete released journal chain."""

import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory

from guard_harness.linux_testnet_lifecycle import no_exchange
from guard_harness.native_paper import LifecycleError


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
