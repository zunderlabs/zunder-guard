import os
import signal
from pathlib import Path

import pytest

from guard_harness import crash_process


@pytest.mark.parametrize("change", ["none", "foreign", "missing", "exited"])
def test_crash_is_bound_to_open_pidfd(monkeypatch: pytest.MonkeyPatch, change: str) -> None:
    calls: list[object] = []
    monkeypatch.setattr(os, "pidfd_open", lambda pid: 42, raising=False)
    monkeypatch.setattr(os, "close", lambda fd: calls.append(("close", fd)))

    def read(path: Path) -> str:
        if change == "missing":
            raise FileNotFoundError
        return (
            "zunder-guard\n"
            if path.name == "comm"
            else "0::/system.slice/docker-"
            + ("b" if change == "foreign" else "a") * 64
            + ".scope\n"
        )

    def send(fd: int, sig: signal.Signals) -> None:
        assert (fd, sig) == (42, signal.SIGKILL)
        if change == "exited":
            raise ProcessLookupError
        calls.append("signal")

    monkeypatch.setattr(Path, "read_text", read)
    monkeypatch.setattr(signal, "pidfd_send_signal", send, raising=False)
    if change == "none":
        crash_process.crash(12002, "a" * 64)
        assert calls == ["signal", ("close", 42)]
    else:
        with pytest.raises((ValueError, FileNotFoundError, ProcessLookupError)):
            crash_process.crash(12002, "a" * 64)
        assert calls == [("close", 42)]
