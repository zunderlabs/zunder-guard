"""Linux-only owned process crash injection; pidfd prevents numeric PID reuse."""

import os
import re
import signal
import sys
from collections.abc import Callable
from pathlib import Path
from typing import cast


def crash(pid: int, identity: str) -> None:
    if pid <= 1 or not re.fullmatch(r"[0-9a-f]{64}", identity):
        raise ValueError("invalid process/container identity")
    open_name, signal_name = "pidfd_open", "pidfd_send_signal"
    open_pidfd = cast(Callable[[int], int], getattr(os, open_name))
    send_signal = cast(Callable[[int, int], None], getattr(signal, signal_name))
    fd = open_pidfd(pid)
    try:
        root = Path("/proc") / str(pid)
        if root.joinpath("comm").read_text().strip() != "zunder-guard":
            raise ValueError("process is not Guard")
        cgroups = root.joinpath("cgroup").read_text().splitlines()
        if not any(
            re.search(r"(?:/docker/|/docker-?)" + identity + r"(?:\.scope)?$", line)
            for line in cgroups
        ):
            raise ValueError("process does not belong to owned container")
        send_signal(fd, signal.SIGKILL)
    finally:
        os.close(fd)


if __name__ == "__main__":
    crash(int(sys.argv[1]), sys.argv[2])
