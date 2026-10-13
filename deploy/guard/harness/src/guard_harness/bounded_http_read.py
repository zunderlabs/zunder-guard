"""Isolated stdlib-only HTTP read worker with a whole-response process deadline.

Launched as an absolute file with -I -S: it imports no harness/SDK or credentials.
subprocess.run kills and waits for its direct child on timeout before returning.
"""

import errno
import io
import ipaddress
import json
import ntpath
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

LIMIT = 1_048_576
INFO = "https://api.hyperliquid-testnet.xyz/info"


def _unique_local(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("read refused")
        value[key] = item
    return value


def _admit(url: str, data: bytes | None) -> float:
    if url == INFO and data is not None:
        value = json.loads(data)
        if not isinstance(value, dict) or value.get("type") not in {
            "userAbstraction",
            "perpDexs",
            "meta",
            "allMids",
            "orderStatus",
            "userFillsByTime",
            "clearinghouseState",
            "frontendOpenOrders",
        }:
            raise ValueError("read refused")
        return 10
    parsed = urlsplit(url)
    if (
        parsed.scheme != "http"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or not ipaddress.ip_address(parsed.hostname or "").is_loopback
        or parsed.port is None
        or not 1024 <= parsed.port <= 65535
    ):
        raise ValueError("read refused")
    if data is not None:
        value = json.loads(data, object_pairs_hook=_unique_local)
        if (
            parsed.path != "/info"
            or parsed.query
            or not (
                value == {"type": "meta"}
                or type(value) is dict
                and set(value) == {"type", "user"}
                and value["type"] == "userRole"
                and type(value["user"]) is str
                and re.fullmatch(r"0x[0-9a-f]{40}", value["user"]) is not None
            )
        ):
            raise ValueError("read refused")
    elif not (
        parsed.path in {"/guard/status", "/healthz"}
        and not parsed.query
        or parsed.path == "/guard/events"
        and re.fullmatch(r"since=[0-9]{1,20}", parsed.query)
    ):
        raise ValueError("read refused")
    return 5


def _child_environment() -> dict[str, str]:
    env = {"PATH": os.defpath, "LANG": "C.UTF-8"}
    if sys.platform == "win32":
        # Python's subprocess Windows contract requires a valid SystemRoot for
        # OS assemblies. Carry only this OS bootstrap path, never caller PATH,
        # credentials, proxies, certificate overrides or Python import settings.
        root = os.environ.get("SystemRoot", "")
        drive, _ = ntpath.splitdrive(root)
        if (
            not 3 < len(root) <= 260
            or re.fullmatch(r"[A-Za-z]:", drive) is None
            or not ntpath.isabs(root)
            or ":" in root[2:]
            or ntpath.normpath(root) != root
            or any(ord(char) < 32 or ord(char) == 127 or char in '%<>|"*?' for char in root)
            or not os.path.isdir(root)
        ):
            raise ValueError("read refused")
        env["SystemRoot"] = root
    return env


def bounded_read(url: str, data: bytes | None, *, timeout: float) -> bytes:
    maximum = _admit(url, data)
    if not 0 < timeout <= maximum or data is not None and len(data) > 65_536:
        raise ValueError("read refused")
    encoded = json.dumps({"url": url, "data": None if data is None else data.decode()}).encode()
    try:
        result = subprocess.run(
            [sys.executable, "-I", "-S", str(Path(__file__).resolve()), str(timeout)],
            input=encoded,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            env=_child_environment(),
            close_fds=True,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        raise urllib.error.URLError("bounded read failed") from None
    if result.returncode == 3:
        raise urllib.error.URLError(ConnectionRefusedError(errno.ECONNREFUSED, "read refused"))
    if result.returncode != 0 or len(result.stdout) > LIMIT:
        raise urllib.error.URLError("bounded read failed")
    return result.stdout


class ReadOpener:
    """An opener-shaped boundary; injectable fixtures cannot weaken the production worker."""

    def open(self, request: urllib.request.Request, *, timeout: float) -> io.BytesIO:
        data = request.data
        if data is not None and not isinstance(data, bytes):
            raise ValueError("read refused")
        return io.BytesIO(bounded_read(request.full_url, data, timeout=timeout))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        raise ValueError("redirect refused")


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(65_537)
        if len(raw) > 65_536:
            return 2
        value = json.loads(raw)
        if not isinstance(value, dict) or set(value) != {"url", "data"}:
            return 2
        if not isinstance(value["url"], str) or not (
            value["data"] is None or isinstance(value["data"], str)
        ):
            return 2
        data = None if value["data"] is None else value["data"].encode()
        timeout = float(sys.argv[1])
        maximum = _admit(value["url"], data)
        if not 0 < timeout <= maximum:
            return 2
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
        request = urllib.request.Request(
            value["url"], data=data, headers={"Content-Type": "application/json"}
        )
        with opener.open(request, timeout=timeout) as response:
            captured = response.read(LIMIT + 1)
        if len(captured) > LIMIT:
            return 2
        sys.stdout.buffer.write(captured)
        return 0
    except urllib.error.URLError as error:
        if isinstance(error.reason, OSError) and error.reason.errno == errno.ECONNREFUSED:
            return 3
        return 2
    except (Exception, KeyboardInterrupt):
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
