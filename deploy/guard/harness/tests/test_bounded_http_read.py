import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from guard_harness import bounded_http_read as boundary
from guard_harness.bounded_http_read import INFO, bounded_read


@pytest.mark.parametrize(
    "url,data",
    [
        ("https://api.hyperliquid.xyz/info", b'{"type":"meta"}'),
        (INFO, b'{"type":"order"}'),
        ("http://localhost:18547/guard/status", None),
        ("http://127.0.0.1:18547/exchange", None),
        ("http://127.0.0.1:18547/guard/events?since=0&token=private", None),
        ("http://127.0.0.1:18547/guard/status", b"{}"),
    ],
)
def test_refuses_wrong_endpoint_method_or_scope_without_child(
    monkeypatch: pytest.MonkeyPatch, url: str, data: bytes | None
) -> None:
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("no child"))
    with pytest.raises(ValueError):
        bounded_read(url, data, timeout=1)


def test_isolated_child_gets_only_bounded_stdin_and_minimal_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOME", "/private/key-home")
    monkeypatch.setenv("GH_TOKEN", "PRIVATE-SENTINEL")
    monkeypatch.setenv("HTTPS_PROXY", "http://private-proxy")

    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        assert argv[1:3] == ["-I", "-S"] and Path(argv[3]).name == "bounded_http_read.py"
        expected_keys = {"PATH", "LANG"} | ({"SystemRoot"} if sys.platform == "win32" else set())
        assert set(kwargs["env"]) == expected_keys
        assert "PRIVATE" not in str(kwargs["env"])
        assert kwargs["timeout"] == 10 and kwargs["stderr"] == subprocess.DEVNULL
        assert kwargs["stdout"] == subprocess.PIPE
        assert json.loads(kwargs["input"]) == {"url": INFO, "data": '{"type":"meta"}'}
        return subprocess.CompletedProcess(argv, 0, b"{}")

    monkeypatch.setattr(subprocess, "run", run)
    assert bounded_read(INFO, b'{"type":"meta"}', timeout=10) == b"{}"


@pytest.mark.parametrize(
    "exitcode,body",
    [(2, b"PRIVATE"), (0, b"x" * 1_048_577)],
    ids=["failed-child", "oversized-child"],
)
def test_failed_or_oversized_child_never_exposes_body(
    monkeypatch: pytest.MonkeyPatch, exitcode: int, body: bytes
) -> None:
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, exitcode, body)
    )
    with pytest.raises(urllib.error.URLError, match="bounded read failed") as caught:
        bounded_read(INFO, b'{"type":"meta"}', timeout=10)
    assert "PRIVATE" not in str(caught.value)


def test_slow_dribble_is_killed_and_reaped_under_whole_response_deadline() -> None:
    # The deadline covers the isolated child's start too. A hosted Windows runner can take
    # longer than 0.3 s just to start Python (public CI run 38715930937), so it gets a
    # longer deadline and kill margin. Both stay far below the 12 s dribble, so finishing
    # in time still proves the read was cut off at the deadline, not by the response's end.
    deadline, slack = (3.0, 2.0) if sys.platform == "win32" else (0.3, 0.7)
    dribble = 600
    assert deadline + slack < dribble * 0.02 / 2
    closed = threading.Event()
    connected = threading.Event()

    class Slow(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            connected.set()
            self.send_response(200)
            self.end_headers()
            try:
                for _ in range(dribble):
                    self.wfile.write(b" ")
                    self.wfile.flush()
                    time.sleep(0.02)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                closed.set()

        def log_message(self, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Slow)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        began = time.monotonic()
        with pytest.raises(urllib.error.URLError, match="bounded read failed"):
            bounded_read(
                f"http://127.0.0.1:{server.server_port}/guard/status", None, timeout=deadline
            )
        assert time.monotonic() - began < deadline + slack
        assert connected.is_set()
        assert closed.wait(slack)  # Reaped worker closed the response before any next request.
    finally:
        server.shutdown()
        server.server_close()
        worker.join(1)


@pytest.mark.parametrize(
    "body",
    [
        b'{"type":"meta"}',
        b'{"type":"userRole","user":"0x' + b"a" * 40 + b'"}',
    ],
)
def test_exact_local_warm_reads_use_five_second_isolated_boundary(
    monkeypatch: pytest.MonkeyPatch, body: bytes
) -> None:
    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        assert kwargs["close_fds"] is True and kwargs["timeout"] == 5
        expected_keys = {"PATH", "LANG"} | ({"SystemRoot"} if sys.platform == "win32" else set())
        assert set(kwargs["env"]) == expected_keys
        assert json.loads(kwargs["input"]) == {
            "url": "http://127.0.0.1:18547/info",
            "data": body.decode(),
        }
        return subprocess.CompletedProcess(argv, 0, b"{}")

    monkeypatch.setattr(subprocess, "run", run)
    assert bounded_read("http://127.0.0.1:18547/info", body, timeout=5) == b"{}"
    with pytest.raises(ValueError):
        bounded_read("http://127.0.0.1:18547/info", body, timeout=5.001)


@pytest.mark.parametrize(
    "url,body",
    [
        ("http://127.0.0.1:18547/info", b'{"type":"order","type":"meta"}'),
        ("http://127.0.0.1:18547/info", b'{"type":"meta","extra":"PRIVATE"}'),
        ("http://127.0.0.1:18547/info", b'{"type":"userRole"}'),
        ("http://127.0.0.1:18547/info", b'{"type":"userRole","user":"0x' + b"A" * 40 + b'"}'),
        (
            "http://127.0.0.1:18547/info",
            b'{"type":"userRole","user":"0x' + b"a" * 40 + b'","user":"0x' + b"b" * 40 + b'"}',
        ),
        ("http://127.0.0.1:18547/info", b'{"type":"allMids"}'),
        ("http://127.0.0.1:18547/exchange", b'{"type":"meta"}'),
        ("http://127.0.0.1:18547/info?private=x", b'{"type":"meta"}'),
        ("http://localhost:18547/info", b'{"type":"meta"}'),
        ("http://127.0.0.1:18547/info", None),
    ],
)
def test_local_warm_boundary_refuses_extra_duplicate_or_mutation_bodies_without_child(
    monkeypatch: pytest.MonkeyPatch, url: str, body: bytes | None
) -> None:
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("no child"))
    with pytest.raises(ValueError):
        bounded_read(url, body, timeout=1)


def test_slow_local_warm_post_is_killed_and_reaped() -> None:
    closed = threading.Event()
    connected = threading.Event()

    class Slow(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            connected.set()
            assert self.path == "/info"
            assert json.loads(self.rfile.read(int(self.headers["Content-Length"]))) == {
                "type": "meta"
            }
            self.send_response(200)
            self.end_headers()
            try:
                for _ in range(300):
                    self.wfile.write(b" ")
                    self.wfile.flush()
                    time.sleep(0.02)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                closed.set()

        def log_message(self, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Slow)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        began = time.monotonic()
        with pytest.raises(urllib.error.URLError, match="bounded read failed"):
            bounded_read(
                f"http://127.0.0.1:{server.server_port}/info", b'{"type":"meta"}', timeout=0.3
            )
        assert time.monotonic() - began < 1 and connected.is_set() and closed.wait(1)
    finally:
        server.shutdown()
        server.server_close()
        worker.join(1)


def test_windows_child_receives_only_valid_os_root_without_parent_custody(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("SystemRoot", "C:\\Windows")
    monkeypatch.setenv("PATH", "C:\\private-key-directory")
    for name in [
        "GH_TOKEN",
        "API_WALLET_KEY",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "PYTHONPATH",
        "HOME",
        "USERPROFILE",
        "SSL_CERT_FILE",
    ]:
        monkeypatch.setenv(name, "PRIVATE-CUSTODY-SENTINEL")
    monkeypatch.setattr(os.path, "isdir", lambda path: path == "C:\\Windows")

    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        assert kwargs["env"] == {
            "PATH": os.defpath,
            "LANG": "C.UTF-8",
            "SystemRoot": "C:\\Windows",
        }
        assert argv[0] == sys.executable and argv[1:3] == ["-I", "-S"]
        assert kwargs["close_fds"] is True and kwargs["timeout"] == 10
        assert "PRIVATE" not in str(kwargs["env"]) and "private-key" not in str(kwargs["env"])
        return subprocess.CompletedProcess(argv, 0, b"{}")

    monkeypatch.setattr(subprocess, "run", run)
    assert (
        bounded_read(INFO, b'{"type":"userAbstraction","user":"0x' + b"a" * 40 + b'"}', timeout=10)
        == b"{}"
    )


@pytest.mark.parametrize(
    "root",
    [
        None,
        "",
        "Windows",
        "\\\\server\\Windows",
        "C:Windows",
        "C:\\Windows:PRIVATE",
        "C:\\Windows\\..\\private",
        "C:\\Windows%SECRET%",
        "C:\\Windows\nPRIVATE",
        "C:\\Windows\x00PRIVATE",
        "C:\\" + "a" * 260,
        "C:\\Nonexistent",
    ],
)
def test_windows_invalid_os_bootstrap_refuses_without_child(
    monkeypatch: pytest.MonkeyPatch, root: str | None
) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    if root is None:
        monkeypatch.delenv("SystemRoot", raising=False)
    else:
        # A NUL cannot be set in the real OS environment; represent the same
        # invalid bootstrap mapping in memory without passing it to a process.
        monkeypatch.setattr(os, "environ", {"SystemRoot": root})
    monkeypatch.setattr(os.path, "isdir", lambda path: path == "C:\\Windows")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("no child"))
    with pytest.raises(ValueError, match="read refused") as caught:
        bounded_read(INFO, b'{"type":"meta"}', timeout=10)
    assert "PRIVATE" not in str(caught.value)


def test_non_windows_child_does_not_forward_os_or_custody_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("SystemRoot", "PRIVATE-CUSTODY-SENTINEL")
    monkeypatch.setenv("HTTPS_PROXY", "PRIVATE-CUSTODY-SENTINEL")
    assert boundary._child_environment() == {"PATH": os.defpath, "LANG": "C.UTF-8"}


@pytest.mark.parametrize("post", [False, True])
def test_real_isolated_worker_completes_successful_loopback_json_read(post: bool) -> None:
    connected = threading.Event()
    expected = b'{"bootstrap":"ok"}'

    class Ready(BaseHTTPRequestHandler):
        def answer(self) -> None:
            connected.set()
            self.send_response(200)
            self.send_header("Content-Length", str(len(expected)))
            self.end_headers()
            self.wfile.write(expected)

        def do_GET(self) -> None:
            assert self.path == "/guard/status"
            self.answer()

        def do_POST(self) -> None:
            assert self.path == "/info"
            assert self.rfile.read(int(self.headers["Content-Length"])) == b'{"type":"meta"}'
            self.answer()

        def log_message(self, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Ready)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        path, body = ("/info", b'{"type":"meta"}') if post else ("/guard/status", None)
        result = bounded_read(f"http://127.0.0.1:{server.server_port}{path}", body, timeout=5)
        assert connected.is_set() and result == expected
    finally:
        server.shutdown()
        server.server_close()
        thread.join(1)
