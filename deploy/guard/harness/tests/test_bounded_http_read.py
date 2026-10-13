import json
import subprocess
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

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
        assert argv[1:3] == ["-I", "-S"] and argv[3].endswith("/bounded_http_read.py")
        assert set(kwargs["env"]) == {"PATH", "LANG"}
        assert "PRIVATE" not in str(kwargs["env"])
        assert kwargs["timeout"] == 10 and kwargs["stderr"] == subprocess.DEVNULL
        assert kwargs["stdout"] == subprocess.PIPE
        assert json.loads(kwargs["input"]) == {"url": INFO, "data": '{"type":"meta"}'}
        return subprocess.CompletedProcess(argv, 0, b"{}")

    monkeypatch.setattr(subprocess, "run", run)
    assert bounded_read(INFO, b'{"type":"meta"}', timeout=10) == b"{}"


@pytest.mark.parametrize("exitcode,body", [(2, b"PRIVATE"), (0, b"x" * 1_048_577)])
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
    closed = threading.Event()

    class Slow(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.end_headers()
            try:
                for _ in range(300):
                    self.wfile.write(b" ")
                    self.wfile.flush()
                    time.sleep(0.02)
            except (BrokenPipeError, ConnectionResetError):
                closed.set()

        def log_message(self, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Slow)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        began = time.monotonic()
        with pytest.raises(urllib.error.URLError, match="bounded read failed"):
            bounded_read(f"http://127.0.0.1:{server.server_port}/guard/status", None, timeout=0.3)
        assert time.monotonic() - began < 1
        assert closed.wait(1)  # Reaped worker closed the response before any next request.
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
        assert set(kwargs["env"]) == {"PATH", "LANG"}
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

    class Slow(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
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
            except (BrokenPipeError, ConnectionResetError):
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
        assert time.monotonic() - began < 1 and closed.wait(1)
    finally:
        server.shutdown()
        server.server_close()
        worker.join(1)
