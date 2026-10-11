"""Exercise the actual stdlib HTTP boundary, without a venue or signing key."""

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from guard_harness.paper_bot import LocalGuard, PaperError


@pytest.fixture
def server() -> Iterator[tuple[str, list[dict[str, Any]]]]:
    requests: list[dict[str, Any]] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            pass

        def do_POST(self) -> None:
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append(body)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"verdict":"veto"}')

        def do_GET(self) -> None:
            if self.path == "/redirect":
                self.send_response(307)
                self.send_header("Location", "/must-not-be-read")
                self.end_headers()
                return
            requests.append({"path": self.path})
            self.send_response(200)
            self.end_headers()
            if self.path == "/oversize":
                self.wfile.write(b" " * 1_048_577)
            elif self.path == "/malformed":
                self.wfile.write(b"not JSON")
            else:
                self.wfile.write(b'{"mode":"paper"}')

    http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{http.server_port}", requests
    finally:
        http.shutdown()
        http.server_close()
        thread.join(timeout=5)


def test_http_preserves_strict_paper_envelope(server: tuple[str, list[dict[str, Any]]]) -> None:
    url, requests = server
    body = {"expectedMode": "paper", "action": {"type": "order"}, "nonce": 123}
    assert LocalGuard(url).request("/exchange", body) == {"verdict": "veto"}
    assert requests == [body]


def test_http_never_follows_redirect(server: tuple[str, list[dict[str, Any]]]) -> None:
    url, requests = server
    with pytest.raises(PaperError, match="redirected"):
        LocalGuard(url).request("/redirect")
    assert requests == []


@pytest.mark.parametrize("path", ["/oversize", "/malformed"])
def test_http_refuses_unbounded_or_invalid_response(
    server: tuple[str, list[dict[str, Any]]], path: str
) -> None:
    with pytest.raises(PaperError):
        LocalGuard(server[0]).request(path)


def test_does_not_use_ambient_proxy(
    server: tuple[str, list[dict[str, Any]]], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("no_proxy", "")
    monkeypatch.setenv("NO_PROXY", "")
    assert LocalGuard(server[0]).request("/guard/status") == {"mode": "paper"}
