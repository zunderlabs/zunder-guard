#!/usr/bin/env python3
"""Loopback HTTP fixture for the Windows download-loop test (windows-download.ps1).

Serves GET /<mode>/<name> on 127.0.0.1 only. The body is <name> repeated to the size:
  ok        4096 bytes at once
  throttle  26 KiB, 1 KiB per second (26 s: longer than the 20 s header timeout)
  stall     the headers and 64 of 4096 bytes, then nothing for 45 s, then the connection ends
  cut       first request per path: 1000 of 4096 bytes, then the connection is closed; then ok
  reset     first request per path: 1000 of 4096 bytes, then a TCP reset; then ok
  missing   404
Every request's path is appended to LOG. The port is written to PORTFILE once listening.

  python download-fixture-server.py PORTFILE LOG
"""

import http.server
import os
import socket
import struct
import sys
import threading
import time

SIZES = {"throttle": 26 * 1024}
SIZE = 4096
COUNTS: dict[str, int] = {}
LOCK = threading.Lock()


def body(name: str, size: int) -> bytes:
    seed = name.encode()
    return (seed * (size // len(seed) + 1))[:size]


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    log_path = ""

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 (stdlib name)
        pass

    def do_GET(self) -> None:  # noqa: N802 (stdlib name)
        parts = self.path.strip("/").split("/")
        if len(parts) != 2 or not parts[1]:
            self.send_error(400)
            return
        mode, name = parts
        with LOCK:
            count = COUNTS[self.path] = COUNTS.get(self.path, 0) + 1
            with open(self.log_path, "a", encoding="utf-8") as log:
                log.write(self.path + "\n")
        if mode == "missing":
            self.send_error(404)
            return
        if mode not in {"ok", "throttle", "stall", "cut", "reset"}:
            self.send_error(400)
            return
        size = SIZES.get(mode, SIZE)
        data = body(name, size)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(size))
        self.end_headers()
        try:
            if mode == "throttle":
                for offset in range(0, size, 1024):
                    self.wfile.write(data[offset : offset + 1024])
                    time.sleep(1)
            elif mode == "stall":
                self.wfile.write(data[:64])
                time.sleep(45)
            elif mode in {"cut", "reset"} and count == 1:
                self.wfile.write(data[:1000])
                if mode == "reset":
                    # Linger on, zero seconds: close sends RST instead of FIN.
                    linger = struct.pack("HH" if os.name == "nt" else "ii", 1, 0)
                    self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
                    self.connection.close()
            else:
                self.wfile.write(data)
        except OSError:
            pass  # the client gave up (a timeout under test); nothing to report


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: download-fixture-server.py PORTFILE LOG")
    Handler.log_path = sys.argv[2]
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    pending = sys.argv[1] + ".pending"
    with open(pending, "w", encoding="utf-8") as port:
        port.write(str(server.server_address[1]))
    os.replace(pending, sys.argv[1])
    server.serve_forever()


if __name__ == "__main__":
    main()
