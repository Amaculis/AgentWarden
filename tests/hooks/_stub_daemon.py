"""Configurable stub HTTP daemon for hook subprocess tests (spec 005).

A real `http.server.ThreadingHTTPServer` bound to 127.0.0.1 on an OS-assigned
port, running in a background thread. This is what makes it possible to test
`hooks/on_tool.py`'s real network code path (urllib, threading, wall-clock
deadline, encoding) end to end, without ever touching a developer's real
daemon on 8765.

Not a test module itself (no `test_` prefix) -- pytest will not collect it.

Binding a loopback port must FAIL (raise), not skip, if it cannot be done:
this project's tests are expected to run with normal loopback access. Do not
wrap the bind in a try/except that turns it into a skip.
"""

from __future__ import annotations

import contextlib
import threading
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest


class RecordedRequest:
    __slots__ = ("method", "path", "body", "headers")

    def __init__(self, method: str, path: str, body: bytes, headers) -> None:
        self.method = method
        self.path = path
        self.body = body
        self.headers = headers


class StubDaemon:
    """A tiny HTTP server a test can point `WARDEN_URL` at.

    Configure the next response via the plain attributes below, then let the
    hook subprocess talk to `self.url`. `last_request` records the most
    recent request this server received (`None` if it never received one).
    """

    def __init__(self) -> None:
        self.status: int = 200
        self.body: bytes = b"{}"
        self.delay_s: float = 0.0
        # (chunk_size, interval_s, total_duration_s) or None.
        self.slow_drip: tuple[int, float, float] | None = None
        self.last_request: RecordedRequest | None = None
        self.request_count: int = 0
        self._lock = threading.Lock()

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._make_handler())
        self.port: int = self._server.server_address[1]
        self.url: str = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def _make_handler(self) -> Callable[..., BaseHTTPRequestHandler]:
        stub = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt, *args) -> None:  # noqa: A002
                pass  # keep test output quiet

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", 0) or 0)
                body = self.rfile.read(length) if length else b""
                with stub._lock:
                    stub.last_request = RecordedRequest(
                        self.command, self.path, body, dict(self.headers)
                    )
                    stub.request_count += 1
                    delay_s = stub.delay_s
                    slow_drip = stub.slow_drip
                    status = stub.status
                    resp_body = stub.body

                if delay_s:
                    time.sleep(delay_s)

                if slow_drip is not None:
                    self._write_slow_drip(status, resp_body, slow_drip)
                    return

                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp_body)))
                self.end_headers()
                with contextlib.suppress(Exception):
                    self.wfile.write(resp_body)

            def _write_slow_drip(
                self, status: int, resp_body: bytes, slow_drip: tuple[int, float, float]
            ) -> None:
                chunk, interval_s, total_duration_s = slow_drip
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp_body)))
                self.end_headers()
                try:
                    self.wfile.flush()
                except Exception:
                    return
                deadline = time.monotonic() + total_duration_s
                sent = 0
                while sent < len(resp_body) and time.monotonic() < deadline:
                    piece = resp_body[sent : sent + chunk]
                    try:
                        self.wfile.write(piece)
                        self.wfile.flush()
                    except Exception:
                        return
                    sent += len(piece)
                    time.sleep(interval_s)

            # do_GET is unused by the hook, but keep the server well-behaved.
            def do_GET(self) -> None:  # noqa: N802
                self.send_response(404)
                self.end_headers()

        return Handler

    def shutdown(self) -> None:
        self._server.shutdown()
        self._server.server_close()


@pytest.fixture
def stub_daemon():
    """A running StubDaemon; shut down automatically at the end of the test."""
    daemon = StubDaemon()
    try:
        yield daemon
    finally:
        daemon.shutdown()


@pytest.fixture
def second_stub_daemon():
    """A second, independent StubDaemon (e.g. to stand in for a proxy)."""
    daemon = StubDaemon()
    try:
        yield daemon
    finally:
        daemon.shutdown()
