"""OpenAICompatProvider against a real HTTP server on loopback (no external network).

The MockTransport tests cover parsing; these cover the real httpx transport: request shape,
Authorization header, total deadline on a slow-drip server, and no redirect following.
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from agentwarden.providers.openai_compat import OpenAICompatProvider

VERDICT = {"decision": "allow", "risk": 5, "confidence": 0.9, "reason": "fine"}


class _Server:
    def __init__(self) -> None:
        self.mode = "ok"
        self.requests: list[dict] = []
        server = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args) -> None:
                pass

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length))
                server.requests.append(
                    {"path": self.path, "auth": self.headers.get("Authorization"), "body": body}
                )
                if server.mode == "redirect":
                    self.send_response(307)
                    self.send_header("Location", "http://example.invalid/steal")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                payload = json.dumps(
                    {
                        "choices": [
                            {"message": {"role": "assistant", "content": json.dumps(VERDICT)}}
                        ],
                        "usage": {"prompt_tokens": 120, "completion_tokens": 30},
                    }
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                if server.mode == "drip":
                    for byte in payload:
                        try:
                            self.wfile.write(bytes([byte]))
                            self.wfile.flush()
                        except OSError:
                            return
                        time.sleep(0.05)
                else:
                    self.wfile.write(payload)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}/v1"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def server():
    s = _Server()
    yield s
    s.close()


def _complete(provider: OpenAICompatProvider, timeout: float = 5.0):
    return provider.complete([{"role": "user", "content": "hi"}], timeout=timeout, max_tokens=50)


def test_real_http_round_trip(server):
    result = _complete(OpenAICompatProvider(server.base, "secret-key", "muse-spark-test"))
    assert result.error is None
    assert json.loads(result.text) == VERDICT
    assert (result.tokens_in, result.tokens_out) == (120, 30)
    [request] = server.requests
    assert request["path"] == "/v1/chat/completions"
    assert request["auth"] == "Bearer secret-key"
    assert request["body"]["model"] == "muse-spark-test"
    assert request["body"]["temperature"] == 0
    assert request["body"]["max_tokens"] == 50


def test_slow_drip_hits_total_deadline(server):
    server.mode = "drip"  # ~200 bytes at 50 ms each = ~10 s; per-read timeouts never fire
    start = time.monotonic()
    result = _complete(OpenAICompatProvider(server.base, "k", "m"), timeout=1.0)
    assert result.error == "timeout"
    assert time.monotonic() - start < 3.0


def test_redirect_not_followed(server):
    server.mode = "redirect"
    result = _complete(OpenAICompatProvider(server.base, "k", "m"))
    assert result.error == "http"
    assert len(server.requests) == 1


def test_closed_port_is_connection_error():
    result = _complete(OpenAICompatProvider("http://127.0.0.1:1/v1", "k", "m"), timeout=2.0)
    assert result.error in ("connection", "timeout")
