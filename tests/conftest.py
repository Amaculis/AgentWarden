"""Suite-wide isolation (invariant 5): tests never reach a real model.

A developer may have `WARDEN_JUDGE` / `META_API_KEY` exported for `make run` or `make eval`;
without this fixture `decide()` would build a real provider during `make test`.
"""

from __future__ import annotations

import httpx
import pytest

_MODEL_ENV = (
    "WARDEN_JUDGE",
    "WARDEN_JUDGE_PROMPT",
    "WARDEN_CASCADE",
    "META_API_KEY",
    "META_API_BASE",
    "WARDEN_MODEL",
    "WARDEN_LOCAL_BASE",
    "WARDEN_LOCAL_KEY",
    "WARDEN_LOCAL_MODEL",
    "WARDEN_SCANNER",
    "WARDEN_SCANNER_PROMPT",
)


@pytest.fixture(autouse=True)
def _no_real_model(request, monkeypatch, tmp_path):
    for name in _MODEL_ENV:
        monkeypatch.delenv(name, raising=False)
    # Never write the verdict cache into the developer's home directory.
    monkeypatch.setenv("WARDEN_CACHE_PATH", str(tmp_path / "verdict-cache.sqlite"))
    monkeypatch.delenv("WARDEN_CACHE", raising=False)
    if request.node.get_closest_marker("slow") is None:
        real_handle = httpx.HTTPTransport.handle_request

        def _loopback_only(self, request):
            # e2e tests talk to a real daemon on 127.0.0.1; anything else is a model call.
            if request.url.host not in ("127.0.0.1", "localhost", "::1"):
                raise RuntimeError(f"test tried to reach the network: {request.url}")
            return real_handle(self, request)

        # Real transports only; httpx.MockTransport used by provider tests is unaffected.
        monkeypatch.setattr(httpx.HTTPTransport, "handle_request", _loopback_only)
