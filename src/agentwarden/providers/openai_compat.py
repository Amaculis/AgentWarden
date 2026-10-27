"""OpenAI-compatible chat-completions provider (Meta Model API and local servers).

Plain httpx, no SDK: one POST to `<base_url>/chat/completions`, no retries, no redirects.
`timeout` is a total deadline for the whole call, not per socket read, so a slow-drip
endpoint cannot hold a worker past it. The API key is sent only in the Authorization header
and never logged.
"""

from __future__ import annotations

import json
import logging
import time

import httpx

from agentwarden.providers.base import ProviderResult

logger = logging.getLogger(__name__)

MAX_RESPONSE_BYTES = 256 * 1024


class _DeadlineExceeded(Exception):
    pass


def _int_or_none(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


class OpenAICompatProvider:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str,
        http_client: httpx.Client | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self._api_key = api_key
        self._http_client = http_client

    def complete(
        self, messages: list[dict[str, str]], *, timeout: float, max_tokens: int
    ) -> ProviderResult:
        start = time.monotonic()

        def done(**fields) -> ProviderResult:
            return ProviderResult(latency_ms=int((time.monotonic() - start) * 1000), **fields)

        try:
            # Contributor tier trains on prompts; AgentWarden sends code context. Never call it.
            if "contributor" in self.model.lower():
                logger.error("refusing contributor-tier model %s", self.model)
                return done(error="config")
            status, raw = self._post(messages, max_tokens, start + timeout, timeout)
        except (httpx.TimeoutException, _DeadlineExceeded):
            return done(error="timeout")
        except httpx.TransportError:
            return done(error="connection")
        except Exception as exc:
            logger.warning("provider call failed: %s", type(exc).__name__)
            return done(error="connection")
        try:
            if status != 200:
                logger.warning("provider returned HTTP %s", status)
                return done(error="http")
            data = json.loads(raw)
            text = data["choices"][0]["message"]["content"]
            if not isinstance(text, str):
                return done(error="http")
            usage = data.get("usage")
            usage = usage if isinstance(usage, dict) else {}
            return done(
                text=text,
                tokens_in=_int_or_none(usage.get("prompt_tokens")),
                tokens_out=_int_or_none(usage.get("completion_tokens")),
            )
        except Exception:
            return done(error="http")

    def _post(
        self, messages: list[dict[str, str]], max_tokens: int, deadline: float, timeout: float
    ) -> tuple[int, bytes]:
        body = {
            "model": self.model,
            "messages": messages,
            "temperature": 0,
            "max_tokens": max_tokens,
        }
        headers = {"Authorization": f"Bearer {self._api_key}"}
        url = f"{self.base_url}/chat/completions"
        client = self._http_client or httpx.Client(follow_redirects=False)
        try:
            with client.stream("POST", url, json=body, headers=headers, timeout=timeout) as resp:
                chunks: list[bytes] = []
                size = 0
                for chunk in resp.iter_bytes():
                    if time.monotonic() > deadline:
                        raise _DeadlineExceeded
                    size += len(chunk)
                    if size > MAX_RESPONSE_BYTES:
                        return 413, b""
                    chunks.append(chunk)
                if time.monotonic() > deadline:
                    raise _DeadlineExceeded
                return resp.status_code, b"".join(chunks)
        finally:
            if self._http_client is None:
                client.close()
