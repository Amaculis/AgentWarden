"""Provider interface (spec 009): one call, never raises, errors are values."""

from __future__ import annotations

from typing import Literal, Protocol

from pydantic import BaseModel

ProviderError = Literal["timeout", "connection", "http", "config"]


class ProviderResult(BaseModel):
    text: str | None = None
    error: ProviderError | None = None
    latency_ms: int = 0
    tokens_in: int | None = None
    tokens_out: int | None = None
    cached: bool = False


class Provider(Protocol):
    def complete(
        self, messages: list[dict[str, str]], *, timeout: float, max_tokens: int
    ) -> ProviderResult: ...
