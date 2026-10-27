"""Deterministic provider for tests (spec 009). Never touches the network."""

from __future__ import annotations

from agentwarden.providers.base import ProviderResult

_ERRORS = {"!timeout": "timeout", "!connection": "connection", "!http": "http"}


class MockProvider:
    """Returns `responses` in order (text, or "!timeout" / "!connection" / "!http").

    The last response repeats once the list is exhausted; an empty list always answers
    "!connection" so a misconfigured mock stays fail-closed.
    """

    def __init__(self, responses: list[str] | None = None) -> None:
        self.responses = list(responses or [])
        self.calls: list[list[dict[str, str]]] = []

    def complete(
        self, messages: list[dict[str, str]], *, timeout: float, max_tokens: int
    ) -> ProviderResult:
        self.calls.append([dict(m) for m in messages])
        if not self.responses:
            return ProviderResult(error="connection")
        index = min(len(self.calls) - 1, len(self.responses) - 1)
        response = self.responses[index]
        if response in _ERRORS:
            return ProviderResult(error=_ERRORS[response])
        return ProviderResult(text=response)
