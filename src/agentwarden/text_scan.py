"""Strings in a tool input, for the cheap escalation checks (specs 022, 023)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

SKIPPED_KEYS = frozenset({"old_string"})  # code being removed


def strings(value: Any) -> Iterator[str]:
    """Every string in `value`, recursively, except values under `SKIPPED_KEYS`."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            if key not in SKIPPED_KEYS:
                yield from strings(item)
    elif isinstance(value, list | tuple):
        for item in value:
            yield from strings(item)
