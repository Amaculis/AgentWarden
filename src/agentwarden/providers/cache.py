"""Verdict cache (spec 012): identical requests are answered from SQLite, not re-billed.

Keyed by model + max_tokens + messages; the messages already contain the prompt text and
the redacted request. Only successful, cacheable results are stored. Never raises.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
from collections.abc import Callable
from pathlib import Path

from agentwarden.providers.base import Provider, ProviderResult

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS verdicts (
    key TEXT PRIMARY KEY,
    text TEXT NOT NULL,
    tokens_in INTEGER,
    tokens_out INTEGER
)
"""


def cache_path() -> Path:
    env = os.environ.get("WARDEN_CACHE_PATH")
    return Path(env) if env else Path.home() / ".agentwarden" / "cache.sqlite"


class CachedProvider:
    def __init__(
        self,
        provider: Provider,
        path: Path | str | None = None,
        cacheable: Callable[[str], bool] | None = None,
        namespace: str = "",
    ) -> None:
        self.provider = provider
        self.path = Path(path) if path else cache_path()
        self.cacheable = cacheable
        self.model = getattr(provider, "model", type(provider).__name__)
        # Role + endpoint keep e.g. the local and the Spark judge apart even if the model ids
        # happen to match.
        self.namespace = f"{namespace}|{getattr(provider, 'base_url', '')}"
        self.calls = 0
        self.hits = 0
        self.tokens_in = 0
        self.tokens_out = 0

    def _key(self, messages: list[dict[str, str]], max_tokens: int) -> str:
        blob = json.dumps(
            {
                "namespace": self.namespace,
                "model": self.model,
                "max_tokens": max_tokens,
                "messages": messages,
            },
            sort_keys=True,
            ensure_ascii=False,
        )
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=1.0)
        conn.execute(_SCHEMA)
        return conn

    def _get(self, key: str) -> ProviderResult | None:
        try:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT text, tokens_in, tokens_out FROM verdicts WHERE key = ?", (key,)
                ).fetchone()
            finally:
                conn.close()
        except Exception as exc:
            logger.warning("verdict cache read failed: %s", type(exc).__name__)
            return None
        if row is None:
            return None
        return ProviderResult(text=row[0], tokens_in=row[1], tokens_out=row[2], cached=True)

    def _put(self, key: str, result: ProviderResult) -> None:
        try:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO verdicts VALUES (?, ?, ?, ?)",
                    (key, result.text, result.tokens_in, result.tokens_out),
                )
                conn.commit()
            finally:
                conn.close()
        except Exception as exc:
            logger.warning("verdict cache write failed: %s", type(exc).__name__)

    def complete(
        self, messages: list[dict[str, str]], *, timeout: float, max_tokens: int
    ) -> ProviderResult:
        self.calls += 1
        try:
            key = self._key(messages, max_tokens)
        except Exception:
            key = None
        if key is not None:
            hit = self._get(key)
            if hit is not None:
                self.hits += 1
                return hit
        result = self.provider.complete(messages, timeout=timeout, max_tokens=max_tokens)
        self.tokens_in += result.tokens_in or 0
        self.tokens_out += result.tokens_out or 0
        if key is not None and result.error is None and isinstance(result.text, str):
            try:
                ok = self.cacheable is None or self.cacheable(result.text)
            except Exception:
                ok = False
            if ok:
                self._put(key, result)
        return result
