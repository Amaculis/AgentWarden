"""Muse Spark via Meta Model API (OpenAI-compatible). Key only from the environment."""

from __future__ import annotations

import os

from agentwarden.providers.openai_compat import OpenAICompatProvider

DEFAULT_BASE = "https://api.meta.ai/v1"  # VERIFY against dev.meta.ai docs
DEFAULT_MODEL = "muse-spark-1.2"  # VERIFY via the models list


def from_env() -> OpenAICompatProvider | None:
    key = os.environ.get("META_API_KEY")
    if not key:
        return None
    return OpenAICompatProvider(
        base_url=os.environ.get("META_API_BASE") or DEFAULT_BASE,
        api_key=key,
        model=os.environ.get("WARDEN_MODEL") or DEFAULT_MODEL,
    )
