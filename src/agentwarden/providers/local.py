"""Meta open-weights model behind any OpenAI-compatible endpoint (vLLM, Ollama, ...)."""

from __future__ import annotations

import os

from agentwarden.providers.openai_compat import OpenAICompatProvider


def from_env() -> OpenAICompatProvider | None:
    base = os.environ.get("WARDEN_LOCAL_BASE")
    if not base:
        return None
    return OpenAICompatProvider(
        base_url=base,
        api_key=os.environ.get("WARDEN_LOCAL_KEY") or "local",
        model=os.environ.get("WARDEN_LOCAL_MODEL") or "local",
    )
