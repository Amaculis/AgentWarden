"""Model providers (spec 009)."""

from __future__ import annotations

from agentwarden.providers.base import Provider, ProviderResult


def get_provider(name: str | None) -> Provider | None:
    """Provider by name (`meta_api` | `local` | `mock`); unknown, `off` or unconfigured → None."""
    name = (name or "").strip().lower()
    if name == "meta_api":
        from agentwarden.providers import meta_api

        return meta_api.from_env()
    if name == "local":
        from agentwarden.providers import local

        return local.from_env()
    if name == "mock":
        from agentwarden.providers.mock import MockProvider

        return MockProvider()
    return None


__all__ = ["Provider", "ProviderResult", "get_provider"]
