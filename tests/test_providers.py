"""Tests for agentwarden.providers (spec 009). No real network: `MockProvider` for
judge tests, `httpx.MockTransport` for `OpenAICompatProvider`.
"""

from __future__ import annotations

import httpx
import pytest

from agentwarden.providers import get_provider
from agentwarden.providers.base import ProviderResult
from agentwarden.providers.mock import MockProvider
from agentwarden.providers.openai_compat import OpenAICompatProvider

# ---------------------------------------------------------------------------
# MockProvider
# ---------------------------------------------------------------------------


def test_mock_provider_returns_responses_in_order():
    provider = MockProvider(["first", "second"])

    r1 = provider.complete([{"role": "user", "content": "a"}], timeout=1, max_tokens=10)
    r2 = provider.complete([{"role": "user", "content": "b"}], timeout=1, max_tokens=10)

    assert r1.text == "first"
    assert r1.error is None
    assert r2.text == "second"


def test_mock_provider_repeats_last_response_when_exhausted():
    provider = MockProvider(["only"])

    provider.complete([], timeout=1, max_tokens=10)
    r2 = provider.complete([], timeout=1, max_tokens=10)
    r3 = provider.complete([], timeout=1, max_tokens=10)

    assert r2.text == "only"
    assert r3.text == "only"


@pytest.mark.parametrize(
    ("marker", "expected_error"),
    [("!timeout", "timeout"), ("!connection", "connection"), ("!http", "http")],
)
def test_mock_provider_error_markers(marker, expected_error):
    provider = MockProvider([marker])
    result = provider.complete([], timeout=1, max_tokens=10)
    assert result.error == expected_error
    assert result.text is None


def test_mock_provider_records_calls():
    provider = MockProvider(["ok"])
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "data"}]

    provider.complete(messages, timeout=1, max_tokens=10)

    assert provider.calls == [messages]


def test_mock_provider_empty_responses_always_connection_error():
    provider = MockProvider([])
    result = provider.complete([], timeout=1, max_tokens=10)
    assert result.error == "connection"


# ---------------------------------------------------------------------------
# OpenAICompatProvider via httpx.MockTransport -- no network
# ---------------------------------------------------------------------------


def _client_with_handler(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_openai_compat_parses_response():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "allow, low risk"}}],
                "usage": {"prompt_tokens": 12, "completion_tokens": 4},
            },
        )

    provider = OpenAICompatProvider(
        base_url="https://example.invalid/v1",
        api_key="k",
        model="muse-spark-1.2",
        http_client=_client_with_handler(handler),
    )

    result = provider.complete([{"role": "user", "content": "hi"}], timeout=5, max_tokens=50)

    assert result.error is None
    assert result.text == "allow, low risk"
    assert result.tokens_in == 12
    assert result.tokens_out == 4


def test_openai_compat_http_500_is_http_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "boom"})

    provider = OpenAICompatProvider(
        base_url="https://example.invalid/v1",
        api_key="k",
        model="muse-spark-1.2",
        http_client=_client_with_handler(handler),
    )

    result = provider.complete([], timeout=5, max_tokens=50)

    assert result.error == "http"
    assert result.text is None


def test_openai_compat_connect_error_is_connection():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route")

    provider = OpenAICompatProvider(
        base_url="https://example.invalid/v1",
        api_key="k",
        model="muse-spark-1.2",
        http_client=_client_with_handler(handler),
    )

    result = provider.complete([], timeout=5, max_tokens=50)

    assert result.error == "connection"


def test_openai_compat_read_timeout_is_timeout():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("too slow")

    provider = OpenAICompatProvider(
        base_url="https://example.invalid/v1",
        api_key="k",
        model="muse-spark-1.2",
        http_client=_client_with_handler(handler),
    )

    result = provider.complete([], timeout=5, max_tokens=50)

    assert result.error == "timeout"


def test_openai_compat_contributor_model_refused_without_request():
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json={})

    provider = OpenAICompatProvider(
        base_url="https://example.invalid/v1",
        api_key="k",
        model="muse-spark-contributor",
        http_client=_client_with_handler(handler),
    )

    result = provider.complete([], timeout=5, max_tokens=50)

    assert result.error == "config"
    assert called is False


def test_openai_compat_complete_never_raises_on_handler_exception():
    def handler(request: httpx.Request) -> httpx.Response:
        raise ValueError("unexpected crash")

    provider = OpenAICompatProvider(
        base_url="https://example.invalid/v1",
        api_key="k",
        model="muse-spark-1.2",
        http_client=_client_with_handler(handler),
    )

    result = provider.complete([], timeout=5, max_tokens=50)

    assert isinstance(result, ProviderResult)
    assert result.error is not None
    assert result.text is None


def test_openai_compat_malformed_json_body_is_http_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not json")

    provider = OpenAICompatProvider(
        base_url="https://example.invalid/v1",
        api_key="k",
        model="muse-spark-1.2",
        http_client=_client_with_handler(handler),
    )

    result = provider.complete([], timeout=5, max_tokens=50)

    assert result.error == "http"


# ---------------------------------------------------------------------------
# from_env()
# ---------------------------------------------------------------------------


def test_meta_api_from_env_none_without_key(monkeypatch: pytest.MonkeyPatch):
    from agentwarden.providers import meta_api

    monkeypatch.delenv("META_API_KEY", raising=False)

    assert meta_api.from_env() is None


def test_meta_api_from_env_configured(monkeypatch: pytest.MonkeyPatch):
    from agentwarden.providers import meta_api

    monkeypatch.setenv("META_API_KEY", "secret-key")

    provider = meta_api.from_env()

    assert provider is not None


def test_local_from_env_none_without_base(monkeypatch: pytest.MonkeyPatch):
    from agentwarden.providers import local

    monkeypatch.delenv("WARDEN_LOCAL_BASE", raising=False)

    assert local.from_env() is None


def test_local_from_env_configured(monkeypatch: pytest.MonkeyPatch):
    from agentwarden.providers import local

    monkeypatch.setenv("WARDEN_LOCAL_BASE", "http://127.0.0.1:8000/v1")

    provider = local.from_env()

    assert provider is not None


# ---------------------------------------------------------------------------
# get_provider()
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["off", None, "bogus"])
def test_get_provider_unconfigured_or_unknown_is_none(name, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("META_API_KEY", raising=False)
    monkeypatch.delenv("WARDEN_LOCAL_BASE", raising=False)

    assert get_provider(name) is None


def test_get_provider_mock_returns_a_provider():
    provider = get_provider("mock")

    assert provider is not None
    assert hasattr(provider, "complete")


def test_openai_compat_total_deadline_on_slow_drip():
    import time as _time

    from agentwarden.providers.openai_compat import OpenAICompatProvider

    def slow_body():
        for _ in range(10):
            _time.sleep(0.1)
            yield b" "

    def handler(request):
        return httpx.Response(200, content=slow_body())

    provider = OpenAICompatProvider(
        "http://test.invalid/v1",
        "k",
        "m",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    start = _time.monotonic()
    result = provider.complete([{"role": "user", "content": "hi"}], timeout=0.3, max_tokens=10)
    assert result.error == "timeout"
    assert _time.monotonic() - start < 0.8


@pytest.mark.parametrize("usage", [[], {"prompt_tokens": "abc", "completion_tokens": True}])
def test_openai_compat_bad_usage_never_raises(usage):
    from agentwarden.providers.openai_compat import OpenAICompatProvider

    def handler(request):
        body = {"choices": [{"message": {"content": "{}"}}], "usage": usage}
        return httpx.Response(200, json=body)

    provider = OpenAICompatProvider(
        "http://test.invalid/v1",
        "k",
        "m",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    result = provider.complete([{"role": "user", "content": "hi"}], timeout=2, max_tokens=10)
    assert result.text == "{}"
    assert result.tokens_in is None and result.tokens_out is None
