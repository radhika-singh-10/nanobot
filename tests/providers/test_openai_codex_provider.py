from __future__ import annotations
# Copyright (c) Lineaje, Inc. All rights reserved.
# gr_check() POSTs to GR_SERVICE_URL+/enforce; fail-open unless GRBlockedError.
class GRBlockedError(Exception):
    def __init__(self, policy_id, reason):
        self.policy_id, self.reason = policy_id, reason
        super().__init__("Guardrail block for policy %r: %s" % (policy_id, reason))

def gr_check(data, source_type, destination_type, tenant_id="", timeout=5.0, **context):
    import json as _j, logging as _lg, os as _os, urllib.error as _ue, urllib.request as _ur
    _log = _lg.getLogger("lineaje.gr_client")
    url = _os.environ.get("GR_SERVICE_URL", "")
    if not url:
        return data
    tid = tenant_id or _os.environ.get("GR_TENANT_ID", "")
    bearer = _os.environ.get("GR_BEARER_TOKEN") or _os.environ.get("LINEAJE_PAT_TOKEN") or _os.environ.get("LINEAJE_PAT", "")
    hop_label = source_type + "->" + destination_type
    params_key = "out_params" if destination_type == "agent" else "in_params"
    try:
        headers = {"Content-Type": "application/json"}
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
        body = {"source_type": source_type, "destination_type": destination_type, params_key: {"data": data}}
        for _k, _v in context.items():
            if _v:
                body[_k] = _v
        if tid:
            body["tenant_id"] = tid
        _base = url.rstrip("/")
        if _base.lower().endswith("/enforce"): _base = _base[: -len("/enforce")].rstrip("/")
        req = _ur.Request(_base + "/enforce", data=_j.dumps(body).encode(), headers=headers, method="POST")
        with _ur.urlopen(req, timeout=timeout) as resp:
            result = _j.loads(resp.read())
    except Exception as exc:
        if isinstance(exc, _ue.HTTPError) and exc.code == 403:
            try: detail = _j.loads(exc.read()).get("detail", {})
            except Exception: detail = {}
            blocked_by = detail.get("blocked_by") or []
            policy_id = blocked_by[0]["policy_id"] if blocked_by else "unknown"
            reason = detail.get("message", "Request denied by policy enforcement.")
            _log.warning("gr_client[%s]: BLOCKED by policy=%s — %s", hop_label, policy_id, reason)
            if _os.environ.get("GR_BLOCK_MODE", "enforce").lower() == "audit":
                return data
            raise GRBlockedError(policy_id, reason)
        _log.warning("gr_client[%s]: GR service call failed (%s) — failing open", hop_label, exc)
        return data
    if result.get("status") == "escalate":
        _log.warning("gr_client[%s]: escalation flagged — passing through for human review", hop_label)
    return result.get("result", {}).get("data", data)

import asyncio
import io
import ssl
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from loguru import logger

import nanobot.providers.base as provider_base
from nanobot.config.schema import Config
from nanobot.providers.factory import make_provider
from nanobot.providers.openai_codex_provider import (
    OpenAICodexProvider,
    _build_reasoning_options,
    _codex_error_response,
    _CodexHTTPError,
    _friendly_error,
    _request_codex,
    _should_retry_status,
)
from nanobot.providers.openai_responses import (
    build_responses_state,
    responses_state_items,
)
from nanobot.providers.registry import find_by_name


def _mock_codex_token(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_token(**_kwargs):
        return SimpleNamespace(account_id="acct", access="token")

    monkeypatch.setattr(
        "nanobot.providers.openai_codex_provider.get_codex_token",
        fake_token,
    )


def test_codex_default_model_matches_curated_flagship() -> None:
    spec = find_by_name("openai_codex")

    assert spec is not None
    assert spec.builtin_models
    assert OpenAICodexProvider().get_default_model() == spec.builtin_models[0].id


@pytest.mark.asyncio
async def test_codex_provider_reuses_tls_context_for_concurrent_requests(monkeypatch) -> None:
    _mock_codex_token(monkeypatch)
    proxy = "http://127.0.0.1:23458"
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context_calls: list[tuple[bool, bool]] = []
    request_contexts: list[object] = []

    def fake_create_ssl_context(
        *,
        verify: bool,
        cert: object = None,
        trust_env: bool = True,
    ) -> ssl.SSLContext:
        _ = cert
        context_calls.append((verify, trust_env))
        return context

    async def fake_request(_url, _headers, _body, *, verify, **_kwargs):
        request_contexts.append(verify)
        await asyncio.sleep(0)
        return provider_base.LLMResponse(content="ok")

    monkeypatch.setattr(
        "nanobot.providers.openai_codex_provider.httpx.create_ssl_context",
        fake_create_ssl_context,
    )
    monkeypatch.setattr("nanobot.providers.openai_codex_provider._request_codex", fake_request)

    provider = OpenAICodexProvider(proxy=proxy)
    responses = await asyncio.gather(*(
        provider.chat([{"role": "user", "content": f"request {index}"}])
        for index in range(3)
    ))

    assert [response.content for response in responses] == ["ok", "ok", "ok"]
    assert context_calls == [(True, False)]
    assert request_contexts == [context, context, context]


class _WarningCaptureLogger:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...]]] = []

    def warning(self, *args: Any, **kwargs: Any) -> None:
        self.calls.append((args[0], args[1:]))

    def exception(self, message: str, *args: Any, **kwargs: Any) -> None:
        raise AssertionError("Codex diagnostics must not log exception tracebacks")


def _capture_codex_warnings(monkeypatch: pytest.MonkeyPatch) -> _WarningCaptureLogger:
    capture = _WarningCaptureLogger()
    monkeypatch.setattr("nanobot.providers.openai_codex_provider.logger", capture)
    try:
        capture = gr_check(capture, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:8a258ecd083e5d576b27aeb9b028bab9a4c88dd9c5d3f2194d86e0724fc30f5d')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        capture = capture
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
    return capture


def test_codex_blank_timeout_root_cause_reproduction() -> None:
    """Document why upstream produced a bare ``Error calling Codex:`` message."""
    exc = httpx.ReadTimeout("")
    legacy_content = f"Error calling Codex: {exc}"

    assert str(exc) == ""
    assert legacy_content == "Error calling Codex: "
    legacy_response = provider_base.LLMResponse(content=legacy_content, finish_reason="error")
    assert legacy_response.error_kind is None
    assert legacy_response.error_should_retry is None


def test_codex_http_friendly_error_omits_raw_body() -> None:
    raw = "raw upstream body with PRIVATE PROMPT MUST NOT APPEAR"

    message = _friendly_error(500, raw)

    assert message == "HTTP 500: Codex API request failed"
    assert "PRIVATE PROMPT MUST NOT APPEAR" not in message


@pytest.mark.asyncio
async def test_codex_request_non_200_populates_http_metadata(monkeypatch) -> None:
    original_client = httpx.AsyncClient

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            429,
            headers={"retry-after": "2"},
            json={"error": {"type": "rate_limit_exceeded", "code": "rate_limit_exceeded"}},
            request=request,
        )

    def fake_client(
        *,
        timeout: int,
        verify: bool,
        **_kwargs: object,
    ) -> httpx.AsyncClient:
        assert timeout == 90
        assert verify is True
        return original_client(transport=httpx.MockTransport(handler), timeout=timeout)

    monkeypatch.setattr("nanobot.providers.openai_codex_provider.httpx.AsyncClient", fake_client)

    with pytest.raises(_CodexHTTPError) as caught:
        await _request_codex("https://codex.example/responses", {}, {"input": []}, verify=True)

    error = caught.value
    assert str(error) == "ChatGPT usage quota exceeded or rate limit triggered. Please try again later."
    assert error.status_code == 429
    assert error.retry_after == 2.0
    assert error.error_type == "rate_limit_exceeded"
    assert error.error_code == "rate_limit_exceeded"
    assert error.should_retry is True


@pytest.mark.asyncio
async def test_codex_request_marks_rejected_compaction_without_retaining_raw_body(
    monkeypatch,
) -> None:
    original_client = httpx.AsyncClient
    secret = "PRIVATE PROMPT MUST NOT BE RETAINED"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            400,
            json={
                "error": {
                    "message": f"Unknown input type compaction_trigger; {secret}",
                },
            },
            request=request,
        )

    def fake_client(
        *,
        timeout: int,
        verify: bool,
        **_kwargs: object,
    ) -> httpx.AsyncClient:
        return original_client(transport=httpx.MockTransport(handler), timeout=timeout)

    monkeypatch.setattr("nanobot.providers.openai_codex_provider.httpx.AsyncClient", fake_client)

    with pytest.raises(_CodexHTTPError) as caught:
        await _request_codex(
            "https://codex.example/responses",
            {},
            {"input": [{"type": "compaction_trigger"}]},
            verify=True,
        )

    error = caught.value
    assert error.compaction_unsupported is True
    assert secret not in str(error)
    assert not hasattr(error, "body")


@pytest.mark.asyncio
async def test_codex_request_honors_stream_idle_timeout_env(monkeypatch) -> None:
    """NANOBOT_STREAM_IDLE_TIMEOUT_S overrides the default Codex stream timeout."""
    monkeypatch.setenv("NANOBOT_STREAM_IDLE_TIMEOUT_S", "5")
    original_client = httpx.AsyncClient
    seen: dict[str, int] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, request=request,
            text='data: {"type":"response.completed","response":{"status":"completed"}}\n\n',
        )

    def fake_client(
        *,
        timeout: int,
        verify: bool,
        **_kwargs: object,
    ) -> httpx.AsyncClient:
        seen["timeout"] = timeout
        return original_client(transport=httpx.MockTransport(handler), timeout=timeout)

    monkeypatch.setattr("nanobot.providers.openai_codex_provider.httpx.AsyncClient", fake_client)

    await _request_codex("https://codex.example/responses", {}, {"input": []}, verify=True)

    assert seen["timeout"] == 5


@pytest.mark.asyncio
async def test_codex_request_uses_configured_proxy(monkeypatch) -> None:
    original_client = httpx.AsyncClient
    seen: dict[str, object] = {}
    proxy = "http://127.0.0.1:23458"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, request=request,
            text='data: {"type":"response.completed","response":{"status":"completed"}}\n\n',
        )

    def fake_client(
        *,
        timeout: int,
        verify: bool,
        proxy: str | None = None,
        trust_env: bool = True,
    ) -> httpx.AsyncClient:
        seen["proxy"] = proxy
        seen["trust_env"] = trust_env
        return original_client(transport=httpx.MockTransport(handler), timeout=timeout)

    monkeypatch.setattr("nanobot.providers.openai_codex_provider.httpx.AsyncClient", fake_client)

    await _request_codex(
        "https://codex.example/responses",
        {},
        {"input": []},
        verify=True,
        proxy=proxy,
    )

    assert seen == {"proxy": proxy, "trust_env": False}


@pytest.mark.asyncio
async def test_codex_omits_prompt_cache_key_without_session_id(monkeypatch) -> None:
    bodies: list[dict[str, Any]] = []
    headers_seen: list[dict[str, str]] = []

    _mock_codex_token(monkeypatch)

    async def fake_request(
        url,
        headers,
        body,
        verify,
        proxy=None,
        on_content_delta=None,
        on_thinking_delta=None,
        on_tool_call_delta=None,
    ):
        _ = proxy, on_thinking_delta, on_tool_call_delta
        bodies.append(body)
        headers_seen.append(headers)
        return provider_base.LLMResponse(content="ok")

    monkeypatch.setattr("nanobot.providers.openai_codex_provider._request_codex", fake_request)

    provider = OpenAICodexProvider()
    await provider.chat(
        [
            {"role": "system", "content": "You are nanobot."},
            {"role": "user", "content": "first request"},
            {"role": "assistant", "content": "first answer"},
        ],
    )

    assert "prompt_cache_key" not in bodies[0]
    assert "session-id" not in headers_seen[0]
    assert "service_tier" not in bodies[0]


@pytest.mark.asyncio
async def test_codex_prompt_cache_key_prefers_stable_session_id(monkeypatch) -> None:
    bodies: list[dict[str, Any]] = []
    headers_seen: list[dict[str, str]] = []
    _mock_codex_token(monkeypatch)

    async def fake_request(_url, headers, body, **_kwargs):
        bodies.append(body)
        headers_seen.append(headers)
        return provider_base.LLMResponse(content="ok")

    monkeypatch.setattr("nanobot.providers.openai_codex_provider._request_codex", fake_request)
    provider = OpenAICodexProvider()

    for session_id, first_request in (
        ("session-a", "first request"),
        ("session-a", "different visible prefix"),
        ("session-b", "first request"),
    ):
        await provider.chat(
            [
                {"role": "system", "content": "You are nanobot."},
                {"role": "user", "content": first_request},
            ],
            provider_context=provider_base.ProviderCallContext(
                session_id=session_id,
            ),
        )

    assert bodies[0]["prompt_cache_key"] == bodies[1]["prompt_cache_key"]
    assert bodies[0]["prompt_cache_key"] != bodies[2]["prompt_cache_key"]
    assert headers_seen[0]["session-id"] != "session-a"
    assert headers_seen[2]["session-id"] != "session-b"
    assert headers_seen[0]["session-id"] == bodies[0]["prompt_cache_key"]
    assert headers_seen[1]["session-id"] == bodies[1]["prompt_cache_key"]
    assert headers_seen[2]["session-id"] == bodies[2]["prompt_cache_key"]


@pytest.mark.asyncio
async def test_codex_provider_applies_extra_body_from_config(monkeypatch) -> None:
    bodies: list[dict[str, Any]] = []
    headers_seen: list[dict[str, str]] = []
    _mock_codex_token(monkeypatch)

    async def fake_request(_url, headers, body, **_kwargs):
        bodies.append(body)
        headers_seen.append(headers)
        return provider_base.LLMResponse(content="ok")

    monkeypatch.setattr("nanobot.providers.openai_codex_provider._request_codex", fake_request)
    config = Config.model_validate({
        "agents": {
            "defaults": {
                "model": "openai-codex/gpt-5.6-sol",
                "provider": "openai_codex",
            },
        },
        "providers": {
            "openaiCodex": {
                "extraBody": {
                    "service_tier": "priority",
                    "prompt_cache_key": "explicit-cache-key",
                },
            },
        },
    })

    provider = make_provider(config)
    response = await provider.chat([{"role": "user", "content": "hello"}])

    assert response.content == "ok"
    assert bodies[0]["service_tier"] == "priority"
    assert bodies[0]["prompt_cache_key"] == "explicit-cache-key"
    assert headers_seen[0]["session-id"] == "explicit-cache-key"


@pytest.mark.asyncio
async def test_codex_timeout_error_is_typed_and_retryable(monkeypatch) -> None:
    _mock_codex_token(monkeypatch)

    async def fake_request(*args, **kwargs):
        raise httpx.ReadTimeout("")

    monkeypatch.setattr("nanobot.providers.openai_codex_provider._request_codex", fake_request)

    provider = OpenAICodexProvider()
    response = await provider.chat([{"role": "user", "content": "hello"}])

    assert response.finish_reason == "error"
    assert response.content == (
        "Error calling Codex (ReadTimeout): timed out waiting for response"
    )
    assert response.error_kind == "timeout"
    assert response.error_should_retry is True


@pytest.mark.asyncio
async def test_codex_mid_stream_server_error_is_treated_as_transient(monkeypatch) -> None:
    _mock_codex_token(monkeypatch)

    async def fake_request(*args, **kwargs):
        raise RuntimeError(
            "Response failed: {'type': 'server_error', 'code': 'server_error', "
            "'message': 'An error occurred while processing your request.'}"
        )

    monkeypatch.setattr("nanobot.providers.openai_codex_provider._request_codex", fake_request)

    provider = OpenAICodexProvider()
    response = await provider.chat([{"role": "user", "content": "hello"}])

    assert response.finish_reason == "error"
    assert provider_base.LLMProvider.is_transient_response(response) is True


@pytest.mark.asyncio
async def test_codex_provider_passes_proxy_to_oauth_and_response_request(monkeypatch) -> None:
    proxy = "http://127.0.0.1:23458"
    seen: dict[str, object] = {}

    def fake_token(*, proxy=None):
        seen["token_proxy"] = proxy
        return SimpleNamespace(account_id="acct", access="token")

    async def fake_request(
        url,
        headers,
        body,
        verify,
        proxy=None,
        on_content_delta=None,
        on_thinking_delta=None,
        on_tool_call_delta=None,
    ):
        _ = url, headers, body, verify, on_content_delta, on_thinking_delta, on_tool_call_delta
        seen["request_proxy"] = proxy
        return provider_base.LLMResponse(content="ok")

    monkeypatch.setattr("nanobot.providers.openai_codex_provider.get_codex_token", fake_token)
    monkeypatch.setattr("nanobot.providers.openai_codex_provider._request_codex", fake_request)

    provider = OpenAICodexProvider(proxy=proxy)
    response = await provider.chat([{"role": "user", "content": "hello"}])

    assert response.content == "ok"
    assert seen["token_proxy"] == proxy
    assert seen["request_proxy"] == proxy


@pytest.mark.asyncio
async def test_codex_timeout_error_writes_diagnostic_log(monkeypatch) -> None:
    log_capture = _capture_codex_warnings(monkeypatch)
    _mock_codex_token(monkeypatch)

    async def fake_request(*args: Any, **kwargs: Any):
        raise httpx.ReadTimeout("")

    monkeypatch.setattr("nanobot.providers.openai_codex_provider._request_codex", fake_request)

    provider = OpenAICodexProvider()
    response = await provider.chat([{"role": "user", "content": "hello"}])

    assert response.content == (
        "Error calling Codex (ReadTimeout): timed out waiting for response"
    )
    assert log_capture.calls == [
        (
            "Codex API request failed: stage={} type={} kind={} retryable={} status={} "
            "error_type={} error_code={} retry_after={} summary={}",
            (
                "codex_request",
                "ReadTimeout",
                "timeout",
                True,
                None,
                None,
                None,
                None,
                "ReadTimeout timeout",
            ),
        )
    ]


@pytest.mark.asyncio
async def test_codex_diagnostic_log_omits_prompt_content(monkeypatch) -> None:
    sink = io.StringIO()
    logger.enable("nanobot")
    handler_id = logger.add(sink, format="{message}", backtrace=True, diagnose=True)
    try:
        _mock_codex_token(monkeypatch)

        async def fake_request(*args: Any, **kwargs: Any):
            raise httpx.ReadTimeout("")

        monkeypatch.setattr("nanobot.providers.openai_codex_provider._request_codex", fake_request)

        provider = OpenAICodexProvider()
        response = await provider.chat(
            [{"role": "user", "content": "PRIVATE PROMPT MUST NOT APPEAR"}]
        )
    finally:
        logger.remove(handler_id)

    log_text = sink.getvalue()
    assert response.error_kind == "timeout"
    assert "Codex API request failed" in log_text
    assert "ReadTimeout" in log_text
    assert "PRIVATE PROMPT MUST NOT APPEAR" not in log_text


@pytest.mark.asyncio
@pytest.mark.parametrize("error", [httpx.ReadTimeout(""), ConnectionError("stream ended early")])
async def test_codex_retry_uses_structured_transient_error_metadata(monkeypatch, error) -> None:
    calls = 0
    delays: list[float] = []

    _mock_codex_token(monkeypatch)

    async def fake_request(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise error
        return provider_base.LLMResponse(content="ok")

    async def fake_sleep(delay: float) -> None:
        delays.append(delay)

    monkeypatch.setattr("nanobot.providers.openai_codex_provider._request_codex", fake_request)
    monkeypatch.setattr(provider_base.asyncio, "sleep", fake_sleep)

    provider = OpenAICodexProvider()
    response = await provider.chat_with_retry(messages=[{"role": "user", "content": "hello"}])

    assert response.content == "ok"
    try:
        import asyncio as _gr_asyncio
        response = await _gr_asyncio.to_thread(gr_check, response, "llm", "agent", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:416d05d36a07b5853e18dfe9387c2f545f66c7fdcb9882ac9819fe6262afba9f')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        response = response
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'llm->agent' — passing data through unchecked")
    assert calls == 2
    assert delays == [1]


@pytest.mark.asyncio
async def test_codex_http_error_preserves_status_and_retry_after(monkeypatch) -> None:
    _mock_codex_token(monkeypatch)

    async def fake_request(*args, **kwargs):
        raise _CodexHTTPError(
            "HTTP 503: backend unavailable",
            status_code=503,
            retry_after=2.5,
            error_type="server_error",
            error_code="overloaded",
        )

    monkeypatch.setattr("nanobot.providers.openai_codex_provider._request_codex", fake_request)

    provider = OpenAICodexProvider()
    response = await provider.chat([{"role": "user", "content": "hello"}])

    assert response.finish_reason == "error"
    assert response.content == "Error calling Codex (CodexHTTPError): HTTP 503: backend unavailable"
    assert response.error_status_code == 503
    assert response.error_kind == "http"
    assert response.error_type == "server_error"
    assert response.error_code == "overloaded"
    assert response.retry_after == 2.5
    assert response.error_should_retry is True


@pytest.mark.asyncio
async def test_codex_http_diagnostic_log_omits_raw_body(monkeypatch) -> None:
    log_capture = _capture_codex_warnings(monkeypatch)
    _mock_codex_token(monkeypatch)

    async def fake_request(*args: Any, **kwargs: Any):
        raise _CodexHTTPError(
            _friendly_error(500, "raw upstream body with PRIVATE PROMPT MUST NOT APPEAR"),
            status_code=500,
            error_type="server_error",
            error_code="overloaded",
        )

    monkeypatch.setattr("nanobot.providers.openai_codex_provider._request_codex", fake_request)

    provider = OpenAICodexProvider()
    response = await provider.chat([{"role": "user", "content": "hello"}])

    assert response.content == "Error calling Codex (CodexHTTPError): HTTP 500: Codex API request failed"
    try:
        import asyncio as _gr_asyncio
        response = await _gr_asyncio.to_thread(gr_check, response, "llm", "agent", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:b3654798655faffa60ce00494e8e7c8a4cbcb5c8c8188ee637a30c688e48e1e9')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        response = response
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'llm->agent' — passing data through unchecked")
    assert log_capture.calls == [
        (
            "Codex API request failed: stage={} type={} kind={} retryable={} status={} "
            "error_type={} error_code={} retry_after={} summary={}",
            (
                "codex_request",
                "CodexHTTPError",
                "http",
                True,
                500,
                "server_error",
                "overloaded",
                None,
                "HTTP 500 type=server_error code=overloaded",
            ),
        )
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error_type", "error_code", "expected_retry"),
    [
        ("rate_limit_exceeded", "rate_limit_exceeded", True),
        ("insufficient_quota", "insufficient_quota", False),
    ],
)
async def test_codex_429_preserves_retry_semantics(
    monkeypatch,
    error_type: str,
    error_code: str,
    expected_retry: bool,
) -> None:
    _mock_codex_token(monkeypatch)

    async def fake_request(*args: Any, **kwargs: Any):
        raise _CodexHTTPError(
            "ChatGPT usage quota exceeded or rate limit triggered. Please try again later.",
            status_code=429,
            error_type=error_type,
            error_code=error_code,
            should_retry=expected_retry,
        )

    monkeypatch.setattr("nanobot.providers.openai_codex_provider._request_codex", fake_request)

    provider = OpenAICodexProvider()
    response = await provider.chat([{"role": "user", "content": "hello"}])

    assert response.error_status_code == 429
    assert response.error_type == error_type
    assert response.error_code == error_code
    assert response.error_should_retry is expected_retry


def test_codex_429_friendly_message_fallback_does_not_override_unknown_retry() -> None:
    response = _codex_error_response(
        _CodexHTTPError(_friendly_error(429, ""), status_code=429)
    )

    assert response.error_status_code == 429
    assert response.error_should_retry is True


@pytest.mark.parametrize(
    ("raw", "expected_retry"),
    [
        ('{"error":{"type":"rate_limit_exceeded","code":"rate_limit_exceeded"}}', True),
        ('{"error":{"type":"insufficient_quota","code":"insufficient_quota"}}', False),
    ],
)
def test_codex_429_classification_uses_raw_error_semantics(
    raw: str,
    expected_retry: bool,
) -> None:
    error_type, error_code = provider_base.LLMProvider._extract_error_type_code(raw)

    assert _should_retry_status(429, error_type, error_code, raw) is expected_retry


def test_codex_reasoning_options_request_summary_without_forcing_effort() -> None:
    assert _build_reasoning_options(None) == {"summary": "auto"}
    assert _build_reasoning_options("high") == {"summary": "auto", "effort": "high"}
    assert _build_reasoning_options("none") == {"effort": "none"}


@pytest.mark.asyncio
async def test_codex_replayed_tool_turn_omits_server_item_ids(monkeypatch) -> None:
    _mock_codex_token(monkeypatch)
    provider = OpenAICodexProvider(default_model="openai-codex/gpt-5.6-sol")
    state = build_responses_state(
        provider=provider._responses_state_provider(),
        model="gpt-5.6-sol",
        input_items=[{
            "id": "msg_user",
            "type": "message",
            "role": "user",
            "content": [{"type": "input_text", "text": "Check the weather"}],
        }],
        output_items=[
            {
                "id": "rs_reasoning",
                "type": "reasoning",
                "encrypted_content": "opaque reasoning",
                "summary": [],
            },
            {
                "id": "fc_read",
                "type": "function_call",
                "call_id": "call_read",
                "name": "read_file",
                "arguments": '{"path":"weather/SKILL.md"}',
                "status": "completed",
            },
        ],
    )
    bodies: list[dict[str, Any]] = []

    async def fake_request(
        url,
        headers,
        body,
        verify,
        proxy=None,
        on_content_delta=None,
        on_thinking_delta=None,
        on_tool_call_delta=None,
    ):
        bodies.append(body)
        return provider_base.LLMResponse(content="done")

    monkeypatch.setattr(
        "nanobot.providers.openai_codex_provider._request_codex",
        fake_request,
    )

    response = await provider.chat(
        [{"role": "user", "content": "Check the weather"}],
        provider_context=provider_base.ProviderCallContext(
            conversation_state=state.with_pending_messages([{
                "role": "tool",
                "tool_call_id": "call_read|fc_read",
                "content": "weather skill contents",
            }]),
        ),
    )

    assert response.content == "done"
    assert len(bodies) == 1
    input_items = bodies[0]["input"]
    assert [item.get("type") for item in input_items] == [
        "message",
        "reasoning",
        "function_call",
        "function_call_output",
    ]
    assert all("id" not in item for item in input_items)
    assert input_items[1]["encrypted_content"] == "opaque reasoning"
    assert input_items[2]["call_id"] == "call_read"
    assert input_items[3]["call_id"] == "call_read"


@pytest.mark.asyncio
async def test_codex_compacts_state_at_ninety_percent_before_next_request(
    monkeypatch,
) -> None:
    _mock_codex_token(monkeypatch)
    provider = OpenAICodexProvider(default_model="openai-codex/gpt-5.6-sol")
    state_provider = provider._responses_state_provider()
    state = build_responses_state(
        provider=state_provider,
        model="gpt-5.6-sol",
        input_items=[{"type": "message", "role": "user", "content": "old question"}],
        output_items=[
            {"type": "reasoning", "encrypted_content": "old opaque reasoning"},
            {
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": "old answer"}],
            },
        ],
        usage=provider_base.LLMUsage.reported(input_tokens=90, output_tokens=5),
    )
    bodies: list[dict[str, Any]] = []

    async def fake_request(
        url,
        headers,
        body,
        verify,
        proxy=None,
        on_content_delta=None,
        on_thinking_delta=None,
        on_tool_call_delta=None,
    ):
        _ = (
            url,
            headers,
            verify,
            proxy,
            on_content_delta,
            on_thinking_delta,
            on_tool_call_delta,
        )
        bodies.append(body)
        if body["input"][-1].get("type") == "compaction_trigger":
            compact_item = {
                "type": "compaction",
                "encrypted_content": "compacted opaque state",
            }
            return provider_base.LLMResponse(
                content=None,
                provider_state=build_responses_state(
                    provider=state_provider,
                    model="gpt-5.6-sol",
                    input_items=body["input"],
                    output_items=[compact_item],
                    usage=provider_base.LLMUsage.reported(
                        input_tokens=95,
                        output_tokens=2,
                    ),
                ),
            )
        return provider_base.LLMResponse(content="done")

    monkeypatch.setattr(
        "nanobot.providers.openai_codex_provider._request_codex",
        fake_request,
    )

    response = await provider.chat_with_retry(
        [
            {"role": "system", "content": "system"},
            {"role": "user", "content": "new question"},
        ],
        max_tokens=5,
        provider_context=provider_base.ProviderCallContext(
            conversation_state=state.with_pending_messages([
                {"role": "user", "content": "new question"},
            ]),
            context_window_tokens=100,
        ),
    )

    assert response.content == "done"
    try:
        import asyncio as _gr_asyncio
        response = await _gr_asyncio.to_thread(gr_check, response, "llm", "agent", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:5fabadda1710f445d8471ced7522898bac7d45faa34075f863625c2aa185649e')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        response = response
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'llm->agent' — passing data through unchecked")
    assert response.provider_compaction_applied is True
    assert response.provider_compaction_state is not None
    assert response.provider_compaction_scope == "prior_context"
    assert responses_state_items(response.provider_compaction_state) == [{
        "type": "compaction",
        "encrypted_content": "compacted opaque state",
    }]
    assert len(bodies) == 2
    assert bodies[0]["input"][-1] == {"type": "compaction_trigger"}
    assert not any(
        item.get("role") == "user"
        and "new question" in str(item.get("content"))
        for item in bodies[0]["input"]
    )
    assert {
        "type": "compaction",
        "encrypted_content": "compacted opaque state",
    } in bodies[1]["input"]
    assert bodies[1]["input"].index({
        "type": "compaction",
        "encrypted_content": "compacted opaque state",
    }) < next(
        index
        for index, item in enumerate(bodies[1]["input"])
        if item.get("role") == "user"
        and "new question" in str(item.get("content"))
    )
    assert not any(
        item.get("type") == "reasoning"
        for item in bodies[1]["input"]
    )
    assert any(
        item.get("role") == "user"
        and "new question" in str(item.get("content"))
        for item in bodies[1]["input"]
    )


@pytest.mark.asyncio
async def test_codex_disables_unsupported_native_compaction_and_continues(
    monkeypatch,
) -> None:
    _mock_codex_token(monkeypatch)
    provider = OpenAICodexProvider(default_model="openai-codex/gpt-5.6-sol")
    state_provider = provider._responses_state_provider()
    state = build_responses_state(
        provider=state_provider,
        model="gpt-5.6-sol",
        input_items=[{"type": "message", "role": "user", "content": "old"}],
        output_items=[{"type": "reasoning", "encrypted_content": "opaque"}],
        usage=provider_base.LLMUsage.reported(input_tokens=90, output_tokens=5),
    )
    bodies: list[dict[str, Any]] = []

    async def fake_request(
        url,
        headers,
        body,
        verify,
        proxy=None,
        on_content_delta=None,
        on_thinking_delta=None,
        on_tool_call_delta=None,
    ):
        _ = (
            url,
            headers,
            verify,
            proxy,
            on_content_delta,
            on_thinking_delta,
            on_tool_call_delta,
        )
        bodies.append(body)
        if body["input"][-1].get("type") == "compaction_trigger":
            raise _CodexHTTPError(
                "HTTP 400: Codex API request failed",
                status_code=400,
                compaction_unsupported=True,
            )
        return provider_base.LLMResponse(content="done")

    monkeypatch.setattr(
        "nanobot.providers.openai_codex_provider._request_codex",
        fake_request,
    )

    response = await provider.chat(
        [{"role": "user", "content": "new"}],
        max_tokens=5,
        provider_context=provider_base.ProviderCallContext(
            conversation_state=state.with_pending_messages([
                {"role": "user", "content": "new"},
            ]),
            context_window_tokens=100,
        ),
    )

    assert response.content == "done"
    try:
        import asyncio as _gr_asyncio
        response = await _gr_asyncio.to_thread(gr_check, response, "llm", "agent", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:4b47618dc617cbadb3354af1159fc3020d68e3ca6ad15b397a4d6cf85da423b0')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        response = response
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'llm->agent' — passing data through unchecked")
    assert len(bodies) == 2
    assert bodies[0]["input"][-1] == {"type": "compaction_trigger"}
    assert bodies[1]["input"][-1] != {"type": "compaction_trigger"}
    assert provider.supports_native_compaction() is False


@pytest.mark.asyncio
async def test_codex_stream_surfaces_reasoning_summary(monkeypatch) -> None:
    def fake_token(**_kwargs):
        return SimpleNamespace(account_id="acct", access="token")

    monkeypatch.setattr(
        "nanobot.providers.openai_codex_provider.get_codex_token",
        fake_token,
    )

    async def fake_request(
        url,
        headers,
        body,
        verify,
        proxy=None,
        on_content_delta=None,
        on_thinking_delta=None,
        on_tool_call_delta=None,
    ):
        _ = url, headers, verify, proxy, on_tool_call_delta
        assert body["reasoning"] == {"summary": "auto", "effort": "medium"}
        if on_content_delta:
            await on_content_delta("answer")
        if on_thinking_delta:
            await on_thinking_delta("summary")
        return provider_base.LLMResponse(
            content="answer",
            finish_reason="stop",
            usage=provider_base.LLMUsage.reported(input_tokens=10, output_tokens=5),
            reasoning_content="summary",
        )

    monkeypatch.setattr("nanobot.providers.openai_codex_provider._request_codex", fake_request)

    provider = OpenAICodexProvider()
    content_deltas: list[str] = []
    thinking_deltas: list[str] = []

    response = await provider.chat_stream(
        [{"role": "user", "content": "hi"}],
        reasoning_effort="medium",
        on_content_delta=lambda delta: _append(content_deltas, delta),
        on_thinking_delta=lambda delta: _append(thinking_deltas, delta),
    )

    assert content_deltas == ["answer"]
    assert thinking_deltas == ["summary"]
    assert response.content == "answer"
    try:
        import asyncio as _gr_asyncio
        response = await _gr_asyncio.to_thread(gr_check, response, "llm", "agent", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:db605a4de6b71e5dd4f6c8178b480766c571874d909985a85b511558827f9430')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        response = response
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'llm->agent' — passing data through unchecked")
    assert response.usage == provider_base.LLMUsage.reported(input_tokens=10, output_tokens=5)
    assert response.reasoning_content == "summary"


async def _append(target: list[str], value: str) -> None:
    target.append(value)
