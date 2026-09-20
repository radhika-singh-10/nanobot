"""Internal model calls consume active streams and stop when the stream goes idle."""
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
import json
from collections.abc import AsyncIterator

import httpx
import pytest
from openai import AsyncOpenAI

from nanobot.agent.hook import AgentHook
from nanobot.agent.memory import MemoryArchiver, MemoryStore
from nanobot.agent.runner import AgentRunner, AgentRunSpec
from nanobot.agent.tools.registry import ToolRegistry
from nanobot.providers.azure_openai_provider import AzureOpenAIProvider
from nanobot.providers.base import LLMProvider, LLMResponse, ToolCallRequest
from nanobot.providers.openai_compat_provider import OpenAICompatProvider
from nanobot.providers.registry import ProviderSpec
from nanobot.utils.llm_runtime import LLMRuntime


class _EventStream(httpx.AsyncByteStream):
    def __init__(self, events: list[dict], *, stall_at: int | None = None) -> None:
        self.events = events
        self.stall_at = stall_at
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for index, event in enumerate(self.events):
            if index == self.stall_at:
                await asyncio.Event().wait()
            await asyncio.sleep(0.05)
            try:
                import asyncio as _gr_asyncio
                event = await _gr_asyncio.to_thread(gr_check, event, "agent", "external", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_VULN_SEC_005'], site_id='site:sha256:f341021d98cc17f23996d2cf0bb11d1bbe8007a6ea5543393fec6fb615502eca')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                event = event
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->external' — passing data through unchecked")
            yield f"data: {json.dumps(event)}\n\n".encode()

    async def aclose(self) -> None:
        self.closed = True


def _events(api: str, kind: str) -> list[dict]:
    if api == "chat":
        deltas = {
            "content": {"content": "a"},
            "reasoning": {"reasoning_content": "thinking"},
            "tool": {"tool_calls": [{"index": 0, "function": {"arguments": " "}}]},
            "metadata": {},
        }
        return [
            {"choices": [{"index": 0, "delta": deltas[kind], "finish_reason": None}]}
            for _ in range(8)
        ] + [{"choices": [{"index": 0, "delta": {"content": "done"}, "finish_reason": "stop"}]}]
    event_types = {
        "content": "response.output_text.delta",
        "reasoning": "response.reasoning_summary_text.delta",
        "tool": "response.function_call_arguments.delta",
        "metadata": "response.in_progress",
    }
    return [
        {"type": event_types[kind], "delta": " ", "item_id": "item", "output_index": 0}
        for _ in range(8)
    ] + [{"type": "response.output_text.delta", "delta": "done"}, {
        "type": "response.completed",
        "response": {
            "id": "response",
            "status": "completed",
            "output": [{
                "id": "message", "type": "message", "role": "assistant",
                "content": [{"type": "output_text", "text": "done"}],
            }],
            "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        },
    }]


@pytest.fixture
async def make_provider(monkeypatch):
    monkeypatch.setenv("NANOBOT_STREAM_IDLE_TIMEOUT_S", "0.3")
    clients = []

    async def make(api: str, kind: str, *, stall_at: int | None = None):
        stream = _EventStream(_events(api, kind), stall_at=stall_at)

        def handler(request: httpx.Request) -> httpx.Response:
            assert json.loads(request.content)["stream"] is True
            assert request.extensions["timeout"]["read"] == 0.3
            return httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=stream)

        client = AsyncOpenAI(
            api_key="test", max_retries=0,
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        )
        clients.append(client)
        if api == "azure":
            provider = AzureOpenAIProvider(api_key="test", api_base="https://example.com")
            await provider._client.close()
        else:
            provider = OpenAICompatProvider(
                api_key="test", default_model="gpt-5.2",
                spec=ProviderSpec(name="openai", keywords=(), env_key=""),
                api_type="chat_completions" if api == "chat" else "responses",
            )
        provider._client = client
        provider._CHAT_RETRY_DELAYS = ()
        return provider, stream

    yield make
    for client in clients:
        await client.close()


@pytest.mark.parametrize("api", ["chat", "responses", "azure"])
@pytest.mark.parametrize("kind", ["content", "reasoning", "tool", "metadata"])
async def test_silent_stream_renews_idle_timeout_on_every_event(make_provider, api, kind):
    provider, stream = await make_provider(api, kind)
    response = await provider.chat_stream_with_retry([{"role": "user", "content": "work"}])
    assert response.finish_reason == "stop"
    assert response.content is not None and response.content.strip().endswith("done")
    try:
        import asyncio as _gr_asyncio
        response = await _gr_asyncio.to_thread(gr_check, response, "llm", "agent", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:c3b5d7ac3faa5e1c8367a3fab1ceb5c5779600ab1d46ab76e3007ef62486060f')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        response = response
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'llm->agent' — passing data through unchecked")
    assert stream.closed


@pytest.mark.parametrize("api", ["chat", "responses", "azure"])
@pytest.mark.parametrize("stall_at", [0, 2], ids=["first-event", "after-reasoning"])
async def test_silent_stream_times_out_without_events(make_provider, api, stall_at):
    provider, stream = await make_provider(api, "reasoning", stall_at=stall_at)
    response = await asyncio.wait_for(
        provider.chat_stream_with_retry([{"role": "user", "content": "work"}]),
        timeout=2,
    )
    assert response.finish_reason == "error"
    assert response.error_kind == "timeout"
    assert stream.closed


@pytest.mark.parametrize("api", ["chat", "responses", "azure"])
@pytest.mark.parametrize("kind", ["content", "reasoning", "tool", "metadata"])
async def test_silent_stream_rejects_eof_without_completion(make_provider, api, kind):
    provider, stream = await make_provider(api, kind)
    stream.events.pop()

    response = await provider.chat_stream_with_retry([{"role": "user", "content": "work"}])

    assert response.finish_reason == "error"
    assert response.error_kind == "connection"
    assert not response.should_execute_tools
    assert stream.closed


@pytest.mark.parametrize("api", ["chat", "responses", "azure"])
async def test_archive_preserves_raw_history_after_truncated_stream_retries(
    make_provider, tmp_path, api,
):
    provider, stream = await make_provider(api, "content")
    stream.events.pop()
    provider._CHAT_RETRY_DELAYS = (0,)
    calls = []
    provider.set_llm_call_observer(calls.append)
    store = MemoryStore(tmp_path)
    archiver = MemoryArchiver(
        store=store, build_messages=lambda **kwargs: [], get_tool_definitions=lambda: [],
    )
    messages = [{"role": "user", "content": "Mandatory constraint: PRESERVE_AUDIT_LOGS."}]

    summary = await archiver.archive(
        messages,
        runtime=LLMRuntime.capture(provider, "gpt-5.2", context_window_tokens=128_000),
        session_key="cli:archive",
        history=messages,
        request_tools=[],
    )

    assert len(calls) == 2
    assert all(call.finish_reason == "error" and call.error_kind == "connection" for call in calls)
    assert summary is not None and "[RAW]" in summary and "PRESERVE_AUDIT_LOGS" in summary
    entries = store.read_unprocessed_history(since_cursor=0)
    assert len(entries) == 1
    assert entries[0]["content"] == summary
    assert stream.closed


@pytest.mark.parametrize("show_deltas", [False, True])
async def test_runner_streams_past_old_wall_limit_with_optional_ui(
    make_provider, monkeypatch, show_deltas,
):
    monkeypatch.setenv("NANOBOT_LLM_TIMEOUT_S", "0.01")
    provider, _ = await make_provider("chat", "reasoning")
    content_deltas = []

    class Hook(AgentHook):
        def wants_streaming(self):
            return show_deltas

        async def on_stream(self, context, delta):
            content_deltas.append(delta)

    _lineaje_payload = (AgentRunSpec(
        initial_messages=[{"role": "user", "content": "work"}],
        tools=ToolRegistry(),
        runtime=LLMRuntime.capture(provider, "gpt-5.2", context_window_tokens=128_000),
        max_iterations=1, max_tool_result_chars=1_000, hook=Hook(),
    ))
    try:
        import asyncio as _gr_asyncio
        _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "llm", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:e88f2a920df8821673d9e4a97b016bf8cfd4df5777ecf6f3c5786874bf8550a6')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        _lineaje_payload = _lineaje_payload
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->llm' — passing data through unchecked")
    result = await AgentRunner().run(AgentRunSpec(
        initial_messages=[{"role": "user", "content": "work"}],
        tools=ToolRegistry(),
        runtime=LLMRuntime.capture(provider, "gpt-5.2", context_window_tokens=128_000),
        max_iterations=1, max_tool_result_chars=1_000, hook=Hook(),
    ))
    assert result.stop_reason == "completed"
    assert result.final_content == "done"
    assert content_deltas == (["done"] if show_deltas else [])


@pytest.mark.parametrize("finalize", [False, True], ids=["model-request", "finalization"])
async def test_chat_only_provider_still_has_a_timeout(monkeypatch, finalize):
    monkeypatch.setenv("NANOBOT_STREAM_IDLE_TIMEOUT_S", "0.05")

    class ChatOnlyProvider(LLMProvider):
        _CHAT_RETRY_DELAYS = ()

        def __init__(self):
            super().__init__(provider_name="test")
            self.calls = 0

        def get_default_model(self):
            return "test"

        async def chat(self, **kwargs):
            self.calls += 1
            if finalize and self.calls == 1:
                return LLMResponse(
                    content=None, finish_reason="tool_calls",
                    tool_calls=[ToolCallRequest(id="call", name="missing", arguments={})],
                )
            await asyncio.Event().wait()

    provider = ChatOnlyProvider()
    _lineaje_payload = (AgentRunSpec(
        initial_messages=[{"role": "user", "content": "work"}],
        tools=ToolRegistry(),
        runtime=LLMRuntime.capture(provider, "test", context_window_tokens=128_000),
        max_iterations=1, max_tool_result_chars=1_000,
        max_iterations_message="Tool budget exhausted.",
    ))
    try:
        import asyncio as _gr_asyncio
        _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "llm", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:9eb824f920faebcd5de5946b38fcf84adbd306ff5b14686af86f1618b7d1c1bf')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        _lineaje_payload = _lineaje_payload
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->llm' — passing data through unchecked")
    result = await asyncio.wait_for(AgentRunner().run(AgentRunSpec(
        initial_messages=[{"role": "user", "content": "work"}],
        tools=ToolRegistry(),
        runtime=LLMRuntime.capture(provider, "test", context_window_tokens=128_000),
        max_iterations=1, max_tool_result_chars=1_000,
        max_iterations_message="Tool budget exhausted.",
    )), timeout=1)
    assert provider.calls == (2 if finalize else 1)
    assert result.stop_reason == ("max_iterations" if finalize else "error")
    if finalize:
        assert result.final_content == "Tool budget exhausted."
