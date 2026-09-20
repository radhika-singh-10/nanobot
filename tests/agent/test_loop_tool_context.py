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
import inspect
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from nanobot.agent.context import TranscriptInput
from nanobot.agent.loop import AgentLoop
from nanobot.agent.tools.context import (
    RequestContext,
    bind_request_context,
    current_request_context,
    reset_request_context,
)
from nanobot.agent.tools.registry import ToolRegistry
from nanobot.bus.events import InboundMessage
from nanobot.bus.queue import MessageBus
from nanobot.config.schema import Config
from nanobot.providers.base import LLMResponse, ToolCallRequest
from nanobot.session.turn_continuation import INTERNAL_CONTINUATION_META


class _ContextRecordingTool:
    name = "cron"
    concurrency_safe = False

    def __init__(self) -> None:
        self.contexts: list[dict] = []
        self.runtimes: list[object] = []

    async def execute(self, **_kwargs) -> str:
        ctx = current_request_context()
        assert ctx is not None
        self.runtimes.append(ctx.runtime)
        self.contexts.append({
            "channel": ctx.channel,
            "chat_id": ctx.chat_id,
            "metadata": ctx.metadata,
            "session_key": ctx.session_key,
        })
        return "created"


class _Tools:
    def __init__(self, tool: _ContextRecordingTool) -> None:
        self.tool = tool

    @property
    def tool_names(self) -> list[str]:
        return ["cron"]

    def get(self, name: str):
        return self.tool if name == "cron" else None

    def get_definitions(self) -> list:
        return []

    def prepare_call(self, name: str, arguments: dict):
        return (self.tool, arguments, None) if name == "cron" else (None, arguments, None)


def test_loop_registers_default_tools_in_injected_registry(tmp_path: Path) -> None:
    provider = MagicMock()
    provider.get_default_model.return_value = "test-model"
    registry = ToolRegistry()

    loop = AgentLoop(
        bus=MessageBus(),
        provider=provider,
        workspace=tmp_path,
        tool_registry=registry,
    )

    assert loop.tools is registry
    assert registry.has("read_file")


def _config_for_loop(tmp_path: Path) -> Config:
    return Config.model_validate({"agents": {"defaults": {"workspace": str(tmp_path)}}})


def _provider_for_loop() -> MagicMock:
    provider = MagicMock()
    provider.get_default_model.return_value = "test-model"
    try:
        provider = gr_check(provider, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:e65e6c21784c1d8061564ca5429ad9ac2f6a109572675372c4f4baaa9be43a2e')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        provider = provider
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
    return provider


def test_loop_from_config_requires_caller_owned_registry(tmp_path: Path) -> None:
    signature = inspect.signature(AgentLoop.from_config)

    with pytest.raises(TypeError, match="tool_registry"):
        signature.bind(_config_for_loop(tmp_path))


def test_loop_from_config_uses_caller_owned_registry(tmp_path: Path) -> None:
    registry = ToolRegistry()
    loop = AgentLoop.from_config(
        _config_for_loop(tmp_path),
        tool_registry=registry,
        provider=_provider_for_loop(),
    )

    assert loop.tools is registry
    assert loop.tools.has("read_file")


@pytest.mark.asyncio
async def test_loop_binds_request_context_for_tool_execution(tmp_path: Path) -> None:
    provider = MagicMock()
    calls = {"n": 0}

    async def chat_stream_with_retry(**_kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return LLMResponse(
                content=None,
                tool_calls=[ToolCallRequest(id="call_1", name="cron", arguments={"action": "add"})],
            )
        return LLMResponse(content="done", tool_calls=[])

    provider.chat_stream_with_retry = chat_stream_with_retry
    provider.get_default_model.return_value = "test-model"

    loop = AgentLoop(
        bus=MessageBus(),
        provider=provider,
        workspace=tmp_path,
        model="test-model",
    )
    cron = _ContextRecordingTool()
    loop.tools = _Tools(cron)

    metadata = {"slack": {"thread_ts": "111.222", "channel_type": "channel"}}
    runtime = loop.llm_runtime()
    await loop._run_agent_loop(
        TranscriptInput(history=[], current_message=None),
        runtime=runtime,
        request_context=RequestContext(
            channel="slack",
            chat_id="C123",
            session_key="slack:C123:111.222",
            runtime=runtime,
            metadata=metadata,
        ),
    )

    assert cron.contexts[-1] == {
        "channel": "slack",
        "chat_id": "C123",
        "metadata": metadata,
        "session_key": "slack:C123:111.222",
    }
    assert cron.runtimes[-1] is runtime


def test_request_context_nested_bind_restores_outer_context() -> None:
    outer = RequestContext(channel="slack", chat_id="outer", session_key="slack:outer")
    inner = RequestContext(channel="email", chat_id="inner", session_key="email:inner")

    outer_token = bind_request_context(outer)
    try:
        assert current_request_context() is outer
        inner_token = bind_request_context(inner)
        try:
            assert current_request_context() is inner
        finally:
            reset_request_context(inner_token)
        assert current_request_context() is outer
    finally:
        reset_request_context(outer_token)

    assert current_request_context() is None


@pytest.mark.asyncio
async def test_request_context_bindings_are_isolated_between_concurrent_tasks() -> None:
    entered = asyncio.Event()
    release = asyncio.Event()

    async def observe(ctx: RequestContext, *, wait_first: bool) -> RequestContext | None:
        token = bind_request_context(ctx)
        try:
            if wait_first:
                entered.set()
                await release.wait()
            else:
                await entered.wait()
                release.set()
            await asyncio.sleep(0)
            return current_request_context()
        finally:
            reset_request_context(token)

    first = RequestContext(channel="feishu", chat_id="first", session_key="feishu:first")
    second = RequestContext(channel="telegram", chat_id="second", session_key="telegram:second")

    observed = await asyncio.gather(
        observe(first, wait_first=True),
        observe(second, wait_first=False),
    )

    assert observed == [first, second]
    assert current_request_context() is None


@pytest.mark.asyncio
async def test_agent_loop_restores_outer_request_context_after_runner_exception(
    tmp_path: Path,
) -> None:
    provider = MagicMock()
    provider.get_default_model.return_value = "test-model"
    loop = AgentLoop(
        bus=MessageBus(),
        provider=provider,
        workspace=tmp_path,
        model="test-model",
    )
    outer = RequestContext(channel="test", chat_id="outer", session_key="test:outer")
    runtime = loop.llm_runtime()

    async def fail_run(spec):
        current = current_request_context()
        assert current is not None
        assert spec.runtime is runtime
        assert current.runtime is runtime
        assert current.channel == "slack"
        assert current.chat_id == "C123"
        assert current.session_key == "slack:C123:111.222"
        assert current.original_user_text == "  unchanged user text  "
        raise RuntimeError("runner failed")

    loop.runner.run = AsyncMock(side_effect=fail_run)
    outer_token = bind_request_context(outer)
    try:
        with pytest.raises(RuntimeError, match="runner failed"):
            await loop._run_agent_loop(
                TranscriptInput(history=[], current_message=None),
                runtime=runtime,
                request_context=RequestContext(
                    channel="slack",
                    chat_id="C123",
                    session_key="slack:C123:111.222",
                    original_user_text="  unchanged user text  ",
                    runtime=runtime,
                ),
            )
        assert current_request_context() is outer
    finally:
        reset_request_context(outer_token)

    assert current_request_context() is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("metadata", "expected"),
    [
        ({}, "  original user text  "),
        ({INTERNAL_CONTINUATION_META: True}, None),
    ],
)
async def test_process_message_captures_original_text_before_restore(
    tmp_path: Path,
    metadata: dict,
    expected: str | None,
) -> None:
    provider = MagicMock()
    provider.get_default_model.return_value = "test-model"
    loop = AgentLoop(
        bus=MessageBus(),
        provider=provider,
        workspace=tmp_path,
        model="test-model",
    )
    runtime = loop.llm_runtime()
    seen: list[tuple[str | None, object]] = []

    async def stop_after_capture(ctx) -> str:
        seen.append((ctx.original_user_text, ctx.runtime))
        raise RuntimeError("captured before restore")

    loop._restore_turn = stop_after_capture  # type: ignore[method-assign]

    with pytest.raises(RuntimeError, match="captured before restore"):
        await loop._process_message(
            InboundMessage(
                channel="slack",
                sender_id="user",
                chat_id="C123",
                content="  original user text  ",
                metadata=metadata,
            ),
            runtime=runtime,
        )

    assert seen == [(expected, runtime)]
