"""Tests for runner progress hooks and provider event routing."""
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
from unittest.mock import AsyncMock, MagicMock

import pytest

from agent.runner_helpers import make_run_spec
from nanobot.agent.hooks import FileEditActivityHook
from nanobot.agent.progress_hook import AgentProgressHook
from nanobot.agent.runner import AgentRunner
from nanobot.agent.tools.apply_patch import ApplyPatchTool
from nanobot.agent.tools.filesystem import EditFileTool, WriteFileTool
from nanobot.config.schema import AgentDefaults
from nanobot.providers.base import LLMResponse, ToolCallRequest
from nanobot.utils.file_edit_events import Indel
from nanobot.utils.progress_events import output_events

_MAX_TOOL_RESULT_CHARS = AgentDefaults().max_tool_result_chars


@pytest.mark.asyncio
async def test_runner_routes_hosted_tool_events_to_structured_progress():
    provider = MagicMock()

    async def chat_stream_with_retry(*, on_content_delta, on_tool_call_delta, **kwargs):
        await on_tool_call_delta({
            "call_id": "local-call",
            "name": "read_file",
            "arguments_delta": "",
        })
        await on_tool_call_delta({
            "kind": "hosted_tool",
            "phase": "start",
            "call_id": "x-search-1",
            "name": "x_search",
            "arguments": {"query": "nanobot oauth"},
            "result": None,
        })
        await on_tool_call_delta({
            "kind": "hosted_tool",
            "phase": "end",
            "call_id": "x-search-1",
            "name": "x_search",
            "arguments": {"query": "nanobot oauth"},
            "result": {"name": "x_semantic_search"},
        })
        await on_content_delta("done")
        return LLMResponse(content="done", tool_calls=[], usage=None)

    provider.chat_stream_with_retry = chat_stream_with_retry
    provider.chat_with_retry = AsyncMock()
    tools = MagicMock()
    tools.get_definitions.return_value = []
    progress_events: list[dict] = []
    progress_text: list[str] = []
    streamed_text: list[str] = []

    async def progress_cb(content, *, tool_events=None, **kwargs):
        progress_text.append(content)
        if tool_events:
            progress_events.extend(tool_events)

    async def stream_cb(content: str) -> None:
        streamed_text.append(content)

    hook = AgentProgressHook(output_events(on_progress=progress_cb, on_stream=stream_cb), streaming=True)
    result = await AgentRunner().run(make_run_spec(
        provider,
        initial_messages=[{"role": "user", "content": "search X"}],
        tools=tools,
        model="test-model",
        max_iterations=1,
        max_tool_result_chars=_MAX_TOOL_RESULT_CHARS,
        hook=hook,
    ))

    assert result.final_content == "done"
    assert result.tools_used == []
    assert result.tool_events == []
    assert progress_events == [
        {
            "version": 1,
            "phase": "start",
            "call_id": "x-search-1",
            "name": "x_search",
            "arguments": {"query": "nanobot oauth"},
            "result": None,
            "error": None,
            "files": [],
            "embeds": [],
        },
        {
            "version": 1,
            "phase": "end",
            "call_id": "x-search-1",
            "name": "x_search",
            "arguments": {"query": "nanobot oauth"},
            "result": {"name": "x_semantic_search"},
            "error": None,
            "files": [],
            "embeds": [],
        },
    ]
    assert progress_text == ['search X "nanobot oauth"', ""]
    assert streamed_text == ["done"]
    provider.chat_with_retry.assert_not_awaited()


@pytest.mark.asyncio
async def test_runner_fails_pending_hosted_tool_when_model_request_fails():
    provider = MagicMock()

    async def chat_stream_with_retry(*, on_tool_call_delta, **kwargs):
        await on_tool_call_delta({
            "kind": "hosted_tool",
            "phase": "start",
            "call_id": "x-search-failed",
            "name": "x_search",
            "arguments": {"query": "nanobot oauth"},
            "result": None,
        })
        return LLMResponse(
            content="hosted search backend failed",
            finish_reason="error",
        )

    provider.chat_stream_with_retry = chat_stream_with_retry
    provider.chat_with_retry = AsyncMock()
    tools = MagicMock()
    tools.get_definitions.return_value = []
    progress_events: list[dict] = []

    async def progress_cb(content, *, tool_events=None, **kwargs):
        if tool_events:
            progress_events.extend(tool_events)

    async def stream_cb(_content: str) -> None:
        pass

    hook = AgentProgressHook(output_events(on_progress=progress_cb, on_stream=stream_cb), streaming=True)
    _lineaje_payload = (make_run_spec(
        provider,
        initial_messages=[{"role": "user", "content": "search X"}],
        tools=tools,
        model="test-model",
        max_iterations=1,
        max_tool_result_chars=_MAX_TOOL_RESULT_CHARS,
        hook=hook,
    ))
    try:
        import asyncio as _gr_asyncio
        _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "llm", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:a7adaeb7eda637b44f28b9072ef9ef5937b36a81ef5523791de876d694ac3c81')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        _lineaje_payload = _lineaje_payload
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->llm' — passing data through unchecked")
    result = await AgentRunner().run(make_run_spec(
        provider,
        initial_messages=[{"role": "user", "content": "search X"}],
        tools=tools,
        model="test-model",
        max_iterations=1,
        max_tool_result_chars=_MAX_TOOL_RESULT_CHARS,
        hook=hook,
    ))

    assert result.stop_reason == "error"
    assert [(event["phase"], event["call_id"]) for event in progress_events] == [
        ("start", "x-search-failed"),
        ("error", "x-search-failed"),
    ]
    assert progress_events[-1] == {
        "version": 1,
        "phase": "error",
        "call_id": "x-search-failed",
        "name": "x_search",
        "arguments": {"query": "nanobot oauth"},
        "result": None,
        "error": "hosted search backend failed",
        "files": [],
        "embeds": [],
    }
    provider.chat_with_retry.assert_not_awaited()


@pytest.mark.asyncio
async def test_runner_emits_write_file_diff_from_tool_execution_snapshots(tmp_path, monkeypatch):
    provider = MagicMock()
    call_count = 0
    progress_events: list[dict] = []
    (tmp_path / "big.txt").write_text("old\n", encoding="utf-8")

    async def progress_cb(content, *, file_edit_events=None, **kwargs):
        if file_edit_events:
            progress_events.extend(file_edit_events)

    tool = WriteFileTool(workspace=tmp_path)
    align = MagicMock(wraps=Indel.opcodes)
    monkeypatch.setattr(Indel, "opcodes", align)

    class Tools:
        def get_definitions(self):
            return [{"type": "function", "function": {"name": "write_file"}}]

        def prepare_call(self, name, params):
            return tool, params, None

    async def chat_stream_with_retry(**kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return LLMResponse(
                content=None,
                tool_calls=[
                    ToolCallRequest(
                        id="call-write",
                        name="write_file",
                        arguments={"path": "big.txt", "content": "line\n" * 24},
                    )
                ],
                usage=None,
            )
        return LLMResponse(content="done", tool_calls=[], usage=None)

    provider.chat_stream_with_retry = chat_stream_with_retry
    tools = Tools()

    runner = AgentRunner()
    result = await runner.run(make_run_spec(provider,
        initial_messages=[{"role": "user", "content": "write a large file"}],
        tools=tools,
        model="test-model",
        max_iterations=2,
        max_tool_result_chars=_MAX_TOOL_RESULT_CHARS,
        workspace=tmp_path,
        hook=FileEditActivityHook(events=output_events(on_progress=progress_cb), workspace=tmp_path),
    ))

    assert result.final_content == "done"
    assert align.call_count == 1
    assert progress_events[0]["phase"] == "start"
    assert progress_events[0]["added"] == 0
    assert progress_events[0]["deleted"] == 0
    assert any(
        not event["approximate"]
        and event["phase"] == "end"
        and event["added"] == 24
        and event["deleted"] == 1
        and event["diff"]["format"] == "unified"
        for event in progress_events
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("tool_name", ["edit_file", "apply_patch"])
async def test_runner_reuses_edit_diff_for_summary_and_progress(tmp_path, monkeypatch, tool_name):
    provider = MagicMock()
    call_count = 0
    progress_events: list[dict] = []
    target = tmp_path / "notes.txt"
    target.write_text("old\nkeep\n", encoding="utf-8")

    async def progress_cb(content, *, file_edit_events=None, **kwargs):
        if file_edit_events:
            progress_events.extend(file_edit_events)

    tool = EditFileTool(workspace=tmp_path)
    arguments = {
        "path": str(target),
        "old_text": "old\nkeep\n",
        "new_text": "new\nkeep\nextra\n",
    }
    if tool_name == "apply_patch":
        tool = ApplyPatchTool(workspace=tmp_path)
        arguments = {"edits": [
            {"path": str(target), "action": "replace", "old_text": "old", "new_text": "new"},
            {"path": str(target), "action": "add", "new_text": "extra"},
        ]}
    align = MagicMock(wraps=Indel.opcodes)
    monkeypatch.setattr(Indel, "opcodes", align)

    class Tools:
        def get_definitions(self):
            return [{"type": "function", "function": {"name": tool_name}}]

        def prepare_call(self, name, params):
            return tool, params, None

    async def chat_stream_with_retry(**kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return LLMResponse(
                content=None,
                tool_calls=[
                    ToolCallRequest(
                        id="call-edit",
                        name=tool_name,
                        arguments=arguments,
                    )
                ],
                usage=None,
            )
        return LLMResponse(content="done", tool_calls=[], usage=None)

    provider.chat_stream_with_retry = chat_stream_with_retry
    tools = Tools()

    runner = AgentRunner()
    result = await runner.run(make_run_spec(provider,
        initial_messages=[{"role": "user", "content": "edit a file"}],
        tools=tools,
        model="test-model",
        max_iterations=2,
        max_tool_result_chars=_MAX_TOOL_RESULT_CHARS,
        workspace=tmp_path,
        hook=FileEditActivityHook(events=output_events(on_progress=progress_cb), workspace=tmp_path),
    ))

    assert result.final_content == "done"
    assert align.call_count == 1
    assert target.read_text() == "new\nkeep\nextra\n"
    observation = next(m["content"] for m in result.messages if m["role"] == "tool")
    assert observation == "Patch applied:\n- update notes.txt (+2/-1)"
    assert any(
        event["tool"] == tool_name
        and not event["approximate"]
        and event["phase"] == "end"
        and event["added"] == 2
        and event["deleted"] == 1
        and event["diff"]["format"] == "unified"
        for event in progress_events
    )


@pytest.mark.asyncio
async def test_runner_marks_file_edit_activity_failed_when_tool_errors(tmp_path):
    provider = MagicMock()
    call_count = 0
    progress_events: list[dict] = []

    async def progress_cb(content, *, file_edit_events=None, **kwargs):
        if file_edit_events:
            progress_events.extend(file_edit_events)

    tool = WriteFileTool(workspace=tmp_path)

    class Tools:
        def get_definitions(self):
            return [{"type": "function", "function": {"name": "write_file"}}]

        def prepare_call(self, name, params):
            return tool, params, None

    async def chat_stream_with_retry(**kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return LLMResponse(
                content=None,
                tool_calls=[
                    ToolCallRequest(
                        id="call-write",
                        name="write_file",
                        arguments={"path": "aborted.txt"},
                    )
                ],
                usage=None,
            )
        return LLMResponse(content="done", tool_calls=[], usage=None)

    provider.chat_stream_with_retry = chat_stream_with_retry
    tools = Tools()

    runner = AgentRunner()
    result = await runner.run(make_run_spec(provider,
        initial_messages=[{"role": "user", "content": "write a file"}],
        tools=tools,
        model="test-model",
        max_iterations=2,
        max_tool_result_chars=_MAX_TOOL_RESULT_CHARS,
        workspace=tmp_path,
        hook=FileEditActivityHook(events=output_events(on_progress=progress_cb), workspace=tmp_path),
    ))

    assert result.stop_reason == "completed"
    assert progress_events[-1]["path"] == "aborted.txt"
    assert progress_events[-1]["phase"] == "error"
    assert progress_events[-1]["status"] == "error"


@pytest.mark.asyncio
async def test_runner_marks_file_edit_activity_failed_when_cancelled(tmp_path):
    provider = MagicMock()
    progress_events: list[dict] = []
    executing = asyncio.Event()
    target = tmp_path / "cancelled.txt"
    target.write_text("old\n", encoding="utf-8")

    async def progress_cb(content, *, file_edit_events=None, **kwargs):
        if file_edit_events:
            progress_events.extend(file_edit_events)

    class SlowWriteTool(WriteFileTool):
        async def execute(self, path=None, content=None, **kwargs):
            executing.set()
            await asyncio.sleep(60)
            return "ok"

    tool = SlowWriteTool(workspace=tmp_path)

    class Tools:
        def get_definitions(self):
            return [{"type": "function", "function": {"name": "write_file"}}]

        def prepare_call(self, name, params):
            return tool, params, None

    async def chat_stream_with_retry(**kwargs):
        return LLMResponse(
            content=None,
            tool_calls=[
                ToolCallRequest(
                    id="call-write",
                    name="write_file",
                    arguments={"path": "cancelled.txt", "content": "new\n"},
                )
            ],
            usage=None,
        )

    provider.chat_stream_with_retry = chat_stream_with_retry
    tools = Tools()

    runner = AgentRunner()
    task = asyncio.create_task(runner.run(make_run_spec(provider,
        initial_messages=[{"role": "user", "content": "write a file"}],
        tools=tools,
        model="test-model",
        max_iterations=2,
        max_tool_result_chars=_MAX_TOOL_RESULT_CHARS,
        workspace=tmp_path,
        hook=FileEditActivityHook(events=output_events(on_progress=progress_cb), workspace=tmp_path),
    )))
    await asyncio.wait_for(executing.wait(), timeout=1)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert [event["phase"] for event in progress_events] == ["start", "error"]
    assert progress_events[-1]["path"] == "cancelled.txt"
    assert progress_events[-1]["status"] == "error"
    assert progress_events[-1]["error"] == "Task interrupted before this tool finished."
