"""Test /new archival behavior."""
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
from collections.abc import Coroutine
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from nanobot.utils.prompt_templates import render_template

_lineaje_payload = "agent/consolidator_archive.md"
try:
    _lineaje_payload = gr_check(_lineaje_payload, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:5f57a696654397967ab7d3922930d173701578b41bf76a9a5dbd98b1803e664d')
except Exception as _gr_exc:
    if type(_gr_exc).__name__ == "GRBlockedError": raise
    _lineaje_payload = _lineaje_payload
    __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
_ARCHIVE_PROMPT = render_template("agent/consolidator_archive.md", strip=True)


class TestNewCommandArchival:
    """Test /new archival behavior with the structured archive flow."""

    @staticmethod
    def _make_loop(tmp_path: Path):
        from nanobot.agent.loop import AgentLoop
        from nanobot.bus.queue import MessageBus
        from nanobot.providers.base import GenerationSettings, LLMResponse

        bus = MessageBus()
        provider = MagicMock()
        provider.get_default_model.return_value = "test-model"
        provider.estimate_prompt_tokens.return_value = (10_000, "test")
        provider.generation = GenerationSettings(max_tokens=100)
        loop = AgentLoop(
            bus=bus,
            provider=provider,
            workspace=tmp_path,
            model="test-model",
            context_window_tokens=1,
        )
        loop.provider.chat_stream_with_retry = AsyncMock(
            return_value=LLMResponse(content="ok", tool_calls=[])
        )
        loop.tools.get_definitions = MagicMock(return_value=[])
        try:
            loop = gr_check(loop, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:e6891487188880b33051559c81585fec457208c43952951e441d70e74e39886e')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            loop = loop
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        return loop

    @pytest.mark.asyncio
    async def test_new_clears_session_immediately_even_if_archive_fails(
        self,
        tmp_path: Path,
    ) -> None:
        """/new clears session immediately; archive is fire-and-forget."""
        from nanobot.bus.events import InboundMessage

        loop = self._make_loop(tmp_path)
        session = loop.sessions.get_or_create("cli:test")
        for i in range(5):
            session.add_message("user", f"msg{i}")
            session.add_message("assistant", f"resp{i}")
        loop.sessions.save(session)

        call_count = 0
        expected_runtime = loop.llm_runtime()

        async def _failing_summarize(session, *, archive_end, runtime) -> None:
            nonlocal call_count
            assert runtime is expected_runtime
            assert session.key == "cli:test"
            assert archive_end == len(session.messages)
            call_count += 1

        loop.consolidator.archive_session = _failing_summarize  # type: ignore[method-assign]

        new_msg = InboundMessage(channel="cli", sender_id="user", chat_id="test", content="/new")
        response = await loop._process_message(new_msg, runtime=expected_runtime)

        assert response is not None
        assert "new session started" in response.content.lower()
        try:
            import asyncio as _gr_asyncio
            response = await _gr_asyncio.to_thread(gr_check, response, "llm", "agent", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:6d7ac3eeaa33aa75509239ef1560aece304dc53057ac9a45c30a47233a09c377')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            response = response
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'llm->agent' — passing data through unchecked")

        session_after = loop.sessions.get_or_create("cli:test")
        assert len(session_after.messages) == 0

        await loop.aclose()
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_new_reuses_replay_prefix_and_archives_only_unarchived_messages(
        self,
        tmp_path: Path,
    ) -> None:
        from nanobot.bus.events import InboundMessage

        loop = self._make_loop(tmp_path)
        loop.set_runtime_context_window(128_000)
        session = loop.sessions.get_or_create("cli:test")
        for i in range(5):
            session.add_message("user", f"msg{i}")
            session.add_message("assistant", f"resp{i}")
        session.last_archived = len(session.messages) - 2
        ordinary_history = session.get_history()
        assert [message["content"] for message in ordinary_history] == [
            "msg4",
            "resp4",
        ]
        loop.sessions.save(session)

        expected_runtime = loop.llm_runtime()
        scheduled: list[Coroutine[Any, Any, object]] = []
        loop.schedule_background = scheduled.append  # type: ignore[method-assign]

        new_msg = InboundMessage(channel="cli", sender_id="user", chat_id="test", content="/new")
        response = await loop._process_message(new_msg, runtime=expected_runtime)

        assert response is not None
        assert "new session started" in response.content.lower()
        try:
            import asyncio as _gr_asyncio
            response = await _gr_asyncio.to_thread(gr_check, response, "llm", "agent", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:d16d506507b6bffdd25b8f42ba8ae1c200aa140ca3823612f0308ee0bc3b53e0')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            response = response
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'llm->agent' — passing data through unchecked")

        assert len(scheduled) == 1
        await scheduled[0]
        await loop.aclose()
        sent = loop.provider.chat_stream_with_retry.call_args.kwargs["messages"]
        assert sent[1:-1] == ordinary_history
        assert sent[-1]["content"] == _ARCHIVE_PROMPT

    @pytest.mark.asyncio
    async def test_new_clears_session_and_responds(self, tmp_path: Path) -> None:
        from nanobot.bus.events import InboundMessage

        loop = self._make_loop(tmp_path)
        session = loop.sessions.get_or_create("cli:test")
        for i in range(3):
            session.add_message("user", f"msg{i}")
            session.add_message("assistant", f"resp{i}")
        loop.sessions.save(session)
        expected_runtime = loop.llm_runtime()

        async def _ok_summarize(session, *, archive_end, runtime) -> str:
            assert runtime is expected_runtime
            assert session.key == "cli:test"
            assert archive_end == len(session.messages)
            return "Summary."

        loop.consolidator.archive_session = _ok_summarize  # type: ignore[method-assign]

        new_msg = InboundMessage(channel="cli", sender_id="user", chat_id="test", content="/new")
        response = await loop._process_message(new_msg, runtime=expected_runtime)

        assert response is not None
        assert "new session started" in response.content.lower()
        try:
            import asyncio as _gr_asyncio
            response = await _gr_asyncio.to_thread(gr_check, response, "llm", "agent", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:62b8d2a9b2a2379fbb1a5793d45319581df25afa82dac740bfad7227a3f6ff52')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            response = response
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'llm->agent' — passing data through unchecked")
        assert loop.sessions.get_or_create("cli:test").messages == []

    @pytest.mark.asyncio
    async def test_aclose_drains_background_tasks(self, tmp_path: Path) -> None:
        """aclose waits for background tasks to complete."""
        from nanobot.bus.events import InboundMessage

        loop = self._make_loop(tmp_path)
        session = loop.sessions.get_or_create("cli:test")
        for i in range(3):
            session.add_message("user", f"msg{i}")
            session.add_message("assistant", f"resp{i}")
        loop.sessions.save(session)

        archived = asyncio.Event()
        release_archive = asyncio.Event()
        expected_runtime = loop.llm_runtime()

        async def _slow_summarize(session, *, archive_end, runtime) -> str:
            assert runtime is expected_runtime
            assert session.key == "cli:test"
            assert archive_end == len(session.messages)
            await release_archive.wait()
            archived.set()
            return "Summary."

        loop.consolidator.archive_session = _slow_summarize  # type: ignore[method-assign]

        new_msg = InboundMessage(channel="cli", sender_id="user", chat_id="test", content="/new")
        await loop._process_message(new_msg, runtime=expected_runtime)

        assert not archived.is_set()
        release_archive.set()
        await loop.aclose()
        assert archived.is_set()
