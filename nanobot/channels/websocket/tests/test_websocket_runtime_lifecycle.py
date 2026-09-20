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
import errno
from unittest.mock import AsyncMock, MagicMock

import pytest

from nanobot.bus.queue import MessageBus
from nanobot.channels.websocket.runtime import WebSocketChannel


class _FakeSocket:
    def __init__(self) -> None:
        self.open = True

    def fileno(self) -> int:
        return 1 if self.open else -1

    def getsockopt(self, _level: int, _option: int) -> int:
        return int(self.open)


class _FakeServer:
    def __init__(self) -> None:
        self.socket = _FakeSocket()
        self.closed = False

    @property
    def sockets(self) -> tuple[_FakeSocket, ...]:
        return (self.socket,)

    def is_serving(self) -> bool:
        return not self.closed

    def close(self) -> None:
        self.closed = True
        self.socket.open = False

    async def wait_closed(self) -> None:
        return None


def _channel() -> WebSocketChannel:
    gateway = MagicMock()
    gateway.session_manager = None
    gateway.http.settings_routes.close = AsyncMock()
    return WebSocketChannel(
        {"enabled": True, "allowFrom": ["*"]},
        MessageBus(),
        gateway=gateway,
    )


@pytest.mark.asyncio
async def test_websocket_does_not_report_running_before_bind_succeeds(monkeypatch) -> None:
    channel = _channel()
    channel.logger = MagicMock()
    bind_error = OSError(errno.EADDRINUSE, "address already in use")

    async def fail_bind(*_args, **_kwargs):
        raise bind_error

    monkeypatch.setattr("nanobot.channels.websocket.runtime.serve", fail_bind)

    with pytest.raises(OSError) as exc_info:
        await channel.start()

    assert exc_info.value is bind_error
    assert channel.is_running is False
    assert not any(
        call.args and call.args[0] == "WebSocket server listening on {}"
        for call in channel.logger.info.call_args_list
    )


@pytest.mark.asyncio
async def test_websocket_restarts_only_its_listener_after_serving_socket_is_lost(
    monkeypatch,
) -> None:
    channel = _channel()
    first = _FakeServer()
    second = _FakeServer()
    servers = iter((first, second))
    bind_count = 0
    rebound = asyncio.Event()

    async def bind(*_args, **_kwargs):
        nonlocal bind_count
        bind_count += 1
        server = next(servers)
        if bind_count == 2:
            rebound.set()
        try:
            import asyncio as _gr_asyncio
            server = await _gr_asyncio.to_thread(gr_check, server, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:2ee12c978c44a91a3631ba3c01bedef4d7461a20b2eed476131e114eac2ab1ba')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            server = server
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        return server

    monkeypatch.setattr("nanobot.channels.websocket.runtime.serve", bind)
    monkeypatch.setattr(
        "nanobot.channels.websocket.runtime._LISTENER_CHECK_INTERVAL_S",
        0.01,
    )
    monkeypatch.setattr(
        "nanobot.channels.websocket.runtime._LISTENER_RESTART_BACKOFF_S",
        (0.05,),
    )

    start_task = asyncio.create_task(channel.start())
    try:
        for _ in range(20):
            if channel.is_running:
                break
            await asyncio.sleep(0)
        assert channel.is_running is True

        first.socket.open = False
        for _ in range(50):
            if not channel.is_running:
                break
            await asyncio.sleep(0.005)

        assert channel.is_running is False
        assert bind_count == 1
        await asyncio.wait_for(rebound.wait(), timeout=1)
        assert channel.is_running is True
        assert first.closed is True
    finally:
        await channel.stop()
        await start_task

    assert second.closed is True
