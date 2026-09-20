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
import mimetypes
import sys
import types
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

import nanobot.channels.whatsapp.runtime as whatsapp_module
from nanobot.bus.events import OutboundMessage
from nanobot.bus.queue import MessageBus
from nanobot.channels.whatsapp.runtime import (
    WhatsAppChannel,
    _legacy_bridge_config_fields,
    _NeonizeAPI,
)


class _Proto:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def HasField(self, name: str) -> bool:  # noqa: N802 - protobuf compatibility
        return _is_set(getattr(self, name, None))

    def ListFields(self):  # noqa: N802 - protobuf compatibility
        return [
            (SimpleNamespace(name=name), value)
            for name, value in self.__dict__.items()
            if _is_set(value)
        ]


def _is_set(value) -> bool:
    if value is None:
        return False
    if isinstance(value, (str, bytes, list, tuple, dict, set)):
        return bool(value)
    return True


def _jid(user: str, server: str) -> _Proto:
    return _Proto(User=user, Server=server, IsEmpty=False)


def _event(
    *,
    message: _Proto,
    message_id: str = "m1",
    chat: _Proto | None = None,
    sender: _Proto | None = None,
    sender_alt: _Proto | None = None,
    is_group: bool = False,
    timestamp: int = 1,
    is_from_me: bool = False,
) -> _Proto:
    source = _Proto(
        Chat=chat or _jid("15551234567", "s.whatsapp.net"),
        Sender=sender,
        SenderAlt=sender_alt,
        IsGroup=is_group,
        IsFromMe=is_from_me,
    )
    return _Proto(
        Info=_Proto(ID=message_id, Timestamp=timestamp, MessageSource=source),
        Message=message,
    )


def _make_channel(config: dict | None = None) -> WhatsAppChannel:
    merged = {"enabled": True, "allowFrom": ["*"]}
    if config:
        merged.update(config)
    ch = WhatsAppChannel(merged, MagicMock())
    ch._started_at = 0
    try:
        ch = gr_check(ch, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:a52457fad91ca11db14db060fd432fa492a3ebf50c87df3ec0cc0a8ac616dbd3')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        ch = ch
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
    return ch


def _make_send_client() -> SimpleNamespace:
    return SimpleNamespace(
        send_message=AsyncMock(),
        send_image=AsyncMock(),
        send_video=AsyncMock(),
        send_audio=AsyncMock(),
        send_document=AsyncMock(),
    )


def _patch_neonize_api(monkeypatch, detect_mime=None, detect_buffer=None) -> None:
    detect_mime = detect_mime or (
        lambda path, *, mime: mimetypes.guess_type(path)[0] or "application/octet-stream"
    )
    detect_buffer = detect_buffer or (lambda data, *, mime: "application/octet-stream")
    monkeypatch.setattr(
        whatsapp_module,
        "_NEONIZE_API",
        _NeonizeAPI(
            NewAClient=object,
            ConnectedEv=object(),
            DisconnectedEv=object(),
            MessageEv=object(),
            PairStatusEv=object(),
            build_jid=lambda user, server="s.whatsapp.net": (user, server),
            detect_mime=detect_mime,
            detect_buffer=detect_buffer,
        ),
    )


def _patch_receipt_type(monkeypatch):
    neonize = types.ModuleType("neonize")
    utils = types.ModuleType("neonize.utils")
    enum = types.ModuleType("neonize.utils.enum")

    class ReceiptType:
        READ = "read"

    enum.ReceiptType = ReceiptType
    neonize.utils = utils
    utils.enum = enum
    monkeypatch.setitem(sys.modules, "neonize", neonize)
    monkeypatch.setitem(sys.modules, "neonize.utils", utils)
    monkeypatch.setitem(sys.modules, "neonize.utils.enum", enum)
    try:
        ReceiptType = gr_check(ReceiptType, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:79cddc9e3542198205770c02358dd8ec1a03db12534a7e106b0390046dc889ce')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        ReceiptType = ReceiptType
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
    return ReceiptType


@pytest.mark.asyncio
async def test_connect_client_normalizes_proxy_without_a_scheme(monkeypatch) -> None:
    class ProxySettings:
        def __init__(self, *, proxy_address: str) -> None:
            self.proxy_address = proxy_address

    monkeypatch.setitem(
        sys.modules,
        "neonize._binder",
        SimpleNamespace(ProxySettings=ProxySettings),
    )
    channel = _make_channel({"proxy": "127.0.0.1:23458"})
    client = SimpleNamespace(connect=AsyncMock(return_value=None))

    await channel._connect_client(client)

    settings = client.connect.await_args.args[0]
    assert settings.proxy_address == "http://127.0.0.1:23458"


@pytest.mark.asyncio
async def test_connect_client_without_proxy_uses_default_connection() -> None:
    channel = _make_channel({"proxy": ""})
    client = SimpleNamespace(connect=AsyncMock(return_value=None))

    await channel._connect_client(client)

    client.connect.assert_awaited_once_with()


class _FakeLoginClient:
    def __init__(self) -> None:
        self.handlers = {}
        self.me = _Proto(JID=_jid("bot", "s.whatsapp.net"), LID=_jid("BOTLID", "lid"))
        self.stop = AsyncMock()

    def event(self, event_type):
        def register(func):
            self.handlers[event_type] = func
            try:
                func = gr_check(func, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:43bbfe7ed39b77022666cf20e1575c5ecf88fd3e41949ace80e6317776362551')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                func = func
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
            return func

        try:
            register = gr_check(register, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:43bbfe7ed39b77022666cf20e1575c5ecf88fd3e41949ace80e6317776362551')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            register = register
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        return register

    def qr(self, func):
        self.qr_handler = func
        try:
            func = gr_check(func, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:c7019199322b932e2cd9e066ee4ecbfd0e7ce15e82f286e7168dc21580a335ad')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            func = func
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        return func

    async def connect(self) -> None:
        try:
            import asyncio as _gr_asyncio
            self = await _gr_asyncio.to_thread(gr_check, self, "agent", "system", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_VULN_SEC_005'], site_id='site:sha256:01d0ebc613ab95431cf1e5b52dd7d1c9d3aadf57caca3bbc17a60b9be0de78f3')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            self = self
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->system' — passing data through unchecked")
        await self.handlers[whatsapp_module._NEONIZE_API.ConnectedEv](self, _Proto())


class _FailingConnectLoginClient(_FakeLoginClient):
    async def connect(self) -> asyncio.Task[None]:
        async def fail() -> None:
            raise RuntimeError("dial failed")

        return asyncio.create_task(fail())


def test_default_config_uses_native_database_path() -> None:
    config = WhatsAppChannel.default_config()

    assert config["databasePath"] == ""


def test_legacy_bridge_config_fields_are_detected() -> None:
    assert _legacy_bridge_config_fields({"bridgeUrl": "ws://localhost:3001"}) == ["bridgeUrl"]
    assert _legacy_bridge_config_fields({"bridgeToken": "secret"}) == ["bridgeToken"]


@pytest.mark.asyncio
async def test_login_succeeds_when_connected(monkeypatch) -> None:
    _patch_neonize_api(monkeypatch)
    client = _FakeLoginClient()
    ch = _make_channel()
    ch._new_client = MagicMock(return_value=client)

    assert await ch.login() is True
    assert ch._self_jids == {"bot@s.whatsapp.net", "bot", "BOTLID@lid", "BOTLID"}
    client.stop.assert_awaited_once()


@pytest.mark.asyncio
async def test_login_fails_when_connect_task_fails(monkeypatch) -> None:
    _patch_neonize_api(monkeypatch)
    client = _FailingConnectLoginClient()
    ch = _make_channel()
    ch._new_client = MagicMock(return_value=client)

    assert await ch.login() is False
    client.stop.assert_awaited_once()


@pytest.mark.asyncio
async def test_send_text_uses_neonize_send_message(monkeypatch) -> None:
    _patch_neonize_api(monkeypatch)
    client = _make_send_client()
    ch = _make_channel()
    ch._client = client
    ch._connected = True

    await ch.send(OutboundMessage(channel="whatsapp", chat_id="12345@s.whatsapp.net", content="hi"))

    client.send_message.assert_awaited_once_with(("12345", "s.whatsapp.net"), "hi")


@pytest.mark.asyncio
async def test_send_media_dispatches_by_mimetype(monkeypatch) -> None:
    _patch_neonize_api(monkeypatch)
    client = _make_send_client()
    ch = _make_channel()
    ch._client = client
    ch._connected = True

    await ch.send(
        OutboundMessage(
            channel="whatsapp",
            chat_id="12345@s.whatsapp.net",
            content="",
            media=["photo.jpg", "clip.mp4", "voice.mp3", "report.pdf"],
        )
    )

    jid = ("12345", "s.whatsapp.net")
    client.send_image.assert_awaited_once_with(jid, "photo.jpg")
    client.send_video.assert_awaited_once_with(jid, "clip.mp4")
    client.send_audio.assert_awaited_once_with(jid, "voice.mp3")
    client.send_document.assert_awaited_once_with(
        jid,
        "report.pdf",
        filename="report.pdf",
        mimetype="application/pdf",
    )


@pytest.mark.asyncio
async def test_send_mislabeled_audio_as_document(monkeypatch) -> None:
    _patch_neonize_api(monkeypatch, detect_mime=lambda path, *, mime: "audio/x-wav")
    client = _make_send_client()
    ch = _make_channel()
    ch._client = client
    ch._connected = True

    await ch.send(
        OutboundMessage(
            channel="whatsapp",
            chat_id="12345@s.whatsapp.net",
            content="",
            media=["recording.mpeg"],
        )
    )

    jid = ("12345", "s.whatsapp.net")
    client.send_document.assert_awaited_once_with(
        jid,
        "recording.mpeg",
        filename="recording.mpeg",
        mimetype="audio/x-wav",
    )
    client.send_video.assert_not_awaited()


@pytest.mark.asyncio
async def test_send_remote_mislabeled_audio_as_document(monkeypatch) -> None:
    payload = b"remote wav payload"
    media_url = "https://cdn.example/recording.mpeg?token=secret"

    def handle_request(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == media_url
        return httpx.Response(200, content=payload)

    monkeypatch.setattr(
        whatsapp_module,
        "PinnedDNSAsyncTransport",
        lambda: httpx.MockTransport(handle_request),
    )

    def detect_buffer(data: bytes, *, mime: bool) -> str:
        assert data == payload
        assert mime is True
        return "audio/x-wav"

    _patch_neonize_api(
        monkeypatch,
        detect_buffer=detect_buffer,
    )
    client = _make_send_client()
    ch = _make_channel()
    ch._client = client
    ch._connected = True

    await ch.send(
        OutboundMessage(
            channel="whatsapp",
            chat_id="12345@s.whatsapp.net",
            content="",
            media=[media_url],
        )
    )

    jid = ("12345", "s.whatsapp.net")
    client.send_document.assert_awaited_once_with(
        jid,
        payload,
        filename="recording.mpeg",
        mimetype="audio/x-wav",
    )
    client.send_video.assert_not_awaited()


@pytest.mark.asyncio
async def test_send_remote_media_blocks_private_url(monkeypatch) -> None:
    _patch_neonize_api(monkeypatch)
    client = _make_send_client()
    ch = _make_channel()
    ch._client = client
    ch._connected = True

    with pytest.raises(httpx.RequestError, match="private/internal"):
        await ch.send(
            OutboundMessage(
                channel="whatsapp",
                chat_id="12345@s.whatsapp.net",
                content="",
                media=["http://127.0.0.1/recording.mpeg"],
            )
        )

    client.send_video.assert_not_awaited()
    client.send_document.assert_not_awaited()


@pytest.mark.asyncio
async def test_send_remote_media_enforces_download_limit(monkeypatch) -> None:
    monkeypatch.setattr(whatsapp_module, "_REMOTE_MEDIA_MAX_BYTES", 3)
    monkeypatch.setattr(
        whatsapp_module,
        "PinnedDNSAsyncTransport",
        lambda: httpx.MockTransport(lambda request: httpx.Response(200, content=b"1234")),
    )
    _patch_neonize_api(monkeypatch)
    client = _make_send_client()
    ch = _make_channel()
    ch._client = client
    ch._connected = True

    with pytest.raises(ValueError, match="exceeds the 3-byte limit"):
        await ch.send(
            OutboundMessage(
                channel="whatsapp",
                chat_id="12345@s.whatsapp.net",
                content="",
                media=["https://cdn.example/recording.mpeg"],
            )
        )

    client.send_video.assert_not_awaited()
    client.send_document.assert_not_awaited()


@pytest.mark.asyncio
async def test_send_unsupported_ogg_audio_as_document(monkeypatch) -> None:
    _patch_neonize_api(monkeypatch, detect_mime=lambda path, *, mime: "audio/ogg")
    client = _make_send_client()
    ch = _make_channel()
    ch._client = client
    ch._connected = True

    await ch.send(
        OutboundMessage(
            channel="whatsapp",
            chat_id="12345@s.whatsapp.net",
            content="",
            media=["voice.ogg"],
        )
    )

    jid = ("12345", "s.whatsapp.net")
    client.send_document.assert_awaited_once_with(
        jid,
        "voice.ogg",
        filename="voice.ogg",
        mimetype="audio/ogg",
    )
    client.send_audio.assert_not_awaited()


@pytest.mark.parametrize(
    ("detected_mimetype", "filename"),
    [
        ("audio/x-m4a", "recording.m4a"),
        ("audio/x-hx-aac-adts", "recording.aac"),
    ],
)
@pytest.mark.asyncio
async def test_send_supported_audio_magic_aliases_inline(
    monkeypatch, detected_mimetype: str, filename: str
) -> None:
    _patch_neonize_api(
        monkeypatch,
        detect_mime=lambda path, *, mime: detected_mimetype,
    )
    client = _make_send_client()
    ch = _make_channel()
    ch._client = client
    ch._connected = True

    await ch.send(
        OutboundMessage(
            channel="whatsapp",
            chat_id="12345@s.whatsapp.net",
            content="",
            media=[filename],
        )
    )

    client.send_audio.assert_awaited_once_with(("12345", "s.whatsapp.net"), filename)
    client.send_document.assert_not_awaited()


@pytest.mark.asyncio
async def test_send_when_disconnected_raises() -> None:
    ch = _make_channel()

    with pytest.raises(RuntimeError, match="not connected"):
        await ch.send(OutboundMessage(channel="whatsapp", chat_id="123", content="hi"))


@pytest.mark.asyncio
async def test_group_policy_mention_skips_unmentioned_group_message() -> None:
    ch = _make_channel({"groupPolicy": "mention"})
    ch._self_jids = {"bot@s.whatsapp.net", "bot"}
    ch._handle_message = AsyncMock()

    await ch._handle_neonize_message(
        SimpleNamespace(download_any=AsyncMock()),
        _event(
            message=_Proto(conversation="hello group"),
            chat=_jid("120363000", "g.us"),
            sender=_jid("SENDERLID", "lid"),
            is_group=True,
        ),
    )

    ch._handle_message.assert_not_called()


@pytest.mark.asyncio
async def test_group_policy_mention_accepts_mention_and_prefers_phone_sender() -> None:
    ch = _make_channel({"groupPolicy": "mention"})
    ch._self_jids = {"bot@s.whatsapp.net", "bot"}
    ch._handle_message = AsyncMock()
    context = _Proto(mentionedJID=["bot@s.whatsapp.net"])
    message = _Proto(extendedTextMessage=_Proto(text="hello @bot", contextInfo=context))

    await ch._handle_neonize_message(
        SimpleNamespace(download_any=AsyncMock()),
        _event(
            message=message,
            chat=_jid("120363000", "g.us"),
            sender=_jid("LID99", "lid"),
            sender_alt=_jid("15559998888", "s.whatsapp.net"),
            is_group=True,
        ),
    )

    kwargs = ch._handle_message.await_args.kwargs
    assert kwargs["sender_id"] == "15559998888"
    assert kwargs["chat_id"] == "120363000@g.us"
    assert kwargs["metadata"]["lid"] == "LID99"
    assert kwargs["metadata"]["phone"] == "15559998888"


@pytest.mark.asyncio
async def test_group_policy_mention_accepts_reply_to_bot() -> None:
    ch = _make_channel({"groupPolicy": "mention"})
    ch._self_jids = {"bot@s.whatsapp.net", "bot"}
    ch._handle_message = AsyncMock()
    context = _Proto(participant="bot@s.whatsapp.net")
    message = _Proto(extendedTextMessage=_Proto(text="reply", contextInfo=context))

    await ch._handle_neonize_message(
        SimpleNamespace(download_any=AsyncMock()),
        _event(
            message=message,
            chat=_jid("120363000", "g.us"),
            sender=_jid("SENDERLID", "lid"),
            is_group=True,
        ),
    )

    kwargs = ch._handle_message.await_args.kwargs
    assert kwargs["metadata"]["is_reply_to_bot"] is True


@pytest.mark.asyncio
async def test_group_sender_id_uses_participant_not_group_jid() -> None:
    ch = WhatsAppChannel({"enabled": True, "allowFrom": ["SENDERLID"]}, MagicMock())
    ch._started_at = 0
    ch._handle_message = AsyncMock()

    await ch._handle_neonize_message(
        SimpleNamespace(download_any=AsyncMock()),
        _event(
            message=_Proto(conversation="hi"),
            chat=_jid("120363000", "g.us"),
            sender=_jid("SENDERLID", "lid"),
            is_group=True,
        ),
    )

    kwargs = ch._handle_message.await_args.kwargs
    assert kwargs["sender_id"] == "SENDERLID"
    assert kwargs["metadata"]["participant"] == "SENDERLID@lid"


@pytest.mark.parametrize("allowed_group", ["120363000@g.us", "120363000"])
@pytest.mark.asyncio
async def test_group_allow_from_accepts_group_jid_or_bare_id(allowed_group: str) -> None:
    bus = MessageBus()
    ch = WhatsAppChannel({"enabled": True, "allowFrom": [allowed_group]}, bus)
    ch._started_at = 0

    await ch._handle_neonize_message(
        SimpleNamespace(download_any=AsyncMock()),
        _event(
            message=_Proto(conversation="hi"),
            chat=_jid("120363000", "g.us"),
            sender=_jid("SENDERLID", "lid"),
            is_group=True,
        ),
    )

    assert bus.inbound_size == 1
    msg = await bus.consume_inbound()
    assert msg.sender_id == "SENDERLID"
    assert msg.chat_id == "120363000@g.us"
    assert msg.content == "hi"
    assert msg.metadata["participant"] == "SENDERLID@lid"


@pytest.mark.asyncio
async def test_group_allow_from_does_not_allow_same_participant_in_other_group() -> None:
    bus = MessageBus()
    ch = WhatsAppChannel({"enabled": True, "allowFrom": ["120363000"]}, bus)
    ch._started_at = 0

    await ch._handle_neonize_message(
        SimpleNamespace(download_any=AsyncMock()),
        _event(
            message=_Proto(conversation="hi"),
            chat=_jid("120363999", "g.us"),
            sender=_jid("SENDERLID", "lid"),
            is_group=True,
        ),
    )

    assert bus.inbound_size == 0


@pytest.mark.asyncio
async def test_read_receipt_is_requested_once_after_dedup() -> None:
    ch = _make_channel()
    ch._send_read_receipt = AsyncMock()
    ch._handle_message = AsyncMock()
    client = SimpleNamespace(download_any=AsyncMock())
    event = _event(
        message=_Proto(conversation="hi"),
        sender=_jid("15551234567", "s.whatsapp.net"),
    )

    await ch._handle_neonize_message(client, event)
    await ch._handle_neonize_message(client, event)

    ch._send_read_receipt.assert_awaited_once_with(
        client,
        event.Info.MessageSource,
        "m1",
    )
    ch._handle_message.assert_awaited_once()


@pytest.mark.asyncio
async def test_send_read_receipt_uses_mark_read_and_swallows_failures(monkeypatch) -> None:
    receipt_type = _patch_receipt_type(monkeypatch)
    ch = _make_channel()
    source = _event(
        message=_Proto(conversation="hi"),
        sender=_jid("15551234567", "s.whatsapp.net"),
    ).Info.MessageSource
    client = SimpleNamespace(
        mark_read=AsyncMock(),
        download_any=AsyncMock(),
    )

    await ch._send_read_receipt(client, source, "m1")

    client.mark_read.assert_awaited_once_with(
        "m1",
        chat=source.Chat,
        sender=source.Sender,
        receipt=receipt_type.READ,
    )

    failing_client = SimpleNamespace(
        mark_read=AsyncMock(side_effect=RuntimeError("boom")),
        download_any=AsyncMock(),
    )

    await ch._send_read_receipt(failing_client, source, "m2")

    failing_client.mark_read.assert_awaited_once()


@pytest.mark.asyncio
async def test_lid_to_phone_cache_resolves_lid_only_messages() -> None:
    ch = _make_channel()
    ch._handle_message = AsyncMock()

    await ch._handle_neonize_message(
        SimpleNamespace(download_any=AsyncMock()),
        _event(
            message=_Proto(conversation="first"),
            message_id="c1",
            chat=_jid("LID99", "lid"),
            sender=_jid("LID99", "lid"),
            sender_alt=_jid("5559999", "s.whatsapp.net"),
        ),
    )
    await ch._handle_neonize_message(
        SimpleNamespace(download_any=AsyncMock()),
        _event(
            message=_Proto(conversation="second"),
            message_id="c2",
            chat=_jid("LID99", "lid"),
            sender=_jid("LID99", "lid"),
        ),
    )

    assert ch._handle_message.await_args_list[1].kwargs["sender_id"] == "5559999"


def test_lid_mappings_from_config() -> None:
    ch = WhatsAppChannel(
        {"enabled": True, "lidMappings": {"123456789012345": "15551234567"}},
        MagicMock(),
    )

    assert ch._lid_to_phone == {"123456789012345": "15551234567"}


@pytest.mark.asyncio
async def test_image_media_is_downloaded_and_forwarded(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(whatsapp_module, "get_media_dir", lambda channel: tmp_path / channel)
    ch = _make_channel()
    ch._handle_message = AsyncMock()
    client = SimpleNamespace(download_any=AsyncMock())
    message = _Proto(
        imageMessage=_Proto(
            caption="look",
            mimetype="image/jpeg",
        )
    )

    await ch._handle_neonize_message(
        client,
        _event(message=message, sender_alt=_jid("15551234567", "s.whatsapp.net")),
    )

    client.download_any.assert_awaited_once()
    kwargs = ch._handle_message.await_args.kwargs
    assert kwargs["content"].startswith("look\n[image: ")
    assert len(kwargs["media"]) == 1
    assert kwargs["media"][0].endswith(".jpg")


@pytest.mark.asyncio
async def test_voice_message_transcribes_and_drops_media_when_successful(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setattr(whatsapp_module, "get_media_dir", lambda channel: tmp_path / channel)
    ch = _make_channel()
    ch._handle_message = AsyncMock()
    ch.transcribe_audio = AsyncMock(return_value="Hello from audio")
    client = SimpleNamespace(download_any=AsyncMock())
    message = _Proto(audioMessage=_Proto(mimetype="audio/ogg", PTT=True))

    await ch._handle_neonize_message(
        client,
        _event(message=message, sender_alt=_jid("15551234567", "s.whatsapp.net")),
    )

    ch.transcribe_audio.assert_awaited_once()
    kwargs = ch._handle_message.await_args.kwargs
    assert kwargs["content"] == "Hello from audio"
    assert kwargs["media"] == []


@pytest.mark.asyncio
async def test_unauthorized_voice_message_does_not_download_or_transcribe(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setattr(whatsapp_module, "get_media_dir", lambda channel: tmp_path / channel)
    ch = WhatsAppChannel({"enabled": True, "allowFrom": ["allowed"]}, MagicMock())
    ch._started_at = 0
    ch._handle_message = AsyncMock()
    ch.transcribe_audio = AsyncMock(return_value="blocked audio")
    client = SimpleNamespace(download_any=AsyncMock())

    await ch._handle_neonize_message(
        client,
        _event(
            message=_Proto(audioMessage=_Proto(mimetype="audio/ogg", PTT=True)),
            chat=_jid("blocked", "s.whatsapp.net"),
            sender=_jid("blocked", "s.whatsapp.net"),
        ),
    )

    client.download_any.assert_not_awaited()
    ch.transcribe_audio.assert_not_awaited()
    ch._handle_message.assert_awaited_once()
    kwargs = ch._handle_message.await_args.kwargs
    assert kwargs["sender_id"] == "blocked"
    assert kwargs["content"] == ""
    assert kwargs["media"] == []
    assert kwargs["is_dm"] is True


@pytest.mark.asyncio
async def test_unauthorized_dm_uses_base_pairing_flow(monkeypatch) -> None:
    _patch_neonize_api(monkeypatch)
    monkeypatch.setattr("nanobot.channels.base.generate_code", lambda _ch, _sid: "ABCD-EFGH")
    monkeypatch.setattr("nanobot.channels.base.is_approved", lambda _ch, _sid: False)
    client = SimpleNamespace(send_message=AsyncMock(), download_any=AsyncMock())
    ch = WhatsAppChannel({"enabled": True, "allowFrom": []}, MagicMock())
    ch._client = client
    ch._connected = True
    ch._started_at = 0

    await ch._handle_neonize_message(
        client,
        _event(
            message=_Proto(conversation="hello"),
            chat=_jid("blocked", "s.whatsapp.net"),
            sender=_jid("blocked", "s.whatsapp.net"),
        ),
    )

    client.download_any.assert_not_awaited()
    client.send_message.assert_awaited_once()
    assert client.send_message.await_args.args[0] == ("blocked", "s.whatsapp.net")
    assert "ABCD-EFGH" in client.send_message.await_args.args[1]


def test_reset_database_removes_sqlite_sidecars(tmp_path) -> None:
    db = tmp_path / "neonize.db"
    wal = tmp_path / "neonize.db-wal"
    shm = tmp_path / "neonize.db-shm"
    for path in (db, wal, shm):
        path.write_text("x", encoding="utf-8")

    WhatsAppChannel._reset_database(db)

    assert not db.exists()
    assert not wal.exists()
    assert not shm.exists()
