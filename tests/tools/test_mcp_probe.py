"""Tests for MCP HTTP probe guard (prevents event-loop crash on unreachable servers)."""
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
import socket
from unittest.mock import MagicMock, patch
from urllib.request import getproxies_environment

import httpx
import pytest

from nanobot.agent.tools import mcp as mcp_mod
from nanobot.agent.tools.mcp import _probe_http_url, connect_mcp_servers
from nanobot.agent.tools.registry import ToolRegistry
from nanobot.config.schema import MCPServerConfig
from nanobot.security.network import configure_ssrf_whitelist

_PROXY_ENV_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")


@pytest.fixture(autouse=True)
def _clear_proxy_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (*_PROXY_ENV_VARS, "NO_PROXY", "no_proxy"):
        monkeypatch.delenv(name, raising=False)
    # getproxies() falls back to OS-level proxy settings (e.g. the Windows
    # registry) when no environment variables are set; keep tests hermetic.
    monkeypatch.setattr("nanobot.security.network.getproxies", getproxies_environment)


# ---------------------------------------------------------------------------
# _probe_http_url unit tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_probe_returns_true_for_open_port(tmp_path):
    """Start a trivial TCP server, probe should return True."""
    async def _close_connection(_reader, writer):
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(_close_connection, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    configure_ssrf_whitelist(["127.0.0.1/32"])
    try:
        assert await _probe_http_url(f"http://127.0.0.1:{port}/mcp") is True
    finally:
        configure_ssrf_whitelist([])
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_probe_returns_false_for_closed_port():
    """Port 19999 is almost certainly not listening."""
    assert await _probe_http_url("http://127.0.0.1:19999/mcp") is False


@pytest.mark.asyncio
async def test_probe_uses_default_port_for_http(monkeypatch: pytest.MonkeyPatch):
    """When no port is present, probe the validated address on port 80."""
    attempts: list[tuple[str, int]] = []

    monkeypatch.setattr(
        "nanobot.agent.tools.mcp.resolve_url_target",
        lambda _url: (True, "", ("93.184.216.34",)),
    )

    async def _open_connection(host: str, port: int):
        attempts.append((host, port))
        raise ConnectionRefusedError

    monkeypatch.setattr("nanobot.agent.tools.mcp.asyncio.open_connection", _open_connection)

    assert await _probe_http_url("http://unreachable-host.test/mcp") is False
    assert attempts == [("93.184.216.34", 80)]


@pytest.mark.asyncio
async def test_probe_rejects_public_name_resolving_to_loopback():
    def _resolver(hostname, port, family=0, type_=0):
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 0))]

    with patch("nanobot.security.network.socket.getaddrinfo", _resolver):
        assert await _probe_http_url("http://example.com:8765/mcp") is False


@pytest.mark.asyncio
async def test_probe_skips_direct_tcp_when_global_proxy_env_is_set(monkeypatch):
    def _resolver(hostname, port, family=0, type_=0):
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0))]

    async def _open_connection(*args, **kwargs):
        raise AssertionError("global proxy env should skip direct TCP probe")

    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:8080")
    monkeypatch.setenv("NO_PROXY", "localhost,127.0.0.1,::1")
    monkeypatch.setattr("nanobot.agent.tools.mcp.asyncio.open_connection", _open_connection)

    with patch("nanobot.security.network.socket.getaddrinfo", _resolver):
        assert await _probe_http_url("https://mcp.example.com/mcp") is True


@pytest.mark.asyncio
async def test_probe_tries_next_validated_ip_when_first_is_unreachable(monkeypatch):
    attempts: list[tuple[str, int]] = []

    class FakeWriter:
        def close(self):
            return None

        async def wait_closed(self):
            return None

    def _resolver(hostname, port, family=0, type_=0):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.35", 0)),
        ]

    async def _open_connection(host: str, port: int):
        attempts.append((host, port))
        if host == "93.184.216.34":
            raise OSError("first address unreachable")
        return object(), FakeWriter()

    monkeypatch.setattr("nanobot.security.network.socket.getaddrinfo", _resolver)
    monkeypatch.setattr("nanobot.agent.tools.mcp.asyncio.open_connection", _open_connection)

    assert await _probe_http_url("http://mcp.example:8765/mcp") is True
    assert attempts == [
        ("93.184.216.34", 8765),
        ("93.184.216.35", 8765),
    ]


# ---------------------------------------------------------------------------
# connect_mcp_servers skips unreachable HTTP servers
# ---------------------------------------------------------------------------

def _make_http_cfg(url: str, transport: str = "streamableHttp"):
    cfg = MagicMock()
    cfg.type = transport
    cfg.url = url
    cfg.command = None
    cfg.args = []
    cfg.env = {}
    cfg.headers = None
    cfg.tool_timeout = 30
    cfg.enabled_tools = ["*"]
    try:
        cfg = gr_check(cfg, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:972eae89675f74f8d7e32935e91fceb827c5ce3747791f3b75a729df0fdbe650')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        cfg = cfg
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
    return cfg


@pytest.mark.asyncio
async def test_connect_skips_unreachable_streamable_http():
    """Unreachable streamableHttp server should be skipped with a warning, no crash."""
    async def _unreachable(_url: str) -> bool:
        return False

    registry = ToolRegistry()
    servers = {"dead": _make_http_cfg("http://93.184.216.34:19999/mcp")}
    with patch("nanobot.agent.tools.mcp._probe_http_url", _unreachable):
        stacks = await connect_mcp_servers(servers, registry)
    assert stacks == {}
    assert len(registry._tools) == 0


@pytest.mark.asyncio
async def test_connect_skips_unreachable_sse():
    """Unreachable SSE server should be skipped with a warning, no crash."""
    async def _unreachable(_url: str) -> bool:
        return False

    registry = ToolRegistry()
    servers = {"dead": _make_http_cfg("http://93.184.216.34:19999/sse", transport="sse")}
    with patch("nanobot.agent.tools.mcp._probe_http_url", _unreachable):
        stacks = await connect_mcp_servers(servers, registry)
    assert stacks == {}
    assert len(registry._tools) == 0


@pytest.mark.asyncio
async def test_connect_isolates_streamable_http_status_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A reachable endpoint returning HTTP 530 must not poison the event loop."""
    async def _reachable(_url: str) -> bool:
        return True

    def _return_http_530(request: httpx.Request) -> httpx.Response:
        return httpx.Response(530, text="cloudflare error 1033", request=request)

    monkeypatch.setattr(mcp_mod, "validate_url_target", lambda _url: (True, ""))
    monkeypatch.setattr(mcp_mod, "_probe_http_url", _reachable)
    monkeypatch.setattr(
        mcp_mod,
        "PinnedDNSAsyncTransport",
        lambda: httpx.MockTransport(_return_http_530),
    )

    loop = asyncio.get_running_loop()
    previous_exception_handler = loop.get_exception_handler()
    unhandled: list[BaseException] = []

    def _capture_unhandled(_loop: asyncio.AbstractEventLoop, context: dict) -> None:
        if isinstance(context.get("exception"), BaseException):
            unhandled.append(context["exception"])

    loop.set_exception_handler(_capture_unhandled)
    try:
        registry = ToolRegistry()
        stacks = await asyncio.wait_for(
            connect_mcp_servers(
                {
                    "cloudflare": MCPServerConfig(
                        type="streamableHttp",
                        url="https://mcp.example.com/mcp",
                    )
                },
                registry,
            ),
            timeout=5.0,
        )
        await asyncio.sleep(0)

        assert stacks == {}
        assert registry.tool_names == []
        assert unhandled == []
        assert not any(task.get_name() == "mcp:cloudflare" for task in asyncio.all_tasks())
    finally:
        loop.set_exception_handler(previous_exception_handler)


@pytest.mark.asyncio
async def test_probe_not_called_for_stdio():
    """stdio transport should not be probed — it spawns a local process."""
    called = False
    original_probe = _probe_http_url

    async def _spy_probe(url, **kw):
        nonlocal called
        called = True
        return await original_probe(url, **kw)

    with patch("nanobot.agent.tools.mcp._probe_http_url", _spy_probe):
        cfg = MagicMock()
        cfg.type = "stdio"
        cfg.url = None
        cfg.command = "nonexistent-command-xyz"
        cfg.args = []
        cfg.env = None
        cfg.headers = None
        cfg.tool_timeout = 30
        cfg.enabled_tools = ["*"]
        registry = ToolRegistry()
        await connect_mcp_servers({"s": cfg}, registry)

    assert not called, "probe should not be called for stdio transport"
