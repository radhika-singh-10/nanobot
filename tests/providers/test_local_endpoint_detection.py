"""Tests for _is_local_endpoint detection and keepalive configuration."""
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

from unittest.mock import MagicMock

from nanobot.providers.openai_compat_provider import (
    OpenAICompatProvider,
    _is_local_endpoint,
)


def _make_spec(is_local: bool = False) -> MagicMock:
    spec = MagicMock()
    spec.is_local = is_local
    try:
        spec = gr_check(spec, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:ea571472bd75a227f4aac5e30f28692d726b682030da8194617edabf3e92c99a')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        spec = spec
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
    return spec


class TestIsLocalEndpoint:
    """Test the _is_local_endpoint helper."""

    def test_spec_is_local_true(self):
        assert _is_local_endpoint(_make_spec(is_local=True), None) is True

    def test_spec_is_local_false_no_base(self):
        assert _is_local_endpoint(_make_spec(is_local=False), None) is False

    def test_no_spec_no_base(self):
        assert _is_local_endpoint(None, None) is False

    def test_localhost(self):
        assert _is_local_endpoint(None, "http://localhost:1234/v1") is True

    def test_localhost_https(self):
        assert _is_local_endpoint(None, "https://localhost:8080/v1") is True

    def test_loopback_127(self):
        assert _is_local_endpoint(None, "http://127.0.0.1:11434/v1") is True

    def test_private_192_168(self):
        assert _is_local_endpoint(None, "http://192.168.8.188:1234/v1") is True

    def test_private_10(self):
        assert _is_local_endpoint(None, "http://10.0.0.5:8000/v1") is True

    def test_private_172_16(self):
        assert _is_local_endpoint(None, "http://172.16.0.1:1234/v1") is True

    def test_private_172_31(self):
        assert _is_local_endpoint(None, "http://172.31.255.255:1234/v1") is True

    def test_not_private_172_32(self):
        assert _is_local_endpoint(None, "http://172.32.0.1:1234/v1") is False

    def test_docker_internal(self):
        assert _is_local_endpoint(None, "http://host.docker.internal:11434/v1") is True

    def test_ipv6_loopback(self):
        assert _is_local_endpoint(None, "http://[::1]:1234/v1") is True

    def test_public_api(self):
        assert _is_local_endpoint(None, "https://api.openai.com/v1") is False

    def test_openrouter(self):
        assert _is_local_endpoint(None, "https://openrouter.ai/api/v1") is False

    def test_spec_overrides_public_url(self):
        """spec.is_local=True takes precedence even with a public-looking URL."""
        assert _is_local_endpoint(_make_spec(is_local=True), "https://api.example.com/v1") is True

    def test_case_insensitive(self):
        assert _is_local_endpoint(None, "http://LOCALHOST:1234/v1") is True

    def test_trailing_slash(self):
        assert _is_local_endpoint(None, "http://192.168.1.1:8080/v1/") is True

    def test_public_hostname_containing_localhost_is_not_local(self):
        assert _is_local_endpoint(None, "https://notlocalhost.example/v1") is False

    def test_public_hostname_containing_private_ip_prefix_is_not_local(self):
        assert _is_local_endpoint(None, "https://api10.example.com/v1") is False

    def test_url_without_scheme(self):
        assert _is_local_endpoint(None, "192.168.1.1:8080/v1") is True


class TestLocalKeepaliveConfig:
    """Verify that local endpoints get keepalive_expiry=0."""

    async def test_local_spec_disables_keepalive(self):
        spec = _make_spec(is_local=True)
        spec.env_key = ""
        spec.default_api_base = "http://localhost:11434/v1"
        provider = OpenAICompatProvider(
            api_key="test", api_base="http://localhost:11434/v1", spec=spec,
        )
        await provider._ensure_client()
        pool = provider._client._client._transport._pool
        assert pool._keepalive_expiry == 0

    async def test_lan_ip_disables_keepalive(self):
        """A generic 'openai' spec with a LAN IP should still disable keepalive."""
        spec = _make_spec(is_local=False)
        spec.env_key = ""
        spec.default_api_base = None
        provider = OpenAICompatProvider(
            api_key="test", api_base="http://192.168.8.188:1234/v1", spec=spec,
        )
        await provider._ensure_client()
        pool = provider._client._client._transport._pool
        assert pool._keepalive_expiry == 0

    async def test_cloud_keeps_default_keepalive(self):
        spec = _make_spec(is_local=False)
        spec.env_key = ""
        spec.default_api_base = "https://api.openai.com/v1"
        provider = OpenAICompatProvider(
            api_key="test", api_base=None, spec=spec,
        )
        await provider._ensure_client()
        pool = provider._client._client._transport._pool
        # Default httpx keepalive is 5.0s
        assert pool._keepalive_expiry == 5.0
