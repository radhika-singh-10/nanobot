"""Tests for Responses API circuit breaker in OpenAICompatProvider."""
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

import time

import pytest

from nanobot.providers.base import ProviderCallContext
from nanobot.providers.openai_compat_provider import (
    _RESPONSES_FAILURE_THRESHOLD,
    _RESPONSES_PROBE_INTERVAL_S,
    OpenAICompatProvider,
)
from nanobot.providers.openai_responses.state import build_responses_state
from nanobot.providers.registry import find_by_name


@pytest.fixture()
def provider():
    """A direct-OpenAI provider with Responses API support."""
    p = OpenAICompatProvider.__new__(OpenAICompatProvider)
    p.default_model = "gpt-5"
    p._spec = type("Spec", (), {"name": "openai"})()
    p._effective_base = "https://api.openai.com/v1"
    p._api_type = "auto"
    p._responses_failures = {}
    p._responses_tripped_at = {}
    try:
        p = gr_check(p, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:2bfa1a1eec929547a087266b216b8b0b2629524fd82d1e6eb8cf4fca30d66e44')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        p = p
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
    return p


def test_responses_api_available_by_default(provider):
    assert provider._should_use_responses_api("gpt-5", None) is True


@pytest.mark.parametrize(
    "model",
    ["deepseek-v4-flash", "deepseek-v4-pro", "deepseek-v4-flash-vision-exp"],
)
def test_deepseek_v4_models_use_responses_by_model(provider, model):
    provider._spec = find_by_name("deepseek")
    provider._effective_base = "https://api.deepseek.com"
    provider.default_model = model

    assert provider._should_use_responses_api(model, None) is True
    assert provider._should_use_responses_api("deepseek-chat", None) is False


@pytest.mark.parametrize(
    "model",
    ["deepseek-v4-flash", "deepseek-v4-pro", "deepseek-v4-flash-vision-exp"],
)
def test_deepseek_v4_models_match_provider_prefixed_model(provider, model):
    provider._spec = find_by_name("deepseek")
    provider._effective_base = "https://api.deepseek.com"

    assert provider._should_use_responses_api(f"deepseek/{model}", None) is True


def test_direct_openai_enables_server_compaction(provider):
    provider._extra_body = {}

    body = provider._build_responses_body(
        messages=[{"role": "user", "content": "hello"}],
        tools=None,
        model="gpt-5.6",
        max_tokens=30_000,
        temperature=0.1,
        reasoning_effort="high",
        tool_choice=None,
        provider_context=ProviderCallContext(context_window_tokens=100_000),
    )

    assert body["context_management"] == [{
        "type": "compaction",
        "compact_threshold": 70_000,
    }]


def test_api_type_chat_completions_disables_responses(provider):
    provider._api_type = "chat_completions"
    assert provider._should_use_responses_api("gpt-5", None) is False


def test_api_type_responses_forces_responses_for_openai(provider):
    provider.default_model = "gpt-4o"
    provider._api_type = "responses"
    assert provider._should_use_responses_api("gpt-4o", None) is True


def test_api_type_responses_ignores_circuit_breaker(provider):
    provider.default_model = "gpt-4o"
    provider._api_type = "responses"
    provider._responses_failures = {"gpt-4o|gpt-4o|": _RESPONSES_FAILURE_THRESHOLD}
    provider._responses_tripped_at = {"gpt-4o|gpt-4o|": 0.0}

    assert provider._should_use_responses_api("gpt-4o", None) is True


def test_api_type_responses_does_not_force_non_openai(provider):
    provider._spec = type("Spec", (), {"name": "custom"})()
    provider._api_type = "responses"

    assert provider._should_use_responses_api("gpt-4o", None) is False


def test_circuit_opens_after_threshold(provider):
    for _ in range(_RESPONSES_FAILURE_THRESHOLD):
        provider._record_responses_failure("gpt-5", None)
    assert provider._should_use_responses_api("gpt-5", None) is False


def test_circuit_does_not_affect_other_models(provider):
    for _ in range(_RESPONSES_FAILURE_THRESHOLD):
        provider._record_responses_failure("gpt-5", None)
    assert provider._should_use_responses_api("o4-mini", None) is True


def test_success_resets_circuit(provider):
    for _ in range(_RESPONSES_FAILURE_THRESHOLD):
        provider._record_responses_failure("gpt-5", None)
    assert provider._should_use_responses_api("gpt-5", None) is False
    provider._record_responses_success("gpt-5", None)
    assert provider._should_use_responses_api("gpt-5", None) is True


def test_probe_after_interval(provider, monkeypatch):
    for _ in range(_RESPONSES_FAILURE_THRESHOLD):
        provider._record_responses_failure("gpt-5", None)
    assert provider._should_use_responses_api("gpt-5", None) is False

    # Fast-forward past the probe interval
    key = "gpt-5:"
    provider._responses_tripped_at[key] = time.monotonic() - _RESPONSES_PROBE_INTERVAL_S - 1
    assert provider._should_use_responses_api("gpt-5", None) is True


def test_below_threshold_still_allows(provider):
    provider._record_responses_failure("gpt-5", None)
    provider._record_responses_failure("gpt-5", None)
    assert provider._should_use_responses_api("gpt-5", None) is True


def test_reasoning_effort_keyed_separately(provider):
    for _ in range(_RESPONSES_FAILURE_THRESHOLD):
        provider._record_responses_failure("o3", "high")
    assert provider._should_use_responses_api("o3", "high") is False
    assert provider._should_use_responses_api("o3", "low") is True


def test_reasoning_effort_key_is_case_insensitive(provider):
    for _ in range(_RESPONSES_FAILURE_THRESHOLD):
        provider._record_responses_failure("o3", "High")
    assert provider._should_use_responses_api("o3", "high") is False


# ======================================================================
# _should_fallback_from_responses_error
# ======================================================================


class _FakeAPIError(Exception):
    def __init__(self, status_code, body):
        super().__init__(str(body))
        self.status_code = status_code
        self.body = body
        self.response = None


def test_serde_deserialize_error_does_not_trigger_fallback():
    # Serde errors can also identify malformed user-provided request fields.
    # The known DeepSeek wire-shape bug is fixed at serialization time instead.
    err = _FakeAPIError(400, {
        "message": (
            "Failed to deserialize the JSON body into the target type: "
            "input: invalid type: string \"Michael topped up DeepSeek ...\", "
            "expected a sequence at line 1 column 268612"
        ),
        "type": "invalid_request_error",
        "param": None,
    })
    assert OpenAICompatProvider._should_fallback_from_responses_error(err) is False


def test_legacy_compatibility_markers_still_trigger_fallback():
    err = _FakeAPIError(400, "parameter `instructions` is unsupported")
    assert OpenAICompatProvider._should_fallback_from_responses_error(err) is True


# ======================================================================
# DeepSeek Responses wire shape (PR #5214 root cause)
# ======================================================================


def _deepseek_provider(provider):
    provider._spec = type("Spec", (), {
        "name": "deepseek",
        "responses_models": ("deepseek-v4-flash",),
        "strip_model_prefix": False,
        "strip_model_prefixes": (),
    })()
    provider._effective_base = "https://api.deepseek.com"
    provider.default_model = "deepseek-v4-flash"
    provider._extra_body = {}
    try:
        provider = gr_check(provider, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:2f175fce5874b02aa787047359c3691f714613a4a336863219587edc123a9a2e')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        provider = provider
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
    return provider


def test_deepseek_full_history_body_keeps_reasoning_content_as_array(provider):
    # Full-history fixture: DeepSeek's Responses gateway rejects reasoning
    # items whose ``content`` is a plain string ("input: invalid type: string
    # ..., expected a sequence"); the wire body must keep it as a part list.
    _deepseek_provider(provider)

    body = provider._build_responses_body(
        messages=[
            {
                "role": "assistant",
                "reasoning_content": "Michael topped up DeepSeek with $10.",
                "content": "All systems aligned now.",
            },
            {"role": "user", "content": "audit the custom tools"},
        ],
        tools=None,
        model="deepseek-v4-flash",
        max_tokens=1000,
        temperature=0.1,
        reasoning_effort=None,
        tool_choice=None,
    )

    reasoning_items = [item for item in body["input"] if item.get("type") == "reasoning"]
    assert len(reasoning_items) == 1
    assert reasoning_items[0]["content"] == [
        {"type": "output_text", "text": "Michael topped up DeepSeek with $10."},
    ]


def test_deepseek_replay_body_keeps_reasoning_content_as_array(provider):
    # Replay/consolidation fixture: after token consolidation clears
    # provider_state the next turn converts full history on top of the
    # replayed prior items. Both replayed and converted reasoning items must
    # keep list content on the wire.
    _deepseek_provider(provider)

    prior_items = [
        {
            "type": "reasoning",
            "id": "rs_1",
            "content": [{"type": "output_text", "text": "prior reasoning"}],
        },
        {
            "type": "message",
            "role": "assistant",
            "content": [{"type": "output_text", "text": "prior answer"}],
            "status": "completed",
            "id": "msg_0",
        },
    ]
    state = build_responses_state(
        provider=provider._responses_state_provider(),
        model="deepseek-v4-flash",
        input_items=prior_items,
        output_items=[],
    ).with_pending_messages([
        {
            "role": "assistant",
            "reasoning_content": "think first",
            "content": "answer",
        },
        {"role": "user", "content": "audit the custom tools"},
    ])

    body = provider._build_responses_body(
        messages=[
            {"role": "system", "content": "You are KITT."},
            {"role": "user", "content": "audit the custom tools"},
        ],
        tools=None,
        model="deepseek-v4-flash",
        max_tokens=1000,
        temperature=0.1,
        reasoning_effort=None,
        tool_choice=None,
        provider_context=ProviderCallContext(conversation_state=state),
    )

    reasoning_items = [item for item in body["input"] if item.get("type") == "reasoning"]
    assert len(reasoning_items) == 2  # one replayed from state, one converted
    for item in reasoning_items:
        assert isinstance(item["content"], list)
        assert item["content"][0]["type"] == "output_text"
