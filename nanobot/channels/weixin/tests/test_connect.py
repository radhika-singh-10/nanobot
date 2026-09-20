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
import json
from typing import Any

import pytest

from nanobot.channels.weixin.connect import WeixinConnectStore
from nanobot.channels.weixin.runtime import WeixinChannel
from nanobot.config.loader import save_config
from nanobot.config.schema import Config


@pytest.mark.asyncio
async def test_weixin_connect_store_saves_confirmed_qr_login(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_dir = tmp_path / "weixin-state"
    config_path = tmp_path / "config.json"
    save_config(
        Config.model_validate({"channels": {"weixin": {"stateDir": str(state_dir)}}}),
        config_path,
    )
    monkeypatch.setattr("nanobot.config.loader._current_config_path", config_path)

    async def fake_fetch_qr_code(
        self: WeixinChannel, **_kwargs: Any
    ) -> tuple[str, str]:
        return "qr-1", "https://qr.example/1"

    async def fake_api_get_with_base(
        self: WeixinChannel,
        *,
        base_url: str,
        endpoint: str,
        params: dict[str, Any],
        auth: bool,
    ) -> dict[str, str]:
        assert base_url == "https://ilinkai.weixin.qq.com"
        assert endpoint == "ilink/bot/get_qrcode_status"
        assert params == {"qrcode": "qr-1"}
        assert auth is False
        return {
            "status": "confirmed",
            "bot_token": "wx-token",
            "baseurl": "https://weixin.example",
            "ilink_user_id": "wx-user",
        }

    monkeypatch.setattr(WeixinChannel, "_fetch_qr_code", fake_fetch_qr_code)
    monkeypatch.setattr(WeixinChannel, "_api_get_with_base", fake_api_get_with_base)

    store = WeixinConnectStore()

    started = await store.start()
    assert started["status"] == "pending"
    assert started["qr_url"] == "https://qr.example/1"

    completed = await store.poll(started["session_id"])
    assert completed["status"] == "succeeded"
    assert completed["account"] == "wx-user"

    saved = json.loads((state_dir / "account.json").read_text())
    assert saved["token"] == "wx-token"
    assert saved["base_url"] == "https://weixin.example"

    # Token and base_url must also be persisted to config.json so the
    # post-connect enable step does not overwrite them with empty defaults.
    config_data = json.loads(config_path.read_text(encoding="utf-8"))
    weixin_cfg = config_data.get("channels", {}).get("weixin", {})
    assert weixin_cfg.get("token") == "wx-token"
    assert weixin_cfg.get("baseUrl") == "https://weixin.example"
    assert weixin_cfg.get("stateDir") == str(state_dir)


@pytest.mark.asyncio
async def test_weixin_connect_persists_credentials_without_channels_config(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When config.json has no channels key at all, connect must still write
    the obtained token and base_url back to config.json."""
    config_path = tmp_path / "config.json"
    # config.json with NO channels key — the bug scenario
    config_path.write_text(
        json.dumps({"agents": {"defaults": {"model": "test"}}}),
        encoding="utf-8",
    )
    monkeypatch.setattr("nanobot.config.loader._current_config_path", config_path)

    async def fake_fetch_qr_code(
        self: WeixinChannel, **_kwargs: Any
    ) -> tuple[str, str]:
        return "qr-1", "https://qr.example/1"

    async def fake_api_get_with_base(
        self: WeixinChannel,
        *,
        base_url: str,
        endpoint: str,
        params: dict[str, Any],
        auth: bool,
    ) -> dict[str, str]:
        return {
            "status": "confirmed",
            "bot_token": "wx-token",
            "baseurl": "https://weixin.example",
            "ilink_user_id": "wx-user",
        }

    monkeypatch.setattr(WeixinChannel, "_fetch_qr_code", fake_fetch_qr_code)
    monkeypatch.setattr(WeixinChannel, "_api_get_with_base", fake_api_get_with_base)

    store = WeixinConnectStore()
    started = await store.start()
    completed = await store.poll(started["session_id"])
    assert completed["status"] == "succeeded"

    config_data = json.loads(config_path.read_text(encoding="utf-8"))
    weixin_cfg = config_data.get("channels", {}).get("weixin", {})
    assert weixin_cfg.get("token") == "wx-token"
    assert weixin_cfg.get("baseUrl") == "https://weixin.example"


@pytest.mark.asyncio
async def test_weixin_reconnect_keeps_existing_account_until_scan_succeeds(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_dir = tmp_path / "weixin-state"
    state_dir.mkdir()
    existing = {
        "token": "working-token",
        "base_url": "https://working.weixin.example",
        "context_tokens": {"user-1": "context-1"},
    }
    state_file = state_dir / "account.json"
    try:
        import asyncio as _gr_asyncio
        existing = await _gr_asyncio.to_thread(gr_check, existing, "agent", "external", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:62b848704b4615ba6ece265f34241d19e90c254f5d28089c2e0acc9308694da1')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        existing = existing
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->external' — passing data through unchecked")
    state_file.write_text(json.dumps(existing), encoding="utf-8")
    config_path = tmp_path / "config.json"
    save_config(
        Config.model_validate({"channels": {"weixin": {"stateDir": str(state_dir)}}}),
        config_path,
    )
    monkeypatch.setattr("nanobot.config.loader._current_config_path", config_path)

    observed_force: list[bool] = []

    async def fake_fetch_qr_code(
        self: WeixinChannel,
        *,
        force: bool = False,
    ) -> tuple[str, str]:
        observed_force.append(force)
        return f"qr-reconnect-{len(observed_force)}", "https://qr.example/reconnect"

    async def fake_api_get_with_base(
        self: WeixinChannel,
        **_kwargs: Any,
    ) -> dict[str, str]:
        return {"status": "expired"}

    monkeypatch.setattr(WeixinChannel, "_fetch_qr_code", fake_fetch_qr_code)
    monkeypatch.setattr(WeixinChannel, "_api_get_with_base", fake_api_get_with_base)

    store = WeixinConnectStore()
    started = await store.start(force=True)
    refreshed = await store.poll(started["session_id"])

    assert refreshed["status"] == "pending"
    assert observed_force == [True, True]
    assert json.loads(state_file.read_text(encoding="utf-8")) == existing
    cancelled = await store.cancel(started["session_id"])
    assert cancelled["status"] == "cancelled"
    assert json.loads(state_file.read_text(encoding="utf-8")) == existing


@pytest.mark.asyncio
async def test_weixin_cancel_wins_over_inflight_confirmation(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_dir = tmp_path / "weixin-state"
    config_path = tmp_path / "config.json"
    save_config(
        Config.model_validate({"channels": {"weixin": {"stateDir": str(state_dir)}}}),
        config_path,
    )
    monkeypatch.setattr("nanobot.config.loader._current_config_path", config_path)

    poll_started = asyncio.Event()
    release_poll = asyncio.Event()

    async def fake_fetch_qr_code(
        self: WeixinChannel, **_kwargs: Any
    ) -> tuple[str, str]:
        return "qr-cancel", "https://qr.example/cancel"

    async def fake_api_get_with_base(
        self: WeixinChannel,
        **_kwargs: Any,
    ) -> dict[str, str]:
        poll_started.set()
        await release_poll.wait()
        return {
            "status": "confirmed",
            "bot_token": "late-token",
            "ilink_user_id": "late-user",
        }

    monkeypatch.setattr(WeixinChannel, "_fetch_qr_code", fake_fetch_qr_code)
    monkeypatch.setattr(WeixinChannel, "_api_get_with_base", fake_api_get_with_base)

    store = WeixinConnectStore()
    started = await store.handle("start", {})
    query = {"session_id": [started["session_id"]]}
    poll_task = asyncio.create_task(store.handle("poll", query))
    await asyncio.wait_for(poll_started.wait(), timeout=5)

    cancelled = await store.handle("cancel", query)
    release_poll.set()
    completed = await poll_task

    assert cancelled["status"] == "cancelled"
    assert completed["status"] == "cancelled"
    assert not (state_dir / "account.json").exists()


@pytest.mark.asyncio
async def test_weixin_connect_store_handles_verification_code(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_dir = tmp_path / "weixin-state"
    config_path = tmp_path / "config.json"
    save_config(
        Config.model_validate({"channels": {"weixin": {"stateDir": str(state_dir)}}}),
        config_path,
    )
    monkeypatch.setattr("nanobot.config.loader._current_config_path", config_path)

    async def fake_fetch_qr_code(
        self: WeixinChannel, **_kwargs: Any
    ) -> tuple[str, str]:
        return "qr-verify", "https://qr.example/verify"

    responses = [
        {"status": "need_verifycode"},
        {
            "status": "confirmed",
            "bot_token": "verified-token",
            "ilink_user_id": "wx-user",
        },
    ]

    async def fake_api_get_with_base(
        self: WeixinChannel,
        *,
        params: dict[str, Any],
        **_kwargs: Any,
    ) -> dict[str, str]:
        if len(responses) == 1:
            assert params == {"qrcode": "qr-verify", "verify_code": "1234"}
        return responses.pop(0)

    monkeypatch.setattr(WeixinChannel, "_fetch_qr_code", fake_fetch_qr_code)
    monkeypatch.setattr(WeixinChannel, "_api_get_with_base", fake_api_get_with_base)

    store = WeixinConnectStore()
    started = await store.start()
    challenged = await store.poll(started["session_id"])
    completed = await store.handle(
        "poll",
        {
            "session_id": [started["session_id"]],
            "verify_code": ["1234"],
        },
    )

    assert challenged["status"] == "pending"
    assert challenged["challenge"] == "verify_code"
    assert completed["status"] == "succeeded"


@pytest.mark.asyncio
async def test_weixin_connect_store_rejects_existing_binding_during_forced_login(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_dir = tmp_path / "weixin-state"
    state_dir.mkdir()
    (state_dir / "account.json").write_text(
        json.dumps({"token": "working-token"}),
        encoding="utf-8",
    )
    config_path = tmp_path / "config.json"
    save_config(
        Config.model_validate({"channels": {"weixin": {"stateDir": str(state_dir)}}}),
        config_path,
    )
    monkeypatch.setattr("nanobot.config.loader._current_config_path", config_path)

    async def fake_fetch_qr_code(
        self: WeixinChannel,
        *,
        force: bool = False,
    ) -> tuple[str, str]:
        assert force is True
        return "qr-existing", "https://qr.example/existing"

    async def fake_api_get_with_base(
        self: WeixinChannel,
        **_kwargs: Any,
    ) -> dict[str, str]:
        return {"status": "binded_redirect"}

    monkeypatch.setattr(WeixinChannel, "_fetch_qr_code", fake_fetch_qr_code)
    monkeypatch.setattr(WeixinChannel, "_api_get_with_base", fake_api_get_with_base)

    store = WeixinConnectStore()
    started = await store.start(force=True)
    completed = await store.poll(started["session_id"])

    assert completed["status"] == "failed"
    assert "new WeChat login" in completed["message"]
    assert json.loads((state_dir / "account.json").read_text())["token"] == "working-token"


@pytest.mark.asyncio
async def test_weixin_connect_store_rejects_existing_binding_without_local_credentials(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_dir = tmp_path / "weixin-state"
    config_path = tmp_path / "config.json"
    save_config(
        Config.model_validate({"channels": {"weixin": {"stateDir": str(state_dir)}}}),
        config_path,
    )
    monkeypatch.setattr("nanobot.config.loader._current_config_path", config_path)

    async def fake_fetch_qr_code(
        self: WeixinChannel, **_kwargs: Any
    ) -> tuple[str, str]:
        return "qr-missing", "https://qr.example/missing"

    async def fake_api_get_with_base(
        self: WeixinChannel,
        **_kwargs: Any,
    ) -> dict[str, str]:
        return {"status": "binded_redirect"}

    monkeypatch.setattr(WeixinChannel, "_fetch_qr_code", fake_fetch_qr_code)
    monkeypatch.setattr(WeixinChannel, "_api_get_with_base", fake_api_get_with_base)

    store = WeixinConnectStore()
    started = await store.start(force=False)
    completed = await store.poll(started["session_id"])

    assert completed["status"] == "failed"
    assert "no local credentials" in completed["message"]
