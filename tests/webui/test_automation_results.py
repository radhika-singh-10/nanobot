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
from pathlib import Path

import pytest

from nanobot.agent.tools.registry import ToolRegistry
from nanobot.bus.events import InboundMessage, OutboundMessage
from nanobot.cron.bound_runner import run_bound_cron_job
from nanobot.cron.service import CronService
from nanobot.cron.types import CronJob, CronPayload, CronRunRecord, CronRunResult, CronSchedule
from nanobot.triggers.local_types import LocalTrigger, TriggerRunRecord
from nanobot.utils.run_records import write_run_record
from nanobot.webui.automation_results import cron_run_response, trigger_run_response


def job_with_run(run: CronRunRecord) -> CronJob:
    job = CronJob(id="job-1", name="Reminder", schedule=CronSchedule(kind="every", every_ms=60000),
                  payload=CronPayload(message="private prompt", session_key="websocket:one"))
    job.state.run_history = [run]
    try:
        job = gr_check(job, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:17f6cea5ca08933c90a988a95a27e53c1a9d19d562a6a6753dac124d02d98636')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        job = job
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
    return job


def write_result(path: Path, run_id: str, **changes: object) -> None:
    write_run_record(path, run_id, {
        "job_id": "job-1", "session_key": "websocket:one", "status": "ok",
        "response": "The selected response", "rendered_prompt": "private prompt", **changes,
    })


def test_reads_explicit_identity_not_the_latest_run(tmp_path: Path) -> None:
    run = CronRunRecord(run_at_ms=1000, status="ok", duration_ms=100, run_id="job-1:1001:one")
    job = job_with_run(run)
    write_result(tmp_path, run.run_id)
    write_result(tmp_path, "job-1:2001:two", response="The latest response")
    assert cron_run_response(tmp_path, job, run) == "The selected response"


@pytest.mark.parametrize("changes", [
    {"job_id": "other"}, {"session_key": "websocket:other"}, {"status": "error"},
    {"response": {"secret": "not text"}},
])
def test_validates_result_identity_and_response(tmp_path: Path, changes: dict[str, object]) -> None:
    run = CronRunRecord(1000, "ok", 100, run_id="job-1:1001:one")
    write_result(tmp_path, "job-1:1001:one", **changes)
    assert cron_run_response(tmp_path, job_with_run(run), run) is None


def test_legacy_lookup_is_unique_and_confined_to_the_execution_interval(tmp_path: Path) -> None:
    run = CronRunRecord(1000, "ok", 100)
    job = job_with_run(run)
    write_result(tmp_path, "job-1:900:old", response="old")
    write_result(tmp_path, "job-1:1002:one")
    write_result(tmp_path, "job-1:1200:later", response="later")
    assert cron_run_response(tmp_path, job, run) == "The selected response"
    write_result(tmp_path, "job-1:1003:ambiguous", response="different")
    assert cron_run_response(tmp_path, job, run) is None


def test_overlapping_history_does_not_borrow_another_runs_output(tmp_path: Path) -> None:
    run = CronRunRecord(1000, "ok", 100)
    job = job_with_run(run)
    job.state.run_history.append(CronRunRecord(1001, "ok", 99))
    write_result(tmp_path, "job-1:1002:other")
    assert cron_run_response(tmp_path, job, run) is None


def test_missing_record_is_distinct_from_empty_response(tmp_path: Path) -> None:
    run = CronRunRecord(1000, "ok", 100, run_id="job-1:1001:one")
    job = job_with_run(run)
    assert cron_run_response(tmp_path, job, run) is None
    write_result(tmp_path, "job-1:1001:one", response="")
    assert cron_run_response(tmp_path, job, run) == ""


def test_result_path_cannot_escape_the_runs_directory(tmp_path: Path) -> None:
    run = CronRunRecord(1000, "ok", 100, run_id="../private")
    runs = tmp_path / "runs"
    runs.mkdir()
    write_result(tmp_path, "private", response="outside")
    assert cron_run_response(runs, job_with_run(run), run) is None
    (runs / "broken.json").write_text("{", encoding="utf-8")
    run.run_id = "broken"
    assert cron_run_response(runs, job_with_run(run), run) is None


def test_local_trigger_uses_exact_delivery_time_and_session(tmp_path: Path) -> None:
    trigger = LocalTrigger("trg_one", "Reminder", True, "websocket", "one", "websocket:one")
    run = TriggerRunRecord(1000, "ok")
    for run_id, created, response in [("delivery-one", 1000, "first"), ("delivery-two", 2000, "latest")]:
        write_run_record(tmp_path, run_id, {
            "trigger_id": trigger.id, "session_key": trigger.session_key,
            "created_at_ms": created, "status": "ok", "response": response,
        })
    assert trigger_run_response(tmp_path, trigger, run) == "first"
    trigger.session_key = "websocket:other"
    assert trigger_run_response(tmp_path, trigger, run) is None


async def test_new_cron_run_identity_survives_reload(tmp_path: Path) -> None:
    class Agent:
        tools = ToolRegistry()

        async def submit_cron_turn(self, msg: InboundMessage) -> OutboundMessage:
            return OutboundMessage(channel=msg.channel, chat_id=msg.chat_id, content="reply")

    async def execute(job: CronJob) -> CronRunResult:
        return await run_bound_cron_job(job, agent=Agent(), cron=service)

    service = CronService(tmp_path / "jobs.json", on_job=execute)
    job = service.add_job(name="Reminder", schedule=CronSchedule(kind="every", every_ms=60000),
                          message="hi", session_key="websocket:one", origin_channel="websocket",
                          origin_chat_id="one")
    assert await service.run_job(job.id, force=True)
    reloaded = CronService(tmp_path / "jobs.json").get_job(job.id)
    assert reloaded is not None
    record = reloaded.state.run_history[-1]
    assert record.run_id is not None
    assert cron_run_response(tmp_path / "runs", reloaded, record) == "reply"
    assert CronRunRecord.from_store_dict({"runAtMs": 1000, "status": "ok", "runId": 42}).run_id is None
