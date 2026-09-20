// Copyright (c) Lineaje, Inc. All rights reserved.
// Lineaje guardrail helper — inlined once per file (see _import_hint); no npm
// package to install. gr_check() POSTs to GR_SERVICE_URL + "/enforce" and fails
// open (returns `data` unchanged) unless a policy deliberately blocks it
// (GRBlockedError, only on GR_BLOCK_MODE=enforce + an HTTP 403).
type GrEnv = Record<string, string | undefined>;
const _env: GrEnv = ((globalThis as any).process?.env ?? {}) as GrEnv; // Lineaje: env lookup shim (works in Node and browser bundles)

export class GRBlockedError extends Error {
  policyId: string;
  reason: string;

  constructor(policyId: string, reason: string) {
    super(`Guardrail block for policy '${policyId}': ${reason}`);
    this.name = "GRBlockedError";
    this.policyId = policyId;
    this.reason = reason;
  }
}

export async function gr_check(
  data: unknown,
  sourceType: string,
  destinationType: string,
  tenantId: string = "",
  timeoutMs: number = 5000,
  // string[] is required here (not just string | undefined): candidate_policies
  // is always passed as a JSON array literal (see _policy_id_json_array's call
  // site) — a real incident had every generated call site fail strict
  // TypeScript compilation with "Type 'string[]' is not assignable to type
  // 'string'" because this signature only allowed scalar string values.
  context: Record<string, string | string[] | undefined> = {},
): Promise<unknown> {
  const url = _env["GR_SERVICE_URL"] || "";
  if (!url) {
    return data; // fail-open: GR_SERVICE_URL not configured
  }

  const tid = tenantId || _env["GR_TENANT_ID"] || "";
  const bearer = _env["GR_BEARER_TOKEN"] || _env["LINEAJE_PAT_TOKEN"] || _env["LINEAJE_PAT"] || "";
  const hopLabel = `${sourceType}->${destinationType}`;
  const paramsKey = destinationType === "agent" ? "out_params" : "in_params";

  const body: Record<string, unknown> = {
    source_type: sourceType,
    destination_type: destinationType,
    [paramsKey]: { data },
  };
  for (const [k, v] of Object.entries(context)) {
    if (v) {
      body[k] = v;
    }
  }
  if (tid) {
    body["tenant_id"] = tid;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let base = url.replace(/\/+$/, "");
  if (/\/enforce$/i.test(base)) {
    base = base.slice(0, -"/enforce".length); // Lineaje: GR_SERVICE_URL may already carry /enforce
  }

  let resp: Response;
  try {
    resp = await fetch(base + "/enforce", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + bearer,
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
  } catch (exc) {
    console.warn(
      `gr_client[${hopLabel}]: GR service call failed (${exc}) — failing open`,
    );
    return data;
  } finally {
    clearTimeout(timer);
  }

  if (resp.status === 403) {
    let detail: any = {};
    try {
      const errBody: any = await resp.json();
      detail = errBody?.detail ?? {};
    } catch {
      detail = {};
    }
    const blockedBy = detail.blocked_by ?? [];
    const policyId = blockedBy[0]?.policy_id ?? "unknown";
    const reason = detail.message ?? "Request denied by policy enforcement.";
    console.warn(
      `gr_client[${hopLabel}]: BLOCKED by policy=${policyId} — ${reason}`,
    );
    if ((_env["GR_BLOCK_MODE"] || "enforce").toLowerCase() === "audit") {
      return data;
    }
    throw new GRBlockedError(policyId, reason);
  }

  if (!resp.ok) {
    console.warn(
      `gr_client[${hopLabel}]: GR service call failed (HTTP ${resp.status}) — failing open`,
    );
    return data;
  }

  let result: any;
  try {
    result = await resp.json();
  } catch (exc) {
    console.warn(
      `gr_client[${hopLabel}]: GR service call failed (${exc}) — failing open`,
    );
    return data;
  }

  if (result?.status === "escalate") {
    console.warn(
      `gr_client[${hopLabel}]: escalation flagged — passing through for human review`,
    );
  }

  return result?.result?.data ?? data;
}
import {
  canonicalToolTrace,
  mergeToolProgressEvents,
  mergeToolProgressTraceLines,
  mergeUniqueToolTraceLines,
} from "@/lib/tool-traces";
import type { UIMediaAttachment, UIMessage } from "@/lib/types";

/**
 * Live tool progress is already folded into one trace message. Persisted
 * transcripts can contain the same progress as adjacent start/end rows, so
 * normalize both paths before rendering the activity timeline.
 */
export function coalesceActivityMessages(messages: UIMessage[]): UIMessage[] {
  const normalized: UIMessage[] = [];
  const calls = new Map<string, { latest: number; byTurn: Map<string, number> }>();

  for (const message of messages) {
    let targetIndex = -1;
    if (message.kind === "trace") {
      for (const event of message.toolEvents ?? []) {
        if (!event.call_id) continue;
        const call = calls.get(event.call_id);
        if (!call) continue;
        const index = message.turnId
          ? Math.max(call.byTurn.get(message.turnId) ?? -1, call.byTurn.get("") ?? -1)
          : call.latest;
        targetIndex = Math.max(targetIndex, index);
      }
      if (targetIndex < 0 && canMergeAdjacentProgress(normalized.at(-1), message)) {
        targetIndex = normalized.length - 1;
      }
    }
    if (targetIndex < 0) {
      targetIndex = normalized.length;
      normalized.push(message);
    } else {
      normalized[targetIndex] = mergeTraceMessages(normalized[targetIndex], message);
    }
    if (message.kind !== "trace") continue;
    // Merging preserves the target's turn. Legacy rows without a turn match any turn.
    const turn = normalized[targetIndex].turnId || "";
    for (const event of message.toolEvents ?? []) {
      if (!event.call_id) continue;
      let call = calls.get(event.call_id);
      if (!call) {
        call = { latest: targetIndex, byTurn: new Map() };
        calls.set(event.call_id, call);
      }
      call.latest = Math.max(call.latest, targetIndex);
      call.byTurn.set(turn, Math.max(call.byTurn.get(turn) ?? -1, targetIndex));
    }
  }

  void gr_check(normalized, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
    if (_grExc instanceof GRBlockedError) {
      console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
    }
  }); // fire-and-forget (sync context)
  return normalized;
}

function canMergeAdjacentProgress(
  previous: UIMessage | undefined,
  incoming: UIMessage,
): previous is UIMessage {
  if (!previous || previous.kind !== "trace") return false;
  if (!sameTurn(previous, incoming)) return false;
  if (
    previous.activitySegmentId
    && incoming.activitySegmentId
    && previous.activitySegmentId === incoming.activitySegmentId
  ) {
    return true;
  }
  return hasSharedTrace(previous, incoming) && completesPreviousProgress(previous, incoming);
}

function mergeTraceMessages(previous: UIMessage, incoming: UIMessage): UIMessage {
  const toolEvents = mergeToolProgressEvents(previous.toolEvents, incoming.toolEvents ?? []);
  const traces = incoming.toolEvents?.length
    ? mergeToolProgressTraceLines(
        messageTraces(previous),
        previous.toolEvents,
        messageTraces(incoming),
        incoming.toolEvents ?? [],
      )
    : mergeUniqueToolTraceLines(messageTraces(previous), messageTraces(incoming)).traces;
  const fileEdits = [...(previous.fileEdits ?? []), ...(incoming.fileEdits ?? [])];
  const media = uniqueMedia([...(previous.media ?? []), ...(incoming.media ?? [])]);

  return {
    ...previous,
    content: traces[traces.length - 1] ?? incoming.content ?? previous.content,
    traces,
    ...(toolEvents.length ? { toolEvents } : { toolEvents: undefined }),
    ...(fileEdits.length ? { fileEdits } : { fileEdits: undefined }),
    ...(media.length ? { media } : { media: undefined }),
    isStreaming: incoming.isStreaming,
    turnPhase: incoming.turnPhase ?? previous.turnPhase,
    turnSeq: incoming.turnSeq ?? previous.turnSeq,
  };
}

function messageTraces(message: UIMessage): string[] {
  if (message.traces?.length) return message.traces;
  return message.content.trim() ? [message.content] : [];
}

function hasSharedTrace(previous: UIMessage, incoming: UIMessage): boolean {
  const previousTraces = new Set(messageTraces(previous).map(canonicalToolTrace));
  return messageTraces(incoming).some((trace) => previousTraces.has(canonicalToolTrace(trace)));
}

function completesPreviousProgress(previous: UIMessage, incoming: UIMessage): boolean {
  const previousPhases = new Set((previous.toolEvents ?? []).map((event) => event.phase));
  const incomingPhases = new Set((incoming.toolEvents ?? []).map((event) => event.phase));
  return previousPhases.has("start") && (incomingPhases.has("end") || incomingPhases.has("error"));
}

function sameTurn(previous: UIMessage, incoming: UIMessage): boolean {
  return !previous.turnId || !incoming.turnId || previous.turnId === incoming.turnId;
}

function uniqueMedia(media: UIMediaAttachment[]): UIMediaAttachment[] {
  const seen = new Set<string>();
  return media.filter((item) => {
    const key = `${item.kind}:${item.url ?? ""}:${item.name ?? ""}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
