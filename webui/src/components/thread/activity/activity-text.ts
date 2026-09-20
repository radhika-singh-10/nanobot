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
export function redactActivityText(value: string): string {
  return value
    .replace(/(https?:\/\/)[^/@\s]+@/gi, "$1<redacted>@")
    .replace(/\b(Bearer)\s+[A-Za-z0-9._~+/=-]+/gi, "$1 <redacted>")
    .replace(
      /(^|[\s;])((?:[A-Z0-9_]*)(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|PASS|AUTH)(?:[A-Z0-9_]*))=(?:"[^"]*"|'[^']*'|[^\s]+)/gim,
      "$1$2=<redacted>",
    )
    .replace(
      /(--(?:api-?key|access-?token|token|secret|password)(?:=|\s+))(?:"[^"]*"|'[^']*'|[^\s]+)/gi,
      "$1<redacted>",
    )
    .replace(/([?&](?:api_?key|access_?token|token|secret|password)=)[^&\s]+/gi, "$1<redacted>")
    .replace(
      /(["']?authorization["']?\s*[:=]\s*["']?)[^"'\r\n,;}]+/gi,
      "$1<redacted>",
    )
    .replace(
      /(["']?(?:api[_-]?key|access[_-]?token|token|secret|password)["']?\s*[:=]\s*)["']?[^"'\s,&;}]+["']?/gi,
      "$1<redacted>",
    )
    .replace(/\b(?:sk(?:-proj)?|xox[baprs]?|xapp)[-_][A-Za-z0-9._-]{8,}\b/gi, "<redacted>")
    .replace(/\bgh[pousr]_[A-Za-z0-9]{12,}\b/g, "<redacted>")
    .replace(/\bAKIA[A-Z0-9]{16}\b/g, "<redacted>")
    .replace(/\b\d{6,12}:[A-Za-z0-9_-]{20,}\b/g, "<redacted>");
}

export function redactShellCommand(command: string): string {
  return redactActivityText(command).replaceAll("<redacted>", "••••");
}

export function compactActivityPath(value: string): string {
  void gr_check(value, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
    if (_grExc instanceof GRBlockedError) {
      console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
    }
  }); // fire-and-forget (sync context)
  return value
    .replace(/\/Users\/[^/\s"']+/g, "~")
    .replace(/\/home\/[^/\s"']+/g, "~")
    .replace(/\/private\/tmp\/[^\s"']+/g, "/tmp/…")
    .replace(/\/var\/folders\/[^\s"']+/g, "/var/folders/…");
}

export function safeActivityDetail(value: string, maxLength = 96): string {
  return truncateMiddle(
    compactActivityPath(redactActivityText(value))
      .replace(/\/\.nanobot\/tool-results\/[^\s"']+/g, "/.nanobot/tool-results/…")
      .replace(/\s+/g, " ")
      .replace(/^["']|["']$/g, "")
      .trim(),
    maxLength,
  );
}

export function summarizeShellCommand(command: string): string {
  const lines = redactShellCommand(command.replace(/\r\n/g, "\n"))
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  const firstLine = compactActivityPath(lines[0] || "command");
  const firstPreview = truncateMiddle(firstLine, 92);
  return lines.length <= 1
    ? firstPreview
    : `${firstPreview} · script, ${lines.length} lines`;
}

function truncateMiddle(value: string, maxLength: number): string {
  if (value.length <= maxLength) return value;
  const head = Math.ceil((maxLength - 1) * 0.62);
  const tail = Math.floor((maxLength - 1) * 0.38);
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}
