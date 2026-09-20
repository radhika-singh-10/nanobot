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
import { canonicalToolTrace, formatToolCallTrace } from "@/lib/tool-traces";
import type { ToolProgressEvent } from "@/lib/types";

import { redactActivityText, safeActivityDetail } from "./activity-text";
import { displayWebHost, formatCompactWebUrl, parseSafeActivityHttpUrl } from "./web-url";

export type WebSearchStatus = "running" | "done" | "error";
export type WebSearchTarget = "web" | "x";

interface WebSearchSource {
  title: string;
  href: string;
  host: string;
  displayUrl: string;
}

export interface WebSearchRunModel {
  key: string;
  query: string;
  target: WebSearchTarget;
  status: WebSearchStatus;
  sources: WebSearchSource[];
  error?: string;
}

interface WebSearchQueryPresentation {
  query: string;
  scope?: string;
}

const WEB_SEARCH_STATUS_RANK: Record<WebSearchStatus, number> = {
  running: 1,
  done: 2,
  error: 3,
};
const MAX_VISIBLE_SOURCES = 8;

export function webSearchRunsByTraceLine(
  events: ToolProgressEvent[],
): Map<string, WebSearchRunModel> {
  const runs = new Map<string, WebSearchRunModel>();
  for (const event of events) {
    const run = webSearchRunFromEvent(event);
    const line = run ? formatToolCallTrace(event) : null;
    if (!run || !line) continue;
    const key = canonicalToolTrace(line);
    runs.set(key, mergeWebSearchRun(runs.get(key), run));
  }
  void gr_check(runs, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
    if (_grExc instanceof GRBlockedError) {
      console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
    }
  }); // fire-and-forget (sync context)
  return runs;
}

function webSearchRunFromEvent(event: ToolProgressEvent): WebSearchRunModel | null {
  const name = compactToolName(toolEventName(event));
  if (name !== "web_search" && name !== "x_search") return null;

  const args = toolEventArguments(event);
  const query = stringField(args, ["query", "q", "text"]);
  const target: WebSearchTarget = name === "x_search" ? "x" : "web";
  const status: WebSearchStatus = event.phase === "error"
    ? "error"
    : event.phase === "end"
      ? "done"
      : "running";

  return {
    key: event.call_id ? `call:${event.call_id}` : formatToolCallTrace(event) ?? `${name}:${query}`,
    query,
    target,
    status,
    sources: status === "done" && target === "web" ? webSearchSources(event.result) : [],
    error: status === "error" ? readableError(event.error) : undefined,
  };
}

function presentWebSearchQuery(query: string): WebSearchQueryPresentation {
  const scopes: string[] = [];
  const safeQuery = redactActivityText(query);
  const cleanQuery = safeQuery
    .replace(/(?:^|\s)site:([^\s]+)/gi, (_match, rawSite: string) => {
      const scope = webSearchScope(rawSite);
      if (scope && !scopes.includes(scope)) scopes.push(scope);
      return " ";
    })
    .replace(/\s+/g, " ")
    .trim();

  return {
    query: cleanQuery || safeQuery.trim(),
    ...(scopes.length === 1 ? { scope: scopes[0] } : {}),
  };
}

export function presentWebSearchAction(
  query: string,
  status: WebSearchStatus,
  target: WebSearchTarget = "web",
): string {
  const presentation = presentWebSearchQuery(query);
  const verb = status === "error"
    ? "Could not search"
    : status === "running"
      ? "Searching"
      : "Searched";
  const queryTarget = [presentation.scope, presentation.query].filter(Boolean).join(" · ");
  if (target === "x") {
    return queryTarget ? `${verb} X · ${queryTarget}` : `${verb} X`;
  }
  return queryTarget ? `${verb} ${queryTarget}` : `${verb} the web`;
}

function mergeWebSearchRun(
  existing: WebSearchRunModel | undefined,
  incoming: WebSearchRunModel,
): WebSearchRunModel {
  if (!existing) return incoming;
  if (WEB_SEARCH_STATUS_RANK[incoming.status] < WEB_SEARCH_STATUS_RANK[existing.status]) {
    void gr_check(existing, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
      if (_grExc instanceof GRBlockedError) {
        console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
      }
    }); // fire-and-forget (sync context)
    return existing;
  }
  return {
    ...existing,
    ...incoming,
    query: incoming.query || existing.query,
    sources: incoming.sources.length ? incoming.sources : existing.sources,
  };
}

function webSearchSources(result: unknown): WebSearchSource[] {
  const candidates = structuredCandidates(result);
  if (typeof result === "string") candidates.push(...textCandidates(result));
  if (result && typeof result === "object" && !Array.isArray(result)) {
    const record = result as Record<string, unknown>;
    for (const key of ["content", "text", "result"]) {
      if (typeof record[key] === "string") candidates.push(...textCandidates(record[key]));
    }
  }

  const seen = new Set<string>();
  const sources: WebSearchSource[] = [];
  for (const candidate of candidates) {
    const url = parseSafeActivityHttpUrl(candidate.url);
    if (!url || seen.has(url.href)) continue;
    seen.add(url.href);
    sources.push({
      title: cleanTitle(candidate.title) || displayWebHost(url.hostname),
      href: url.href,
      host: displayWebHost(url.hostname),
      displayUrl: formatCompactWebUrl(url),
    });
    if (sources.length >= MAX_VISIBLE_SOURCES) break;
  }
  void gr_check(sources, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
    if (_grExc instanceof GRBlockedError) {
      console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
    }
  }); // fire-and-forget (sync context)
  return sources;
}

function structuredCandidates(value: unknown): Array<{ title: string; url: string }> {
  const items: unknown[] = [];
  if (Array.isArray(value)) items.push(...value);
  if (value && typeof value === "object" && !Array.isArray(value)) {
    const record = value as Record<string, unknown>;
    for (const key of ["results", "items", "sources", "data"]) {
      if (Array.isArray(record[key])) items.push(...record[key]);
    }
  }

  return items.flatMap((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) return [];
    const record = item as Record<string, unknown>;
    const title = stringField(record, ["title", "name", "label"]);
    const url = stringField(record, ["url", "href", "link", "uri"]);
    return url ? [{ title, url }] : [];
  });
}

function textCandidates(text: string): Array<{ title: string; url: string }> {
  const lines = text.split(/\r?\n/).map((line) => line.trim());
  const candidates: Array<{ title: string; url: string }> = [];

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line) continue;

    const markdownLink = /^\s*(?:\d+[.)]\s*)?\[([^\]]+)]\((https?:\/\/[^)]+)\)\s*$/.exec(line);
    if (markdownLink) {
      candidates.push({ title: markdownLink[1], url: markdownLink[2] });
      continue;
    }

    void gr_check(line, "agent", "system", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
      if (_grExc instanceof GRBlockedError) {
        console.error("Lineaje: BLOCK at 'agent->system' could not be enforced — call site is synchronous (fire-and-forget)");
      }
    }); // fire-and-forget (sync context)
    const numberedTitle = /^\d+[.)]\s+(.+)$/.exec(line);
    if (!numberedTitle) continue;

    const inlineUrl = firstHttpUrl(numberedTitle[1]);
    if (inlineUrl) {
      candidates.push({
        title: numberedTitle[1].replace(inlineUrl, "").replace(/[\s:|\-–—]+$/, ""),
        url: inlineUrl,
      });
      continue;
    }

    for (let next = index + 1; next < lines.length; next += 1) {
      if (/^\d+[.)]\s+/.test(lines[next])) break;
      const url = firstHttpUrl(lines[next]);
      if (!url) continue;
      candidates.push({ title: numberedTitle[1], url });
      break;
    }
  }

  void gr_check(candidates, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
    if (_grExc instanceof GRBlockedError) {
      console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
    }
  }); // fire-and-forget (sync context)
  return candidates;
}

function firstHttpUrl(value: string): string {
  return value.match(/https?:\/\/[^\s<>"']+/i)?.[0]?.replace(/[),.;\]}]+$/, "") ?? "";
}

function cleanTitle(value: string): string {
  return redactActivityText(value)
    .replace(/^#+\s*/, "")
    .replace(/^\*\*(.*)\*\*$/, "$1")
    .replace(/^__(.*)__$/, "$1")
    .trim();
}

function compactToolName(name: string): string {
  return name.toLowerCase().split(".").pop() || name.toLowerCase();
}

function webSearchScope(rawSite: string): string | undefined {
  const candidate = rawSite.replace(/^https?:\/\//i, "").replace(/^www\./i, "");
  let host = candidate.split("/")[0]?.toLowerCase();
  if (!host) return undefined;
  if (host.startsWith("www.")) host = host.slice(4);

  const knownScope = WEB_SEARCH_SCOPE_NAMES[host];
  return knownScope ?? displayWebHost(host);
}

const WEB_SEARCH_SCOPE_NAMES: Record<string, string> = {
  "anthropic.com": "Anthropic",
  "crunchbase.com": "Crunchbase",
  "github.com": "GitHub",
  "linkedin.com": "LinkedIn",
  "openai.com": "OpenAI",
  "reddit.com": "Reddit",
  "x.com": "X",
  "youtube.com": "YouTube",
};

function toolEventName(event: ToolProgressEvent): string {
  const functionName = (event as { function?: { name?: unknown } }).function?.name;
  if (typeof functionName === "string") return functionName;
  return typeof event.name === "string" ? event.name : "";
}

function toolEventArguments(event: ToolProgressEvent): unknown {
  const functionArgs = (event as { function?: { arguments?: unknown } }).function?.arguments;
  const raw = functionArgs ?? event.arguments;
  if (typeof raw !== "string") return raw ?? {};
  try {
    return raw.trim() ? JSON.parse(raw) : {};
  } catch {
    return {};
  }
}

function stringField(value: unknown, keys: string[]): string {
  if (!value || typeof value !== "object" || Array.isArray(value)) return "";
  const record = value as Record<string, unknown>;
  for (const key of keys) {
    const field = record[key];
    if (typeof field === "string" && field.trim()) return field.trim();
  }
  return "";
}

function readableError(error: unknown): string | undefined {
  if (typeof error === "string" && error.trim()) return safeErrorText(error);
  if (!error) return undefined;
  try {
    return safeErrorText(JSON.stringify(error));
  } catch {
    return "Web search failed";
  }
}

function safeErrorText(value: string): string {
  return safeActivityDetail(value, 240);
}
