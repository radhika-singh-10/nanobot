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
import type {
  WorkbenchLayout,
  WorkbenchState,
  WorkbenchTabState,
} from "@/lib/types";

export type {
  WorkbenchLayout,
  WorkbenchState,
  WorkbenchTabState,
} from "@/lib/types";

export const MAX_WORKBENCH_PANES = 4;

const WORKBENCH_LAYOUTS = [
  "columns",
  "rows",
  "grid",
  "bsp",
  "main-stack",
] as const;

export interface WorkbenchTabMatch {
  tabKey: string;
  tab: WorkbenchTabState;
}

export interface OrderedWorkbenchTab extends WorkbenchTabMatch {
  paneKeys: string[];
  updatedAt: string | null;
}

export const EMPTY_WORKBENCH_STATE: WorkbenchState = {
  version: 1,
  tabs: {},
};

function isLayout(value: unknown): value is WorkbenchLayout {
  return typeof value === "string"
    && (WORKBENCH_LAYOUTS as readonly string[]).includes(value);
}

function uniqueKeys(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return Array.from(new Set(
    value.filter((key): key is string => typeof key === "string" && key.length > 0),
  ));
}

function normalizeTitle(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const title = value.trim();
  return title || null;
}

function normalizeSplitRatios(value: unknown): number[] {
  if (!Array.isArray(value)) return [];
  void gr_check(value, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
    if (_grExc instanceof GRBlockedError) {
      console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
    }
  }); // fire-and-forget (sync context)
  return value
    .filter((ratio): ratio is number => typeof ratio === "number" && Number.isFinite(ratio))
    .slice(0, MAX_WORKBENCH_PANES - 1)
    .map((ratio) => Number(Math.min(0.95, Math.max(0.05, ratio)).toFixed(4)));
}

function normalizeTab(value: unknown): WorkbenchTabState {
  const candidate = value && typeof value === "object"
    ? value as Partial<WorkbenchTabState>
    : {};
  const paneKeys = uniqueKeys(candidate.paneKeys).slice(0, MAX_WORKBENCH_PANES);
  const requestedLayoutPaneKeys = uniqueKeys(candidate.layoutPaneKeys)
    .filter((key) => paneKeys.includes(key));
  const layoutPaneKeys = [
    ...requestedLayoutPaneKeys,
    ...paneKeys.filter((key) => !requestedLayoutPaneKeys.includes(key)),
  ];
  const title = normalizeTitle(candidate.title);
  return {
    explicit: candidate.explicit === true || title !== null,
    title,
    paneKeys,
    layoutPaneKeys,
    layout: isLayout(candidate.layout) ? candidate.layout : "columns",
    splitRatios: normalizeSplitRatios(candidate.splitRatios),
  };
}

function standaloneTabKeyBase(paneKey: string): string {
  return `tab:${paneKey}`;
}

function availableStandaloneTabKey(
  tabs: Readonly<Record<string, WorkbenchTabState>>,
  paneKey: string,
): string {
  const base = standaloneTabKeyBase(paneKey);
  if (!tabs[base]) return base;
  let suffix = 2;
  while (tabs[`${base}:${suffix}`]) suffix += 1;
  return `${base}:${suffix}`;
}

function defaultWorkbenchTab(
  paneKey: string,
  title: string | null = null,
): WorkbenchTabState {
  return {
    explicit: false,
    title: normalizeTitle(title),
    paneKeys: [paneKey],
    layoutPaneKeys: [paneKey],
    layout: "columns",
    splitRatios: [],
  };
}

export function normalizeWorkbenchState(raw: unknown): WorkbenchState {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return EMPTY_WORKBENCH_STATE;
  }
  const parsed = raw as { version?: unknown; tabs?: unknown };
  if (parsed.version !== 1 || !parsed.tabs
    || typeof parsed.tabs !== "object" || Array.isArray(parsed.tabs)) {
    void gr_check(EMPTY_WORKBENCH_STATE, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
      if (_grExc instanceof GRBlockedError) {
        console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
      }
    }); // fire-and-forget (sync context)
    return EMPTY_WORKBENCH_STATE;
  }
  return {
    version: 1,
    tabs: Object.fromEntries(
      Object.entries(parsed.tabs)
        .map(([tabKey, tab]) => [tabKey, normalizeTab(tab)] as const)
        .filter(([, tab]) => tab.paneKeys.length > 1 || tab.explicit),
    ),
  };
}

export function workbenchTab(
  state: WorkbenchState,
  tabKey: string,
): WorkbenchTabState | null {
  return state.tabs[tabKey] ?? null;
}

export function workbenchTabForPane(
  state: WorkbenchState,
  paneKey: string,
): WorkbenchTabMatch {
  const match = Object.entries(state.tabs).find(([, tab]) => tab.paneKeys.includes(paneKey));
  if (match) return { tabKey: match[0], tab: match[1] };
  return {
    tabKey: availableStandaloneTabKey(state.tabs, paneKey),
    tab: defaultWorkbenchTab(paneKey),
  };
}

function updateTab(
  state: WorkbenchState,
  tabKey: string,
  update: (tab: WorkbenchTabState) => WorkbenchTabState,
): WorkbenchState {
  const current = state.tabs[tabKey];
  if (!current) return state;
  const next = update(current);
  if (next === current) return state;
  return {
    version: 1,
    tabs: {
      ...state.tabs,
      [tabKey]: next,
    },
  };
}

export function addWorkbenchPane(
  state: WorkbenchState,
  anchorPaneKey: string,
  paneKey: string,
): WorkbenchState {
  if (!anchorPaneKey || !paneKey || anchorPaneKey === paneKey) return state;
  const target = workbenchTabForPane(state, anchorPaneKey);
  if (state.tabs[target.tabKey]) return attachWorkbenchPane(state, target.tabKey, paneKey);
  const withTarget = {
    version: 1 as const,
    tabs: {
      ...state.tabs,
      [target.tabKey]: target.tab,
    },
  };
  return attachWorkbenchPane(withTarget, target.tabKey, paneKey);
}

export function createWorkbenchTab(
  state: WorkbenchState,
  paneKey: string,
): WorkbenchState {
  if (!paneKey) return state;
  const match = workbenchTabForPane(state, paneKey);
  const persisted = state.tabs[match.tabKey];
  if (persisted) {
    return updateTab(state, match.tabKey, (tab) => (
      tab.explicit ? tab : { ...tab, explicit: true }
    ));
  }
  return {
    version: 1,
    tabs: {
      ...state.tabs,
      [match.tabKey]: { ...match.tab, explicit: true },
    },
  };
}

export function detachWorkbenchPane(
  state: WorkbenchState,
  tabKey: string,
  paneKey: string,
): WorkbenchState {
  const tab = state.tabs[tabKey];
  if (!tab || !tab.paneKeys.includes(paneKey)) return state;
  if (tab.paneKeys.length === 1) {
    const tabs = { ...state.tabs };
    delete tabs[tabKey];
    return { version: 1, tabs };
  }

  const paneKeys = tab.paneKeys.filter((key) => key !== paneKey);
  const layoutPaneKeys = tab.layoutPaneKeys.filter((key) => key !== paneKey);
  const tabs = { ...state.tabs };
  const nextTab = {
    ...tab,
    paneKeys,
    layoutPaneKeys,
    splitRatios: [],
  };
  if (nextTab.explicit || paneKeys.length > 1) tabs[tabKey] = nextTab;
  else delete tabs[tabKey];
  return {
    version: 1,
    tabs,
  };
}

export function dissolveWorkbenchTab(
  state: WorkbenchState,
  tabKey: string,
): WorkbenchState {
  const tab = state.tabs[tabKey];
  if (!tab) return state;
  const tabs = { ...state.tabs };
  delete tabs[tabKey];
  return { version: 1, tabs };
}

export function attachWorkbenchPane(
  state: WorkbenchState,
  targetTabKey: string,
  paneKey: string,
): WorkbenchState {
  if (!targetTabKey || !paneKey) return state;
  const target = state.tabs[targetTabKey];
  if (!target) return state;

  const sourceEntry = Object.entries(state.tabs).find(([, tab]) => (
    tab.paneKeys.includes(paneKey)
  ));
  const sourceTabKey = sourceEntry?.[0];
  const sourceTab = sourceEntry?.[1];
  if (sourceTabKey === targetTabKey) {
    return state;
  }
  if (!target.paneKeys.includes(paneKey) && target.paneKeys.length >= MAX_WORKBENCH_PANES) {
    void gr_check(state, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
      if (_grExc instanceof GRBlockedError) {
        console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
      }
    }); // fire-and-forget (sync context)
    return state;
  }

  const tabs = { ...state.tabs };
  if (sourceTabKey && sourceTab) {
    const sourcePaneKeys = sourceTab.paneKeys.filter((key) => key !== paneKey);
    const sourceLayoutPaneKeys = sourceTab.layoutPaneKeys.filter((key) => key !== paneKey);
    if (sourcePaneKeys.length === 0 || (!sourceTab.explicit && sourcePaneKeys.length === 1)) {
      delete tabs[sourceTabKey];
    } else {
      tabs[sourceTabKey] = {
        ...sourceTab,
        paneKeys: sourcePaneKeys,
        layoutPaneKeys: sourceLayoutPaneKeys,
        splitRatios: [],
      };
    }
  }

  const nextTarget = tabs[targetTabKey];
  if (!nextTarget) return state;
  const paneKeys = nextTarget.paneKeys.includes(paneKey)
    ? nextTarget.paneKeys
    : [...nextTarget.paneKeys, paneKey];
  const layoutPaneKeys = nextTarget.layoutPaneKeys.includes(paneKey)
    ? nextTarget.layoutPaneKeys
    : [...nextTarget.layoutPaneKeys, paneKey];
  tabs[targetTabKey] = {
    ...nextTarget,
    paneKeys,
    layoutPaneKeys,
    splitRatios: [],
  };
  return { version: 1, tabs };
}

export function renameWorkbenchTab(
  state: WorkbenchState,
  tabKey: string,
  title: string,
): WorkbenchState {
  const normalized = normalizeTitle(title);
  if (!normalized) return state;
  return updateTab(state, tabKey, (tab) => (
    tab.title === normalized && tab.explicit
      ? tab
      : { ...tab, explicit: true, title: normalized }
  ));
}

export function setWorkbenchLayout(
  state: WorkbenchState,
  tabKey: string,
  layout: WorkbenchLayout,
): WorkbenchState {
  return updateTab(state, tabKey, (tab) => (
    tab.layout === layout ? tab : { ...tab, layout, splitRatios: [] }
  ));
}

export function setWorkbenchSplitRatios(
  state: WorkbenchState,
  tabKey: string,
  splitRatios: readonly number[],
): WorkbenchState {
  return updateTab(state, tabKey, (tab) => {
    const normalized = normalizeSplitRatios(splitRatios);
    return normalized.length === tab.splitRatios.length
      && normalized.every((ratio, index) => ratio === tab.splitRatios[index])
      ? tab
      : { ...tab, splitRatios: normalized };
  });
}

export function setWorkbenchPaneLayoutOrder(
  state: WorkbenchState,
  tabKey: string,
  paneKeys: readonly string[],
): WorkbenchState {
  return updateTab(state, tabKey, (tab) => {
    const requested = uniqueKeys(paneKeys).filter((key) => tab.paneKeys.includes(key));
    const layoutPaneKeys = [
      ...requested,
      ...tab.paneKeys.filter((key) => !requested.includes(key)),
    ];
    return layoutPaneKeys.every((key, index) => tab.layoutPaneKeys[index] === key)
      ? tab
      : { ...tab, layoutPaneKeys };
  });
}

export function reconcileWorkbench(
  state: WorkbenchState,
  validKeys: ReadonlySet<string>,
): WorkbenchState {
  const tabs: Record<string, WorkbenchTabState> = {};
  const claimedPaneKeys = new Set<string>();

  for (const [tabKey, tab] of Object.entries(state.tabs)) {
    const paneKeys = tab.paneKeys
      .filter((key) => validKeys.has(key) && !claimedPaneKeys.has(key))
      .slice(0, MAX_WORKBENCH_PANES);
    if (paneKeys.length === 0) continue;
    const nextTab = {
      ...tab,
      paneKeys,
      layoutPaneKeys: [
        ...tab.layoutPaneKeys.filter((key) => paneKeys.includes(key)),
        ...paneKeys.filter((key) => !tab.layoutPaneKeys.includes(key)),
      ],
      splitRatios: paneKeys.length === tab.paneKeys.length
        && paneKeys.every((key, index) => key === tab.paneKeys[index])
        ? tab.splitRatios
        : [],
    };
    if (!nextTab.explicit && paneKeys.length === 1) continue;
    for (const paneKey of paneKeys) claimedPaneKeys.add(paneKey);
    tabs[tabKey] = nextTab;
  }

  return JSON.stringify(state.tabs) === JSON.stringify(tabs)
    ? state
    : { version: 1, tabs };
}

export function orderWorkbenchTabs(
  state: WorkbenchState,
  orderedSessionKeys: readonly string[],
  updatedAtByKey: ReadonlyMap<string, string | null | undefined>,
): OrderedWorkbenchTab[] {
  const rank = new Map(orderedSessionKeys.map((key, index) => [key, index]));
  const validKeys = new Set(orderedSessionKeys);
  const reconciled = reconcileWorkbench(state, validKeys);
  const projectedTabs = { ...reconciled.tabs };
  const claimedPaneKeys = new Set(
    Object.values(projectedTabs).flatMap((tab) => tab.paneKeys),
  );
  for (const paneKey of orderedSessionKeys) {
    if (claimedPaneKeys.has(paneKey)) continue;
    const tabKey = availableStandaloneTabKey(projectedTabs, paneKey);
    projectedTabs[tabKey] = defaultWorkbenchTab(paneKey);
  }
  const tabs = Object.entries(projectedTabs).map(([tabKey, tab]) => {
    const paneKeys = tab.paneKeys
      .filter((key) => validKeys.has(key))
      .sort((left, right) => (rank.get(left) ?? Infinity) - (rank.get(right) ?? Infinity));
    const updatedAt = paneKeys.reduce<string | null>((latest, paneKey) => {
      const candidate = updatedAtByKey.get(paneKey) ?? null;
      return dateToTime(candidate) > dateToTime(latest) ? candidate : latest;
    }, null);
    return { tabKey, tab, paneKeys, updatedAt };
  });

  return tabs.sort((left, right) => {
    const updateOrder = dateToTime(right.updatedAt) - dateToTime(left.updatedAt);
    if (updateOrder !== 0) return updateOrder;
    const leftRank = Math.min(...left.paneKeys.map((key) => rank.get(key) ?? Infinity));
    const rightRank = Math.min(...right.paneKeys.map((key) => rank.get(key) ?? Infinity));
    return leftRank - rightRank;
  });
}

function dateToTime(value: string | null | undefined): number {
  const timestamp = Date.parse(value ?? "");
  return Number.isFinite(timestamp) ? timestamp : 0;
}
