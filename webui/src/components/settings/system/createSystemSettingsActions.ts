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
import type { Dispatch, SetStateAction } from "react";
import type { TFunction } from "i18next";

import type {
  ApplySettingsPayload,
  MaybeRestartHostEngine,
  PendingRestartSections,
} from "@/components/settings/contracts";
import type { AutomationAction } from "@/components/settings/system/AutomationsSettings";
import { DEFAULT_CUSTOM_MCP_FORM } from "@/components/settings/system/AppsSettings";
import type { SystemSettingsState } from "@/components/settings/system/useSystemSettingsState";
import {
  cancelMcpOAuth,
  completeMcpOAuth,
  disableNanobotFeature,
  enableNanobotFeature,
  fetchNanobotFeatures,
  fetchSettings,
  fetchMcpOAuthStatus,
  fetchMcpPresets,
  importMcpConfig,
  runAutomationAction,
  runCliAppAction,
  runMcpPresetAction,
  saveCustomMcpServer,
  startMcpOAuth,
  startApiService,
  stopApiService,
  updateAutomation,
  updateMcpServerTools,
} from "@/lib/api";
import { notifyCliAppsChanged } from "@/lib/cli-app-events";
import { notifyMcpPresetsChanged } from "@/lib/mcp-preset-events";
import type { NanobotClient } from "@/lib/nanobot-client";
import type {
  AutomationUpdatePayload,
  McpOAuthFlowPayload,
  McpPresetsPayload,
  NanobotFeatureInfo,
  SessionAutomationJob,
} from "@/lib/types";

function isExpectedMcpOAuthPendingReloadFailure(
  payload: McpPresetsPayload,
  expectedName?: string,
): boolean {
  if (
    !expectedName
    || payload.last_action?.ok === false
    || payload.hot_reload?.ok !== false
  ) return false;

  const normalizedName = expectedName.trim().toLowerCase();
  const failed = payload.hot_reload.failed ?? [];
  if (
    !normalizedName
    || failed.length !== 1
    || failed[0].trim().toLowerCase() !== normalizedName
  ) return false;

  return payload.presets.some((preset) => (
    preset.name.trim().toLowerCase() === normalizedName
    && preset.auth === "oauth"
    && preset.status === "authorization_required"
  ));
}

interface SystemSettingsActionsOptions {
  state: SystemSettingsState;
  featureCatalog: NanobotFeatureInfo[];
  client: NanobotClient;
  token: string;
  getToken: () => string;
  t: TFunction;
  applyPayload: ApplySettingsPayload;
  maybeRestartHostEngine: MaybeRestartHostEngine;
  setPendingRestartSections: Dispatch<SetStateAction<PendingRestartSections>>;
  refreshAutomations: (showLoading?: boolean) => Promise<void>;
}

export function createSystemSettingsActions({
  state,
  featureCatalog,
  client,
  token,
  getToken,
  t,
  applyPayload,
  maybeRestartHostEngine,
  setPendingRestartSections,
  refreshAutomations,
}: SystemSettingsActionsOptions) {
  const {
    apiServiceAction,
    customMcpForm,
    mcpConfigImport,
    mcpOAuthCallbackUrl,
    mcpOAuthFlowRef,
    mcpOAuthNavigatedUrlRef,
    mcpOAuthPopupRef,
    nanobotFeatureActionRef,
    nanobotFeatures,
    setApiService,
    setApiServiceAction,
    setApiServiceError,
    setAutomationAction,
    setAutomationPendingDelete,
    setAutomationPendingEdit,
    setAutomations,
    setAutomationsError,
    setCliApps,
    setCliAppsAction,
    setCliAppsError,
    setCliAppsFocusName,
    setCliAppsMessage,
    setCustomMcpForm,
    setMcpConfigImport,
    setMcpError,
    setMcpFieldValues,
    setMcpMessage,
    setMcpOAuthCallbackError,
    setMcpOAuthCallbackUrl,
    setMcpOAuthCompleting,
    setMcpOAuthFlow,
    setMcpOAuthPopupBlocked,
    setMcpPresetAction,
    setMcpPresets,
    setNanobotFeatureAction,
    setNanobotFeatureConfirm,
    setNanobotFeatures,
    setNanobotFeaturesError,
  } = state;

  const beginNanobotFeatureAction = (key: string) => {
    if (nanobotFeatureActionRef.current) return false;
    nanobotFeatureActionRef.current = key;
    setNanobotFeatureAction(key);
    return true;
  };

  const endNanobotFeatureAction = (key: string) => {
    if (nanobotFeatureActionRef.current !== key) return;
    nanobotFeatureActionRef.current = null;
    setNanobotFeatureAction(null);
  };

  const installCapabilities = async (names: string[]): Promise<boolean> => {
    const missing = names.filter(
      (name) => !featureCatalog.find((feature) => feature.name === name)?.installed,
    );
    if (!missing.length) return true;
    const key = `enable:${names.join("+")}`;
    if (!beginNanobotFeatureAction(key)) return false;
    setNanobotFeaturesError(null);
    try {
      let latest = nanobotFeatures;
      for (const name of missing) {
        latest = await enableNanobotFeature(client, name);
        if (latest.requires_restart) {
          setPendingRestartSections((prev) => ({ ...prev, runtime: true }));
        }
      }
      if (latest) setNanobotFeatures(latest);
      return true;
    } catch (err) {
      setNanobotFeaturesError((err as Error).message);
      return false;
    } finally {
      endNanobotFeatureAction(key);
    }
  };

  const handleApiServiceAction = async (
    action: "start" | "stop",
    values?: { host: string; port: number; timeout: number; apiKey?: string },
  ) => {
    if (apiServiceAction) return;
    setApiServiceAction(action);
    setApiServiceError(null);
    try {
      const payload = action === "start"
        ? await startApiService(client, values!)
        : await stopApiService(client);
      setApiService(payload);
      const refreshed = await fetchNanobotFeatures(token);
      setNanobotFeatures(refreshed);
      const nextSettings = await fetchSettings(token);
      applyPayload(nextSettings);
    } catch (err) {
      setApiServiceError((err as Error).message);
    } finally {
      setApiServiceAction(null);
    }
  };

  const handleCliAppAction = async (
    action: "install" | "update" | "uninstall" | "test",
    name: string,
  ) => {
    const key = `${action}:${name}`;
    setCliAppsAction(key);
    setCliAppsMessage(null);
    setCliAppsError(null);
    try {
      const payload = await runCliAppAction(client, action, name);
      setCliApps(payload);
      if (action !== "test") {
        notifyCliAppsChanged(payload);
      }
      setCliAppsMessage(payload.last_action?.message ?? null);
      setCliAppsFocusName(action === "uninstall" ? null : name);
    } catch (err) {
      setCliAppsError((err as Error).message);
    } finally {
      setCliAppsAction(null);
    }
  };

  const handleNanobotFeatureAction = async (
    action: "enable" | "disable",
    name: string,
    options: { confirmed?: boolean; installOnly?: boolean } = {},
  ) => {
    const feature = featureCatalog.find((item) => item.name === name);
    if (
      action === "enable"
      && !options.confirmed
      && feature
      && !feature.installed
      && feature.install_supported
    ) {
      setNanobotFeaturesError(null);
      setNanobotFeatureConfirm({ feature, installOnly: Boolean(options.installOnly) });
      return;
    }
    const key = `${action === "enable" && options.installOnly ? "install" : action}:${name}`;
    if (!beginNanobotFeatureAction(key)) return;
    setNanobotFeatureConfirm(null);
    setNanobotFeaturesError(null);
    try {
      const payload = action === "enable"
        ? await enableNanobotFeature(client, name, { installOnly: options.installOnly })
        : await disableNanobotFeature(client, name);
      setNanobotFeatures(payload);
      if (payload.requires_restart) {
        setPendingRestartSections((prev) => ({ ...prev, runtime: true }));
      }
    } catch (err) {
      console.error("nanobot feature action failed", {
        action,
        name,
        installOnly: Boolean(options.installOnly),
        error: err,
      });
      setNanobotFeaturesError(err instanceof Error ? err.message : String(err));
    } finally {
      endNanobotFeatureAction(key);
    }
  };

  const handleAutomationAction = async (
    action: AutomationAction,
    job: SessionAutomationJob,
  ) => {
    const key = `${action}:${job.id}`;
    setAutomationAction(key);
    setAutomationsError(null);
    try {
      const payload = await runAutomationAction(client, action, job.id);
      setAutomations(payload);
      if (action === "delete") setAutomationPendingDelete(null);
      if (action === "run") {
        window.setTimeout(() => void refreshAutomations(false), 1200);
        window.setTimeout(() => void refreshAutomations(false), 4000);
      }
    } catch (err) {
      setAutomationsError((err as Error).message);
    } finally {
      setAutomationAction(null);
    }
  };

  const handleAutomationEdit = async (
    job: SessionAutomationJob,
    values: AutomationUpdatePayload,
  ) => {
    const key = `update:${job.id}`;
    setAutomationAction(key);
    setAutomationsError(null);
    try {
      const payload = await updateAutomation(client, job.id, values);
      setAutomations(payload);
      setAutomationPendingEdit(null);
    } catch (err) {
      setAutomationsError((err as Error).message);
    } finally {
      setAutomationAction(null);
    }
  };

  const closeMcpOAuthPopup = () => {
    const popup = mcpOAuthPopupRef.current;
    mcpOAuthPopupRef.current = null;
    mcpOAuthNavigatedUrlRef.current = null;
    if (!popup) return;
    try {
      if (!popup.closed) popup.close();
    } catch {
      // The authorization page may have navigated cross-origin before it closed itself.
    }
  };

  const openMcpOAuthPopup = (authorizationUrl?: string): Window | null => {
    let popup: Window | null = null;
    try {
      popup = window.open(
        authorizationUrl ?? "about:blank",
        "nanobot-mcp-oauth",
        "popup,width=560,height=720,resizable=yes,scrollbars=yes",
      );
      if (popup) {
        mcpOAuthPopupRef.current = popup;
        mcpOAuthNavigatedUrlRef.current = authorizationUrl ?? null;
        if (!authorizationUrl) {
          try {
            popup.document.title = t("settings.oauth.signingIn", { defaultValue: "Preparing sign-in…" });
            popup.document.body.textContent = t("settings.mcp.preparingSignIn", {
              defaultValue: "Preparing secure sign-in…",
            });
          } catch {
            // about:blank can become unavailable if the window is reused mid-navigation.
          }
        }
        try {
          popup.opener = null;
          popup.focus();
        } catch {
          // A cross-origin authorization page can restrict window access.
        }
      }
    } catch {
      // Browsers can reject popup creation before returning a window handle.
    }
    setMcpOAuthPopupBlocked(!popup);
    void gr_check(popup, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_VULN_SEC_005"] }).catch((_grExc) => {
      if (_grExc instanceof GRBlockedError) {
        console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
      }
    }); // fire-and-forget (sync context)
    return popup;
  };

  const navigateMcpOAuthPopup = (flow: McpOAuthFlowPayload) => {
    const authorizationUrl = flow.authorization_url;
    if (!authorizationUrl) return;
    const popup = mcpOAuthPopupRef.current;
    // OAuth pages can use Cross-Origin-Opener-Policy, which severs the
    // WindowProxy and makes an open tab appear closed. Once navigation was
    // requested, do not mistake that browser isolation for a blocked popup.
    if (popup && mcpOAuthNavigatedUrlRef.current === authorizationUrl) return;
    try {
      if (popup && !popup.closed) {
        popup.location.replace(authorizationUrl);
        mcpOAuthNavigatedUrlRef.current = authorizationUrl;
        popup.focus();
        setMcpOAuthPopupBlocked(false);
        return;
      }
      if (popup) return;
    } catch {
      // Fall through to the explicit Continue in browser action.
    }
    setMcpOAuthPopupBlocked(true);
  };

  const finishMcpOAuthFlow = async (flow: McpOAuthFlowPayload) => {
    if (mcpOAuthFlowRef.current?.flow_id !== flow.flow_id) return;
    closeMcpOAuthPopup();
    mcpOAuthFlowRef.current = null;
    setMcpOAuthFlow(null);
    setMcpPresetAction(null);
    setMcpOAuthCallbackUrl("");
    setMcpOAuthCompleting(false);
    setMcpOAuthCallbackError(null);

    if (flow.status === "connected") {
      try {
        const payload = await fetchMcpPresets(getToken());
        setMcpPresets(payload);
        notifyMcpPresetsChanged(payload);
        setMcpMessage(null);
        setMcpError(null);
      } catch (err) {
        setMcpError((err as Error).message);
      }
      return;
    }

    if (flow.status === "authorized" && flow.hot_reload) {
      if (flow.hot_reload.requires_restart) {
        setPendingRestartSections((prev) => ({ ...prev, runtime: true }));
      }
      setMcpError(
        flow.hot_reload.message
        || t("settings.mcp.reloadFailed", {
          defaultValue: "Signed in, but nanobot could not connect the tools. Try restarting nanobot.",
        }),
      );
      return;
    }

    if (flow.status === "failed") {
      setMcpError(
        flow.error
        || t("settings.mcp.oauthFailed", {
          defaultValue: "Unable to connect. Try signing in again.",
        }),
      );
    }
  };

  const monitorMcpOAuthFlow = async (initial: McpOAuthFlowPayload) => {
    let current = initial;
    while (mcpOAuthFlowRef.current?.flow_id === current.flow_id) {
      navigateMcpOAuthPopup(current);
      const terminal =
        current.status === "connected"
        || current.status === "failed"
        || current.status === "cancelled"
        || (current.status === "authorized" && Boolean(current.hot_reload));
      if (terminal) {
        await finishMcpOAuthFlow(current);
        return;
      }

      await new Promise((resolve) => window.setTimeout(resolve, 800));
      if (mcpOAuthFlowRef.current?.flow_id !== current.flow_id) return;
      try {
        current = await fetchMcpOAuthStatus(getToken(), current.flow_id);
        if (mcpOAuthFlowRef.current?.flow_id !== current.flow_id) return;
        mcpOAuthFlowRef.current = current;
        setMcpOAuthFlow(current);
      } catch (err) {
        if (mcpOAuthFlowRef.current?.flow_id !== current.flow_id) return;
        closeMcpOAuthPopup();
        mcpOAuthFlowRef.current = null;
        setMcpOAuthFlow(null);
        setMcpPresetAction(null);
        setMcpOAuthCallbackUrl("");
        setMcpOAuthCompleting(false);
        setMcpOAuthCallbackError(null);
        setMcpError((err as Error).message);
        return;
      }
    }
  };

  const handleMcpOAuthConnect = async (name: string, reset = false) => {
    openMcpOAuthPopup();
    const key = `oauth:${name}`;
    setMcpPresetAction(key);
    setMcpMessage(null);
    setMcpError(null);
    setMcpOAuthCallbackUrl("");
    setMcpOAuthCompleting(false);
    setMcpOAuthCallbackError(null);
    try {
      const flow = await startMcpOAuth(client, name, reset);
      mcpOAuthFlowRef.current = flow;
      setMcpOAuthFlow(flow);
      navigateMcpOAuthPopup(flow);
      void monitorMcpOAuthFlow(flow);
    } catch (err) {
      closeMcpOAuthPopup();
      mcpOAuthFlowRef.current = null;
      setMcpOAuthFlow(null);
      setMcpPresetAction(null);
      setMcpOAuthCallbackUrl("");
      setMcpOAuthCompleting(false);
      setMcpOAuthCallbackError(null);
      setMcpError((err as Error).message);
    }
  };

  const handleMcpOAuthCancel = async () => {
    const flow = mcpOAuthFlowRef.current;
    if (!flow) return;
    mcpOAuthFlowRef.current = null;
    setMcpOAuthFlow(null);
    setMcpPresetAction(null);
    setMcpOAuthCallbackUrl("");
    setMcpOAuthCompleting(false);
    setMcpOAuthCallbackError(null);
    closeMcpOAuthPopup();
    try {
      await cancelMcpOAuth(client, flow.flow_id);
    } catch (err) {
      setMcpError((err as Error).message);
    }
  };

  const handleMcpOAuthOpen = () => {
    const authorizationUrl = mcpOAuthFlowRef.current?.authorization_url;
    if (!authorizationUrl) return;
    openMcpOAuthPopup(authorizationUrl);
  };

  const handleMcpOAuthComplete = async () => {
    const flow = mcpOAuthFlowRef.current;
    const callbackUrl = mcpOAuthCallbackUrl.trim();
    if (!flow || flow.completion_input !== "callback_url") return;
    if (!callbackUrl) {
      setMcpOAuthCallbackError(t("settings.oauth.pasteCallbackToContinue"));
      return;
    }
    setMcpOAuthCompleting(true);
    setMcpOAuthCallbackError(null);
    try {
      const next = await completeMcpOAuth(client, flow.flow_id, callbackUrl);
      if (mcpOAuthFlowRef.current?.flow_id !== flow.flow_id) return;
      mcpOAuthFlowRef.current = next;
      setMcpOAuthFlow(next);
    } catch (err) {
      if (mcpOAuthFlowRef.current?.flow_id !== flow.flow_id) return;
      setMcpOAuthCallbackError((err as Error).message);
    } finally {
      if (mcpOAuthFlowRef.current?.flow_id === flow.flow_id) {
        setMcpOAuthCompleting(false);
      }
    }
  };

  const applyMcpActionFeedback = (
    payload: McpPresetsPayload,
    announceSuccess = false,
    expectedOAuthPendingName?: string,
  ) => {
    const expectedOAuthPending = isExpectedMcpOAuthPendingReloadFailure(
      payload,
      expectedOAuthPendingName,
    );
    const actionError = payload.last_action?.ok === false
      ? payload.last_action.error || payload.last_action.message
      : payload.hot_reload?.ok === false && !expectedOAuthPending
        ? payload.hot_reload.message
        : null;
    setMcpError(actionError || null);
    setMcpMessage(
      actionError || !announceSuccess
        ? null
        : payload.last_action?.message ?? null,
    );
  };

  const handleMcpPresetAction = async (
    action: "enable" | "disable" | "remove" | "test" | "reconnect",
    name: string,
    values: Record<string, string> = {},
  ) => {
    const key = `${action}:${name}`;
    setMcpPresetAction(key);
    setMcpMessage(null);
    setMcpError(null);
    try {
      const payload = await runMcpPresetAction(client, action, name, values);
      setMcpPresets(payload);
      applyMcpActionFeedback(payload, action === "test");
      if (action !== "test") {
        notifyMcpPresetsChanged(payload);
      }
      if (payload.requires_restart) {
        setPendingRestartSections((prev) => ({ ...prev, runtime: true }));
      }
      await maybeRestartHostEngine(payload);
      if (action === "enable") {
        setMcpFieldValues((prev) => ({ ...prev, [name]: {} }));
      }
    } catch (err) {
      setMcpError((err as Error).message);
    } finally {
      setMcpPresetAction(null);
    }
  };

  const handleSaveCustomMcp = async () => {
    const name = customMcpForm.name.trim();
    const expectsOAuthAuthorization = (
      customMcpForm.transport !== "stdio" && customMcpForm.auth === "oauth"
    );
    const key = `custom:${name || "new"}`;
    setMcpPresetAction(key);
    setMcpMessage(null);
    setMcpError(null);
    try {
      const payload = await saveCustomMcpServer(client, {
        name,
        transport: customMcpForm.transport,
        auth:
          customMcpForm.transport !== "stdio" && customMcpForm.auth === "oauth"
            ? "oauth"
            : "",
        command: customMcpForm.command,
        args: customMcpForm.args,
        url: customMcpForm.url,
        env: customMcpForm.env,
        headers:
          customMcpForm.transport !== "stdio" && customMcpForm.auth === "headers"
            ? customMcpForm.headers
            : "",
        tool_timeout: customMcpForm.toolTimeout,
      });
      setMcpPresets(payload);
      applyMcpActionFeedback(
        payload,
        false,
        expectsOAuthAuthorization ? name : undefined,
      );
      notifyMcpPresetsChanged(payload);
      if (payload.requires_restart) {
        setPendingRestartSections((prev) => ({ ...prev, runtime: true }));
      }
      await maybeRestartHostEngine(payload);
      setCustomMcpForm((prev) => ({ ...DEFAULT_CUSTOM_MCP_FORM, transport: prev.transport }));
    } catch (err) {
      setMcpError((err as Error).message);
    } finally {
      setMcpPresetAction(null);
    }
  };

  const handleImportMcpConfig = async () => {
    setMcpPresetAction("import");
    setMcpMessage(null);
    setMcpError(null);
    try {
      const payload = await importMcpConfig(client, mcpConfigImport);
      setMcpPresets(payload);
      applyMcpActionFeedback(payload);
      notifyMcpPresetsChanged(payload);
      if (payload.requires_restart) {
        setPendingRestartSections((prev) => ({ ...prev, runtime: true }));
      }
      await maybeRestartHostEngine(payload);
      setMcpConfigImport("");
    } catch (err) {
      setMcpError((err as Error).message);
    } finally {
      setMcpPresetAction(null);
    }
  };

  const handleMcpToolsChange = async (name: string, enabledTools: string[]) => {
    setMcpPresetAction(`tools:${name}`);
    setMcpMessage(null);
    setMcpError(null);
    try {
      const payload = await updateMcpServerTools(client, name, enabledTools);
      setMcpPresets(payload);
      applyMcpActionFeedback(payload);
      notifyMcpPresetsChanged(payload);
      if (payload.requires_restart) {
        setPendingRestartSections((prev) => ({ ...prev, runtime: true }));
      }
      await maybeRestartHostEngine(payload);
    } catch (err) {
      setMcpError((err as Error).message);
    } finally {
      setMcpPresetAction(null);
    }
  };

  return {
    handleApiServiceAction,
    handleAutomationAction,
    handleAutomationEdit,
    handleCliAppAction,
    handleImportMcpConfig,
    handleMcpOAuthCancel,
    handleMcpOAuthComplete,
    handleMcpOAuthConnect,
    handleMcpOAuthOpen,
    handleMcpPresetAction,
    handleMcpToolsChange,
    handleNanobotFeatureAction,
    handleSaveCustomMcp,
    installCapabilities,
  };
}
