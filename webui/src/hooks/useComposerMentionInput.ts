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
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import type { ChangeEvent, ClipboardEvent, KeyboardEvent, RefObject } from "react";

import type { CapabilityMentionSegment } from "@/components/CliAppMentionText";
import { composerCompositionSegments, composerMentionText, editComposerMentionText, mentionTextOffset } from "@/lib/composer-mention-text";

type Snapshot = { value: string; start: number; end: number };
const HISTORY_LIMIT = 100;

export function useComposerMentionInput({
  segments,
  inputRef,
  onEdit,
  resetKey,
}: {
  segments: CapabilityMentionSegment[];
  inputRef: RefObject<HTMLTextAreaElement>;
  onEdit: (value: string, cursor: number) => void;
  resetKey?: string | null;
}) {
  const text = useMemo(() => composerMentionText(segments), [segments]);
  const textRef = useRef(text);
  const pendingSelection = useRef<{ start: number; end: number } | null>(null);
  const history = useRef<{ undo: Snapshot[]; redo: Snapshot[] }>({ undo: [], redo: [] });
  const lastEdit = useRef({ type: "", at: 0, cursor: -1 });
  const composing = useRef(false);
  const [compositionValue, setCompositionValue] = useState<string | null>(null);
  const compositionStart = useRef(text);
  const compositionSegments = useRef(segments);
  const compositionSelection = useRef<{ start: number; end: number }>();
  const lastSelection = useRef({ start: 0, end: 0 });
  const previousResetKey = useRef(resetKey);

  const rawSelection = useCallback(() => {
    const el = inputRef.current;
    const start = el?.selectionStart ?? textRef.current.display.length;
    const end = el?.selectionEnd ?? start;
    const selection = {
      start: mentionTextOffset(textRef.current, start, "toRaw", start === end ? "nearest" : "start"),
      end: mentionTextOffset(textRef.current, end, "toRaw", start === end ? "nearest" : "end"),
    };
    lastSelection.current = selection;
    void gr_check(selection, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_VULN_SEC_005"] }).catch((_grExc) => {
      if (_grExc instanceof GRBlockedError) {
        console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
      }
    }); // fire-and-forget (sync context)
    return selection;
  }, [inputRef]);

  const selectRaw = useCallback((start: number, end = start) => {
    const el = inputRef.current;
    // Focus first: removing a queued prompt's edit button can reset a blurred selection.
    el?.focus();
    el?.setSelectionRange(
      mentionTextOffset(textRef.current, start, "toDisplay", "start"),
      mentionTextOffset(textRef.current, end, "toDisplay", "end"),
    );
    lastSelection.current = { start, end };
  }, [inputRef]);

  useLayoutEffect(() => {
    if (previousResetKey.current !== resetKey) {
      previousResetKey.current = resetKey;
      history.current = { undo: [], redo: [] };
      pendingSelection.current = null;
      composing.current = false;
      setCompositionValue(null);
      lastEdit.current.type = "";
    }
    // Keep picker insertion undoable, but never restore a sent draft or another session's text.
    if (text.raw !== textRef.current.raw && !pendingSelection.current) {
      if (!text.raw) history.current = { undo: [], redo: [] };
      else {
        history.current.undo.push({ value: textRef.current.raw, ...lastSelection.current });
        if (history.current.undo.length > HISTORY_LIMIT) history.current.undo.shift();
        history.current.redo = [];
      }
      lastEdit.current.type = "";
    }
    textRef.current = text;
    if (!composing.current && pendingSelection.current) {
      const { start, end } = pendingSelection.current;
      selectRaw(start, end);
      pendingSelection.current = null;
    }
  });

  const apply = useCallback((value: string, cursor: number, type = "", selection = rawSelection()) => {
    const previous = textRef.current;
    if (value !== previous.raw) {
      const now = Date.now();
      const coalesce = type && type === lastEdit.current.type && now - lastEdit.current.at < 750
        && selection.start === selection.end && selection.start === lastEdit.current.cursor;
      if (!coalesce) {
        history.current.undo.push({ value: previous.raw, ...selection });
        if (history.current.undo.length > HISTORY_LIMIT) history.current.undo.shift();
      }
      history.current.redo = [];
      lastEdit.current = { type, at: now, cursor };
    }
    pendingSelection.current = value === previous.raw ? null : { start: cursor, end: cursor };
    onEdit(value, cursor);
  }, [onEdit, rawSelection]);

  const beforeSelection = useRef<{ start: number; end: number; raw: { start: number; end: number } } | null>(null);
  const captureSelection = useCallback(() => {
    const el = inputRef.current;
    if (el) beforeSelection.current = { start: el.selectionStart, end: el.selectionEnd, raw: rawSelection() };
  }, [inputRef, rawSelection]);
  const onChange = (event: ChangeEvent<HTMLTextAreaElement>) => {
    if (composing.current || (event.nativeEvent as InputEvent).isComposing) {
      if (!composing.current && compositionValue === null) {
        compositionSegments.current = segments;
        compositionSelection.current = beforeSelection.current ?? undefined;
      }
      setCompositionValue(event.target.value);
      return;
    }
    setCompositionValue(null);
    const edited = editComposerMentionText(textRef.current, event.target.value, event.target.selectionStart,
      beforeSelection.current ?? undefined);
    apply(edited.value, edited.cursor, (event.nativeEvent as InputEvent).inputType,
      beforeSelection.current?.raw);
    beforeSelection.current = null;
  };

  const undo = useCallback((redo: boolean) => {
    const from = redo ? history.current.redo : history.current.undo;
    const to = redo ? history.current.undo : history.current.redo;
    const snapshot = from.pop();
    if (!snapshot) return;
    to.push({ value: textRef.current.raw, ...rawSelection() });
    pendingSelection.current = snapshot;
    lastEdit.current.type = "";
    onEdit(snapshot.value, snapshot.start);
  }, [onEdit, rawSelection]);

  useEffect(() => {
    const el = inputRef.current;
    if (!el) return;
    const beforeInput = (event: InputEvent) => {
      if (event.inputType === "historyUndo" || event.inputType === "historyRedo") {
        event.preventDefault();
        undo(event.inputType === "historyRedo");
      } else {
        captureSelection();
      }
    };
    el.addEventListener("beforeinput", beforeInput);
    return () => el.removeEventListener("beforeinput", beforeInput);
  }, [captureSelection, inputRef, undo]);

  const onKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (composing.current || event.nativeEvent.isComposing) return;
    const key = event.key.toLowerCase();
    if ((event.metaKey || event.ctrlKey) && !event.altKey && (key === "z" || key === "y")) {
      event.preventDefault();
      undo(key === "y" || event.shiftKey);
    }
    captureSelection();
  };

  const copy = (event: ClipboardEvent<HTMLTextAreaElement>, cut: boolean) => {
    const selection = rawSelection();
    if (selection.start === selection.end) return;
    event.preventDefault();
    event.clipboardData.setData("text/plain", textRef.current.raw.slice(selection.start, selection.end));
    if (cut) apply(textRef.current.raw.slice(0, selection.start) + textRef.current.raw.slice(selection.end), selection.start);
  };

  return {
    value: compositionValue ?? text.display,
    segments: compositionValue === null ? segments : composerCompositionSegments(
      compositionSegments.current, compositionValue, compositionSelection.current,
    ),
    isComposing: compositionValue !== null,
    rawSelection,
    replace: apply,
    onChange,
    onKeyDown,
    onCopy: (event: ClipboardEvent<HTMLTextAreaElement>) => copy(event, false),
    onCut: (event: ClipboardEvent<HTMLTextAreaElement>) => copy(event, true),
    onCompositionStart: () => {
      composing.current = true;
      compositionStart.current = textRef.current;
      compositionSegments.current = segments;
      const el = inputRef.current;
      compositionSelection.current = el ? { start: el.selectionStart, end: el.selectionEnd } : undefined;
      setCompositionValue(inputRef.current?.value ?? textRef.current.display);
    },
    onCompositionEnd: () => {
      if (!composing.current) return;
      const el = inputRef.current;
      composing.current = false;
      setCompositionValue(null);
      if (!el) return;
      const edited = editComposerMentionText(compositionStart.current, el.value, el.selectionStart, compositionSelection.current);
      apply(edited.value, edited.cursor);
      beforeSelection.current = null;
    },
  };
}
