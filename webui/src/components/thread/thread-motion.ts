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
  ThreadCameraController,
  ThreadCameraFollowResult,
} from "@/components/thread/thread-camera";

type ThreadMotionMode =
  | "idle"
  | "follow-latest"
  | "anchor-prompt"
  | "follow-output"
  | "follow-completion"
  | "navigating-latest"
  | "navigating-history"
  | "browsing-history";

type AutomaticThreadMotionMode =
  | "idle"
  | "follow-latest"
  | "anchor-prompt"
  | "follow-output";

type ThreadMotionEvent =
  | "navigate-latest"
  | "navigate-history"
  | "navigation-settled"
  | "user-scroll"
  | "boundary-scroll"
  | "composer-input"
  | "turn-completed"
  | "resume-follow";

type ThreadMotionTransition = ThreadMotionMode | "current-automatic-mode";

const THREAD_MOTION_TRANSITIONS: Readonly<
  Record<
    ThreadMotionMode,
    Readonly<Partial<Record<ThreadMotionEvent, ThreadMotionTransition>>>
  >
> = {
  idle: {
    "navigate-latest": "navigating-latest",
    "navigate-history": "navigating-history",
    "user-scroll": "browsing-history",
    "resume-follow": "current-automatic-mode",
  },
  "follow-latest": {
    "navigate-history": "navigating-history",
    "user-scroll": "browsing-history",
  },
  "anchor-prompt": {
    "navigate-latest": "navigating-latest",
    "navigate-history": "navigating-history",
    "user-scroll": "browsing-history",
    "turn-completed": "follow-completion",
  },
  "follow-output": {
    "navigate-latest": "navigating-latest",
    "navigate-history": "navigating-history",
    "user-scroll": "browsing-history",
    "turn-completed": "follow-completion",
  },
  "follow-completion": {
    "navigate-latest": "navigating-latest",
    "navigate-history": "navigating-history",
    "user-scroll": "browsing-history",
    "composer-input": "idle",
  },
  "navigating-latest": {
    "navigate-latest": "navigating-latest",
    "navigate-history": "navigating-history",
    "navigation-settled": "current-automatic-mode",
    "user-scroll": "browsing-history",
    "boundary-scroll": "browsing-history",
    "resume-follow": "current-automatic-mode",
  },
  "navigating-history": {
    "navigate-latest": "navigating-latest",
    "navigate-history": "navigating-history",
    "navigation-settled": "browsing-history",
    "user-scroll": "browsing-history",
    "boundary-scroll": "browsing-history",
    "resume-follow": "current-automatic-mode",
  },
  "browsing-history": {
    "navigate-latest": "navigating-latest",
    "navigate-history": "navigating-history",
    "resume-follow": "current-automatic-mode",
  },
};

export interface ThreadMotionGeometry {
  scrollTop: number;
  scrollHeight: number;
  clientHeight: number;
  maxScrollTop: number;
  composerHeight: number;
  promptTop: number | null;
}

interface ThreadMotionTurn {
  id: string | null;
  promptId: string | null;
  hasOutput: boolean;
  entry?: "submitted" | "restored";
}

interface ThreadMotionSnapshot {
  mode: ThreadMotionMode;
  turnId: string | null;
  promptId: string | null;
  promptPositioned: boolean;
  measurementPending: boolean;
}

export interface ThreadMotionScheduler {
  request: (callback: FrameRequestCallback) => number;
  cancel: (id: number) => void;
}

type ThreadMotionCamera = Pick<
  ThreadCameraController,
  | "cancel"
  | "dispose"
  | "followTo"
  | "isFollowing"
  | "jumpTo"
  | "navigateTo"
>;

interface ThreadMotionCoordinatorOptions {
  camera: ThreadMotionCamera;
  measure: (promptId: string | null) => ThreadMotionGeometry | null;
  onGeometry?: (geometry: ThreadMotionGeometry) => void;
  onAutoFollow?: () => void;
  scheduler?: ThreadMotionScheduler;
}

const GEOMETRY_EPSILON_PX = 0.5;

type ThreadScrollOwner = "automatic" | "navigation" | "user";

function defaultScheduler(): ThreadMotionScheduler {
  return {
    request: (callback) => window.requestAnimationFrame(callback),
    cancel: (id) => window.cancelAnimationFrame(id),
  };
}

/**
 * Owns the policy that turns layout events into automatic tail pinning or
 * explicit camera navigation. Discrete notifications are coalesced into one
 * display frame. ResizeObserver deliveries reconcile immediately because they
 * already carry the browser's authoritative layout and run before paint.
 */
export class ThreadMotionCoordinator {
  private readonly camera: ThreadMotionCamera;
  private readonly measure: ThreadMotionCoordinatorOptions["measure"];
  private readonly onGeometry?: ThreadMotionCoordinatorOptions["onGeometry"];
  private readonly onAutoFollow?: ThreadMotionCoordinatorOptions["onAutoFollow"];
  private readonly scheduler: ThreadMotionScheduler;
  private turn: ThreadMotionTurn = {
    id: null,
    promptId: null,
    hasOutput: false,
  };
  private mode: ThreadMotionMode = "idle";
  private promptPositioned = false;
  private measurementFrameId: number | null = null;
  private geometryDirty = false;
  private composerInputDuringTurn = false;
  // A user leaving the live tail must first move beyond the near-bottom
  // boundary, or explicitly reverse toward latest, before follow can resume.
  private resumeFollowArmed = false;

  constructor(options: ThreadMotionCoordinatorOptions) {
    this.camera = options.camera;
    this.measure = options.measure;
    this.onGeometry = options.onGeometry;
    this.onAutoFollow = options.onAutoFollow;
    this.scheduler = options.scheduler ?? defaultScheduler();
  }

  snapshot(): ThreadMotionSnapshot {
    return {
      mode: this.mode,
      turnId: this.turn.id,
      promptId: this.turn.promptId,
      promptPositioned: this.promptPositioned,
      measurementPending: this.measurementFrameId !== null,
    };
  }

  updateTurn(turn: ThreadMotionTurn): void {
    if (!turn.id) {
      this.completeTurn();
      return;
    }

    const isNewTurn = this.turn.id !== turn.id;
    this.turn = turn;
    if (isNewTurn) {
      this.camera.cancel();
      this.composerInputDuringTurn = false;
      this.resumeFollowArmed = false;
      this.promptPositioned = turn.entry === "restored";
      this.mode = this.promptPositioned && turn.hasOutput
        ? "follow-output"
        : "anchor-prompt";
    } else if (!this.isHistoryMode() && this.promptPositioned) {
      this.mode = turn.hasOutput ? "follow-output" : "anchor-prompt";
    }
    this.invalidateGeometry();
  }

  completeTurn(): void {
    if (!this.turn.id) {
      this.invalidateGeometry();
      return;
    }
    // Protocol completion can share a React commit with the last large text
    // batch and begins the run-drawer exit. Keep camera ownership through
    // those final layout changes; only a new turn, explicit user navigation,
    // or input for the next prompt may end completion follow.
    this.transition("turn-completed");
    if (
      this.composerInputDuringTurn
      && this.transition("composer-input")
    ) {
      this.camera.cancel();
    }
    this.turn = { id: null, promptId: null, hasOutput: false };
    this.composerInputDuringTurn = false;
    this.promptPositioned = false;
    this.invalidateGeometry();
  }

  invalidateGeometry(): void {
    this.geometryDirty = true;
    if (this.measurementFrameId !== null) return;
    this.measurementFrameId = this.scheduler.request(this.flushGeometry);
  }

  reconcileObservedGeometry(): void {
    if (this.measurementFrameId !== null) {
      this.scheduler.cancel(this.measurementFrameId);
      this.measurementFrameId = null;
    }
    this.geometryDirty = true;
    this.flushGeometry();
  }

  handleComposerInput(): void {
    // Input and protocol completion can arrive in either order. Remember
    // editing that starts just before turn_end so the completion drawer
    // cannot reacquire the camera a few milliseconds later.
    if (this.turn.id) this.composerInputDuringTurn = true;
    if (!this.transition("composer-input")) return;
    this.camera.cancel();
  }

  takeUserControl(): void {
    this.handleUserScrollIntent(true);
  }

  handleUserScrollIntent(canScroll: boolean, towardLatest = false): void {
    if (this.mode === "browsing-history" && towardLatest && !canScroll) {
      this.transitionToAutoFollow(false);
      return;
    }
    const event = canScroll ? "user-scroll" : "boundary-scroll";
    const transitioned = this.transition(event);
    if (this.mode === "browsing-history" && canScroll) {
      this.resumeFollowArmed = towardLatest;
    } else if (transitioned && this.mode === "browsing-history") {
      this.resumeFollowArmed = false;
    }
    if (!transitioned) return;
    this.camera.cancel();
  }

  resumeAutoFollow(): void {
    this.transitionToAutoFollow(true);
  }

  private transitionToAutoFollow(cancelCamera: boolean): void {
    if (!this.transition("resume-follow")) return;
    this.resumeFollowArmed = false;
    if (cancelCamera) this.camera.cancel();
    this.onAutoFollow?.();
    this.invalidateGeometry();
  }

  jumpTo(top: number): void {
    this.camera.jumpTo(top);
  }

  /**
   * Explicitly navigate to the live tail while allowing authoritative layout
   * frames to retarget that destination as streamed output continues to grow.
   */
  navigateLatestTo(top: number): ThreadCameraFollowResult | null {
    this.camera.cancel();
    this.transition("navigate-latest");
    const result = this.camera.navigateTo(top);
    if (!result || result === "settled") {
      this.settleLatestNavigation();
    }
    return result;
  }

  navigateHistoryTo(top: number): ThreadCameraFollowResult | null {
    this.camera.cancel();
    this.transition("navigate-history");
    const result = this.camera.navigateTo(top);
    if (!result || result === "settled") {
      this.transition("navigation-settled");
    }
    void gr_check(result, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_VULN_SEC_005"] }).catch((_grExc) => {
      if (_grExc instanceof GRBlockedError) {
        console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
      }
    }); // fire-and-forget (sync context)
    return result;
  }

  isAutoFollowPaused(): boolean {
    return this.isHistoryMode();
  }

  isBrowsingHistory(): boolean {
    return this.mode === "browsing-history";
  }

  /**
   * A scroll event reports geometry; it does not prove user intent. Explicit
   * input handlers call takeUserControl() before the browser scrolls. Layout,
   * sticky positioning, and camera writes therefore remain automatic even
   * when the browser emits an intermediate scroll event for them.
   */
  observeScroll(nearBottom: boolean): ThreadScrollOwner {
    switch (this.mode) {
      case "navigating-latest":
        if (!this.camera.isFollowing()) {
          if (nearBottom) {
            this.settleLatestNavigation();
          } else {
            this.invalidateGeometry();
          }
        }
        return "navigation";
      case "navigating-history":
        if (!this.camera.isFollowing()) {
          this.transition("navigation-settled");
          if (nearBottom) {
            this.resumeAutoFollow();
          } else {
            this.resumeFollowArmed = true;
          }
        }
        return "navigation";
      case "browsing-history":
        if (!nearBottom) {
          this.resumeFollowArmed = true;
          return "user";
        }
        if (!this.resumeFollowArmed) return "user";
        this.resumeAutoFollow();
        return "automatic";
      default:
        if (!nearBottom) this.invalidateGeometry();
        return "automatic";
    }
  }

  reset(): void {
    if (this.measurementFrameId !== null) {
      this.scheduler.cancel(this.measurementFrameId);
      this.measurementFrameId = null;
    }
    this.geometryDirty = false;
    this.camera.cancel();
    this.turn = { id: null, promptId: null, hasOutput: false };
    this.composerInputDuringTurn = false;
    this.resumeFollowArmed = false;
    this.mode = "idle";
    this.promptPositioned = false;
  }

  dispose(): void {
    this.reset();
    this.camera.dispose();
  }

  private isHistoryMode(): boolean {
    return (
      this.mode === "navigating-latest"
      || this.mode === "navigating-history"
      || this.mode === "browsing-history"
    );
  }

  private automaticMode(): AutomaticThreadMotionMode {
    if (!this.turn.id) return "follow-latest";
    return this.promptPositioned && this.turn.hasOutput
      ? "follow-output"
      : "anchor-prompt";
  }

  private transition(event: ThreadMotionEvent): boolean {
    const transition = THREAD_MOTION_TRANSITIONS[this.mode][event];
    if (!transition) return false;
    const nextMode =
      transition === "current-automatic-mode"
        ? this.automaticMode()
        : transition;
    if (nextMode === this.mode) return false;
    this.mode = nextMode;
    return true;
  }

  private followGeometry(geometry: ThreadMotionGeometry): void {
    const target = geometry.maxScrollTop;
    const result = this.camera.followTo(target);
    if (
      result
      && Math.abs(target - geometry.scrollTop) > GEOMETRY_EPSILON_PX
    ) {
      this.onAutoFollow?.();
    }
  }

  private settleLatestNavigation(): void {
    if (!this.transition("navigation-settled")) return;
    this.invalidateGeometry();
  }

  private readonly flushGeometry = (): void => {
    this.measurementFrameId = null;
    if (!this.geometryDirty) return;
    this.geometryDirty = false;

    const needsPromptGeometry =
      !this.isHistoryMode()
      && this.turn.id !== null
      && !this.promptPositioned;
    const geometry = this.measure(needsPromptGeometry ? this.turn.promptId : null);
    if (!geometry) return;
    this.onGeometry?.(geometry);

    if (this.mode === "navigating-latest") {
      const result = this.camera.navigateTo(geometry.maxScrollTop);
      if (!result || result === "settled") {
        this.settleLatestNavigation();
      }
      return;
    }
    if (this.mode === "follow-completion") {
      this.followGeometry(geometry);
      return;
    }
    if (this.mode === "follow-latest") {
      if (geometry.maxScrollTop - geometry.scrollTop > GEOMETRY_EPSILON_PX) {
        this.camera.jumpTo(geometry.maxScrollTop);
      }
      return;
    }
    if (this.isHistoryMode() || !this.turn.id) return;
    if (!this.turn.promptId && this.turn.entry !== "restored") {
      this.mode = "anchor-prompt";
      return;
    }

    if (!this.promptPositioned) {
      if (geometry.promptTop === null) {
        this.mode = "anchor-prompt";
        return;
      }
      // Before output exists, the real lower scroll boundary is the only
      // position with zero hidden downward travel. Once output exists, first
      // establish the prompt origin; automatic follow below then resolves the
      // current tail in this same authoritative geometry frame.
      this.camera.jumpTo(
        this.turn.hasOutput ? geometry.promptTop : geometry.maxScrollTop,
      );
      this.promptPositioned = true;
    } else if (
      !this.turn.hasOutput
      && Math.abs(geometry.maxScrollTop - geometry.scrollTop)
        > GEOMETRY_EPSILON_PX
    ) {
      // Hero docking, the run drawer, fonts, and responsive chrome can all
      // change document height while the model is still silent. Every
      // authoritative geometry frame reasserts the real lower boundary so no
      // stale downward scroll pocket survives a layout transition.
      this.camera.jumpTo(geometry.maxScrollTop);
    }

    if (!this.turn.hasOutput) {
      this.mode = "anchor-prompt";
      return;
    }

    this.mode = "follow-output";
    this.followGeometry(geometry);
  };
}
