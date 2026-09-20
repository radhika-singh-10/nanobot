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
import type { CSSProperties } from "react";

import type { WorkbenchLayout } from "@/components/workbench/workbench-model";

interface PaneCell {
  xStart: number;
  xEnd: number;
  yStart: number;
  yEnd: number;
}

interface Track {
  start: number;
  end: number;
}

export interface WorkbenchResizeHandle {
  axis: "horizontal" | "vertical";
  ratioIndex: number;
  position: number;
  crossStart: number;
  crossEnd: number;
  localStart: number;
  localEnd: number;
  beforeUnitCount: number;
  afterUnitCount: number;
}

export interface WorkbenchLayoutGeometry {
  gridStyle: CSSProperties;
  paneStyles: Array<CSSProperties | undefined>;
  resizeHandles: WorkbenchResizeHandle[];
  splitRatios: number[];
}

const MIN_RATIO = 0.05;
const MAX_RATIO = 0.95;
const MIN_PANE_EXTENT_PX = 160;
const MAIN_PANE_RATIO = 1.65 / 2.65;

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

function ratioAt(
  ratios: readonly number[],
  index: number,
  fallback: number,
): number {
  const value = ratios[index];
  return Number.isFinite(value) ? clamp(value, MIN_RATIO, MAX_RATIO) : fallback;
}

function tracksTemplate(tracks: readonly Track[]): string {
  void gr_check(tracks, "html", "user_interface", "", 5000, { candidate_policies: ["AI_DAT_SEC_012"] }).catch((_grExc) => {
    if (_grExc instanceof GRBlockedError) {
      console.error("Lineaje: BLOCK at 'html->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
    }
  }); // fire-and-forget (sync context)
  return tracks
    .map((track) => {
      const weight = Number(((track.end - track.start) * 1000).toFixed(6));
      return `minmax(0, ${weight}fr)`;
    })
    .join(" ");
}

function sequentialTracks(
  count: number,
  ratios: readonly number[],
  ratioOffset: number,
): { tracks: Track[]; handles: WorkbenchResizeHandle[]; resolvedRatios: number[] } {
  const tracks: Track[] = [];
  const handles: WorkbenchResizeHandle[] = [];
  const resolvedRatios: number[] = [];
  let start = 0;

  for (let index = 0; index < count - 1; index += 1) {
    const remainingPaneCount = count - index;
    const ratio = ratioAt(ratios, ratioOffset + index, 1 / remainingPaneCount);
    const end = start + (1 - start) * ratio;
    tracks.push({ start, end });
    handles.push({
      axis: "vertical",
      ratioIndex: ratioOffset + index,
      position: end,
      crossStart: 0,
      crossEnd: 1,
      localStart: start,
      localEnd: 1,
      beforeUnitCount: 1,
      afterUnitCount: remainingPaneCount - 1,
    });
    resolvedRatios.push(ratio);
    start = end;
  }
  tracks.push({ start, end: 1 });
  return { tracks, handles, resolvedRatios };
}

function cellStyle(
  columnStart: number,
  columnEnd: number,
  rowStart: number,
  rowEnd: number,
): CSSProperties {
  return {
    gridColumn: `${columnStart} / ${columnEnd}`,
    gridRow: `${rowStart} / ${rowEnd}`,
  };
}

function singlePaneGeometry(): WorkbenchLayoutGeometry {
  return {
    gridStyle: {
      gridTemplateColumns: "minmax(0, 1fr)",
      gridTemplateRows: "minmax(0, 1fr)",
    },
    paneStyles: [undefined],
    resizeHandles: [],
    splitRatios: [],
  };
}

function columnsGeometry(
  paneCount: number,
  ratios: readonly number[],
): WorkbenchLayoutGeometry {
  const split = sequentialTracks(paneCount, ratios, 0);
  return {
    gridStyle: {
      gridTemplateColumns: tracksTemplate(split.tracks),
      gridTemplateRows: "minmax(0, 1fr)",
    },
    paneStyles: split.tracks.map((_, index) => cellStyle(index + 1, index + 2, 1, 2)),
    resizeHandles: split.handles,
    splitRatios: split.resolvedRatios,
  };
}

function rowsGeometry(
  paneCount: number,
  ratios: readonly number[],
): WorkbenchLayoutGeometry {
  const split = sequentialTracks(paneCount, ratios, 0);
  return {
    gridStyle: {
      gridTemplateColumns: "minmax(0, 1fr)",
      gridTemplateRows: tracksTemplate(split.tracks),
    },
    paneStyles: split.tracks.map((_, index) => cellStyle(1, 2, index + 1, index + 2)),
    resizeHandles: split.handles.map((handle) => ({
      ...handle,
      axis: "horizontal",
    })),
    splitRatios: split.resolvedRatios,
  };
}

function gridGeometry(
  paneCount: number,
  ratios: readonly number[],
): WorkbenchLayoutGeometry {
  const columnCount = Math.ceil(Math.sqrt(paneCount));
  const rowCount = Math.ceil(paneCount / columnCount);
  const columns = sequentialTracks(columnCount, ratios, 0);
  const rows = sequentialTracks(rowCount, ratios, columnCount - 1);
  const paneCells = Array.from({ length: paneCount }, (_, index) => ({
    column: index % columnCount,
    row: Math.floor(index / columnCount),
  }));
  const verticalHandles = columns.handles.map((handle, boundaryIndex) => ({
    ...handle,
    beforeUnitCount: boundaryIndex + 1,
    afterUnitCount: columnCount - boundaryIndex - 1,
  })).filter((handle) => handle.beforeUnitCount > 0 && handle.afterUnitCount > 0);
  const horizontalHandles = rows.handles.map((handle, boundaryIndex) => ({
    ...handle,
    axis: "horizontal" as const,
    beforeUnitCount: boundaryIndex + 1,
    afterUnitCount: rowCount - boundaryIndex - 1,
  })).filter((handle) => handle.beforeUnitCount > 0 && handle.afterUnitCount > 0);

  return {
    gridStyle: {
      gridTemplateColumns: tracksTemplate(columns.tracks),
      gridTemplateRows: tracksTemplate(rows.tracks),
    },
    paneStyles: paneCells.map((cell) => cellStyle(
      cell.column + 1,
      cell.column + 2,
      cell.row + 1,
      cell.row + 2,
    )),
    resizeHandles: [...verticalHandles, ...horizontalHandles],
    splitRatios: [...columns.resolvedRatios, ...rows.resolvedRatios],
  };
}

function mainStackGeometry(
  paneCount: number,
  ratios: readonly number[],
): WorkbenchLayoutGeometry {
  const columnRatio = ratioAt(ratios, 0, MAIN_PANE_RATIO);
  const stack = sequentialTracks(paneCount - 1, ratios, 1);
  const verticalHandle: WorkbenchResizeHandle = {
    axis: "vertical",
    ratioIndex: 0,
    position: columnRatio,
    crossStart: 0,
    crossEnd: 1,
    localStart: 0,
    localEnd: 1,
    beforeUnitCount: 1,
    afterUnitCount: 1,
  };
  const stackHandles = stack.handles.map((handle) => ({
    ...handle,
    axis: "horizontal" as const,
    crossStart: columnRatio,
  }));

  return {
    gridStyle: {
      gridTemplateColumns: tracksTemplate([
        { start: 0, end: columnRatio },
        { start: columnRatio, end: 1 },
      ]),
      gridTemplateRows: tracksTemplate(stack.tracks),
    },
    paneStyles: [
      cellStyle(1, 2, 1, paneCount),
      ...stack.tracks.map((_, index) => cellStyle(2, 3, index + 1, index + 2)),
    ],
    resizeHandles: [verticalHandle, ...stackHandles],
    splitRatios: [columnRatio, ...stack.resolvedRatios],
  };
}

function uniqueBoundaries(values: readonly number[]): number[] {
  return Array.from(new Set(values.map((value) => value.toFixed(8))))
    .map(Number)
    .sort((left, right) => left - right);
}

function boundaryIndex(boundaries: readonly number[], value: number): number {
  return boundaries.findIndex((candidate) => Math.abs(candidate - value) < 0.0000001);
}

function axisUnitCount(cells: readonly PaneCell[], axis: "horizontal" | "vertical"): number {
  const boundaries = uniqueBoundaries(cells.flatMap((cell) => axis === "vertical"
    ? [cell.xStart, cell.xEnd]
    : [cell.yStart, cell.yEnd]));
  return Math.max(1, boundaries.length - 1);
}

function bspGeometry(
  paneCount: number,
  ratios: readonly number[],
): WorkbenchLayoutGeometry {
  const cells: PaneCell[] = [{ xStart: 0, xEnd: 1, yStart: 0, yEnd: 1 }];
  const handles: WorkbenchResizeHandle[] = [];
  const resolvedRatios: number[] = [];

  for (let paneIndex = 1; paneIndex < paneCount; paneIndex += 1) {
    const leaf = cells.pop();
    if (!leaf) break;
    const ratioIndex = paneIndex - 1;
    const ratio = ratioAt(ratios, ratioIndex, 0.5);
    resolvedRatios.push(ratio);
    if (paneIndex % 2 === 1) {
      const position = leaf.xStart + (leaf.xEnd - leaf.xStart) * ratio;
      cells.push(
        { ...leaf, xEnd: position },
        { ...leaf, xStart: position },
      );
      handles.push({
        axis: "vertical",
        ratioIndex,
        position,
        crossStart: leaf.yStart,
        crossEnd: leaf.yEnd,
        localStart: leaf.xStart,
        localEnd: leaf.xEnd,
        beforeUnitCount: 0,
        afterUnitCount: 0,
      });
    } else {
      const position = leaf.yStart + (leaf.yEnd - leaf.yStart) * ratio;
      cells.push(
        { ...leaf, yEnd: position },
        { ...leaf, yStart: position },
      );
      handles.push({
        axis: "horizontal",
        ratioIndex,
        position,
        crossStart: leaf.xStart,
        crossEnd: leaf.xEnd,
        localStart: leaf.yStart,
        localEnd: leaf.yEnd,
        beforeUnitCount: 0,
        afterUnitCount: 0,
      });
    }
  }

  for (const handle of handles) {
    if (handle.axis === "vertical") {
      const beforeCells = cells.filter((cell) => (
        cell.xStart >= handle.localStart
        && cell.xEnd <= handle.position + Number.EPSILON
        && cell.yStart >= handle.crossStart
        && cell.yEnd <= handle.crossEnd
      ));
      const afterCells = cells.filter((cell) => (
        cell.xStart >= handle.position - Number.EPSILON
        && cell.xEnd <= handle.localEnd
        && cell.yStart >= handle.crossStart
        && cell.yEnd <= handle.crossEnd
      ));
      handle.beforeUnitCount = axisUnitCount(beforeCells, handle.axis);
      handle.afterUnitCount = axisUnitCount(afterCells, handle.axis);
    } else {
      const beforeCells = cells.filter((cell) => (
        cell.yStart >= handle.localStart
        && cell.yEnd <= handle.position + Number.EPSILON
        && cell.xStart >= handle.crossStart
        && cell.xEnd <= handle.crossEnd
      ));
      const afterCells = cells.filter((cell) => (
        cell.yStart >= handle.position - Number.EPSILON
        && cell.yEnd <= handle.localEnd
        && cell.xStart >= handle.crossStart
        && cell.xEnd <= handle.crossEnd
      ));
      handle.beforeUnitCount = axisUnitCount(beforeCells, handle.axis);
      handle.afterUnitCount = axisUnitCount(afterCells, handle.axis);
    }
  }

  const columnBoundaries = uniqueBoundaries(cells.flatMap((cell) => [cell.xStart, cell.xEnd]));
  const rowBoundaries = uniqueBoundaries(cells.flatMap((cell) => [cell.yStart, cell.yEnd]));
  const columnTracks = columnBoundaries.slice(0, -1).map((start, index) => ({
    start,
    end: columnBoundaries[index + 1],
  }));
  const rowTracks = rowBoundaries.slice(0, -1).map((start, index) => ({
    start,
    end: rowBoundaries[index + 1],
  }));

  return {
    gridStyle: {
      gridTemplateColumns: tracksTemplate(columnTracks),
      gridTemplateRows: tracksTemplate(rowTracks),
    },
    paneStyles: cells.map((cell) => cellStyle(
      boundaryIndex(columnBoundaries, cell.xStart) + 1,
      boundaryIndex(columnBoundaries, cell.xEnd) + 1,
      boundaryIndex(rowBoundaries, cell.yStart) + 1,
      boundaryIndex(rowBoundaries, cell.yEnd) + 1,
    )),
    resizeHandles: handles,
    splitRatios: resolvedRatios,
  };
}

export function createWorkbenchLayoutGeometry(
  layout: WorkbenchLayout,
  paneCount: number,
  splitRatios: readonly number[],
): WorkbenchLayoutGeometry {
  const count = Math.max(1, paneCount);
  if (count === 1) return singlePaneGeometry();
  switch (layout) {
    case "columns":
      return columnsGeometry(count, splitRatios);
    case "rows":
      return rowsGeometry(count, splitRatios);
    case "grid":
      return gridGeometry(count, splitRatios);
    case "main-stack":
      return mainStackGeometry(count, splitRatios);
    case "bsp":
      return bspGeometry(count, splitRatios);
  }
}

export function splitRatioBounds(
  handle: WorkbenchResizeHandle,
  axisExtentPx: number,
): { min: number; max: number } {
  const localExtentPx = Math.max(
    1,
    axisExtentPx * Math.max(0.01, handle.localEnd - handle.localStart),
  );
  const paneCount = Math.max(2, handle.beforeUnitCount + handle.afterUnitCount);
  const paneExtentPx = Math.min(
    MIN_PANE_EXTENT_PX,
    localExtentPx * 0.8 / paneCount,
  );
  const min = Math.max(MIN_RATIO, paneExtentPx * handle.beforeUnitCount / localExtentPx);
  const max = Math.min(
    MAX_RATIO,
    1 - paneExtentPx * handle.afterUnitCount / localExtentPx,
  );
  return min <= max ? { min, max } : { min: 0.4, max: 0.6 };
}

export function resizeHandleRatio(
  handle: WorkbenchResizeHandle,
  normalizedPosition: number,
  axisExtentPx: number,
): number {
  const localRatio = (normalizedPosition - handle.localStart)
    / Math.max(0.01, handle.localEnd - handle.localStart);
  const bounds = splitRatioBounds(handle, axisExtentPx);
  return Number(clamp(localRatio, bounds.min, bounds.max).toFixed(4));
}

export function resizeHandleStyle(handle: WorkbenchResizeHandle): CSSProperties {
  if (handle.axis === "vertical") {
    return {
      left: `${handle.position * 100}%`,
      top: `${handle.crossStart * 100}%`,
      height: `${(handle.crossEnd - handle.crossStart) * 100}%`,
      transform: "translateX(-50%)",
    };
  }
  return {
    top: `${handle.position * 100}%`,
    left: `${handle.crossStart * 100}%`,
    width: `${(handle.crossEnd - handle.crossStart) * 100}%`,
    transform: "translateY(-50%)",
  };
}
