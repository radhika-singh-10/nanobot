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
import { useCallback, useEffect, useRef, useState } from "react";

import { encodeImage, type EncodeFailure } from "@/lib/imageEncode";
import type { WebUIIngressLimits } from "@/lib/types";

/** Lifecycle stages of one attachment:
 *
 * - ``encoding``  — posted to the Worker / read from disk; chip shows a spinner
 * - ``ready``     — ``dataUrl`` available; safe to submit
 * - ``error``     — validation / decode failure; chip shows inline error
 */
type AttachmentStatus = "encoding" | "ready" | "error";
export type AttachmentKind = "image" | "file";

interface AttachedAttachment {
  id: string;
  kind: AttachmentKind;
  file: File;
  /** Optimistic ``blob:`` preview URL; revoked on ``remove`` / ``clear`` /
   * unmount. */
  previewUrl?: string;
  status: AttachmentStatus;
  /** Populated when ``status === "ready"``. */
  dataUrl?: string;
  /** Size of the final encoded payload (base64 bytes decoded). */
  encodedBytes?: number;
  /** Whether the Worker re-encoded the image to hit the size budget. */
  normalized?: boolean;
  /** Human-readable validation / encoding error when ``status === "error"``. */
  error?: AttachmentError;
}

export type AttachedImage = AttachedAttachment;

interface RestoredReadyAttachment {
  dataUrl: string;
  name?: string;
  kind?: AttachmentKind;
}

export type RestoredReadyImage = RestoredReadyAttachment;

/** Machine-readable rejection reasons surfaced as inline chip errors.
 *
 * Callers localize these via the ``composer.imageRejected.*`` i18n table. */
export type AttachmentError =
  | "unsupported_type"   // server whitelist excludes this MIME
  | "empty_file"         // backend data-URL decoder rejects empty payloads
  | "too_many_attachments" // per-message cap (4) reached before enqueue
  | "total_too_large"    // decoded attachments exceed the business-policy total
  | "transport_too_large" // projected JSON frame exceeds the transport guard
  | "magic_mismatch"     // extension lies about the real content
  | "decode_failed"      // Worker couldn't decode / re-encode
  | "too_large"          // even after normalization we exceed the budget
  | "io";                // file read failed at the browser layer

export const MAX_ATTACHMENTS_PER_MESSAGE = 4;
const MAX_ATTACHMENT_BYTES = 6 * 1024 * 1024;
const MAX_TOTAL_ATTACHMENT_BYTES = 24 * 1024 * 1024;

/** MIME whitelist — mirrors the server's and the ``<input accept>`` attr. */
const ACCEPTED_IMAGE_MIMES: ReadonlySet<string> = new Set([
  "image/png",
  "image/jpeg",
  "image/webp",
  "image/gif",
]);

const DOCUMENT_MIME_BY_EXTENSION: ReadonlyMap<string, string> = new Map([
  [".pdf", "application/pdf"],
  [".docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"],
  [".xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"],
  [".pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"],
  [".txt", "text/plain"],
  [".md", "text/markdown"],
  [".csv", "text/csv"],
  [".json", "application/json"],
  [".xml", "application/xml"],
  [".html", "text/html"],
  [".htm", "text/html"],
  [".log", "text/plain"],
  [".yaml", "application/yaml"],
  [".yml", "application/yaml"],
  [".toml", "application/toml"],
  [".ini", "text/plain"],
  [".cfg", "text/plain"],
]);

const ACCEPTED_DOCUMENT_MIMES: ReadonlySet<string> = new Set(DOCUMENT_MIME_BY_EXTENSION.values());

export const ACCEPT_ATTR = [
  ...ACCEPTED_IMAGE_MIMES,
  ...ACCEPTED_DOCUMENT_MIMES,
  ...DOCUMENT_MIME_BY_EXTENSION.keys(),
].join(",");

function extensionOf(name: string): string {
  const dot = name.lastIndexOf(".");
  return dot < 0 ? "" : name.slice(dot).toLowerCase();
}

function mimeForFile(file: File): string {
  const byName = DOCUMENT_MIME_BY_EXTENSION.get(extensionOf(file.name));
  if (byName) return byName;
  if (!file.type || file.type === "application/octet-stream") {
    return "application/octet-stream";
  }
  return file.type;
}

function projectedDataUrlBytes(
  file: File,
  kind: AttachmentKind,
  maxFileBytes: number,
): number {
  const prefixBytes = `data:${mimeForFile(file)};base64,`.length;
  const decodedBytes = kind === "image" ? Math.min(file.size, maxFileBytes) : file.size;
  return prefixBytes + 4 * Math.ceil(decodedBytes / 3);
}

function positiveLimit(value: number | null | undefined, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) && value > 0
    ? Math.floor(value)
    : fallback;
}

function attachmentPayloadBudget(limits: WebUIIngressLimits | null | undefined): number | null {
  const maxFrameBytes = limits?.transport.max_frame_bytes;
  if (typeof maxFrameBytes !== "number" || !Number.isFinite(maxFrameBytes)) {
    return null;
  }
  return Math.max(
    0,
    Math.floor(maxFrameBytes)
      - positiveLimit(limits?.message.max_text_bytes, 0)
      - positiveLimit(limits?.transport.envelope_reserve_bytes, 0),
  );
}

export function acceptedAttachmentKind(file: File): AttachmentKind | null {
  if (DOCUMENT_MIME_BY_EXTENSION.has(extensionOf(file.name))) return "file";
  if (ACCEPTED_IMAGE_MIMES.has(file.type)) return "image";
  const mime = mimeForFile(file);
  if (ACCEPTED_DOCUMENT_MIMES.has(mime)) return "file";
  return null;
}

function dataUrlMime(dataUrl: string): string {
  void gr_check(dataUrl, "agent", "system", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_VULN_SEC_005"] }).catch((_grExc) => {
    if (_grExc instanceof GRBlockedError) {
      console.error("Lineaje: BLOCK at 'agent->system' could not be enforced — call site is synchronous (fire-and-forget)");
    }
  }); // fire-and-forget (sync context)
  const match = /^data:([^;,]+)[;,]/.exec(dataUrl);
  return match?.[1] || "image/png";
}

function kindFromDataUrl(dataUrl: string): AttachmentKind {
  return dataUrlMime(dataUrl).startsWith("image/") ? "image" : "file";
}

function dataUrlToFile(dataUrl: string, name?: string): File {
  const mime = dataUrlMime(dataUrl);
  const fallbackName = `image.${mime.split("/")[1] || "png"}`;
  try {
    const [, base64 = ""] = dataUrl.split(",", 2);
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return new File([bytes], name || fallbackName, { type: mime });
  } catch {
    return new File([], name || fallbackName, { type: mime });
  }
}

function uuid(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return (crypto as Crypto).randomUUID();
  }
  return `img-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

function bufferToBase64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(
      null,
      bytes.subarray(i, i + chunk) as unknown as number[],
    );
  }
  return btoa(binary);
}

async function encodeFile(file: File, maxFileBytes: number): Promise<{
  ok: true;
  dataUrl: string;
  bytes: number;
} | {
  ok: false;
  reason: AttachmentError;
}> {
  if (file.size > maxFileBytes) return { ok: false, reason: "too_large" };
  try {
    const buffer = await file.arrayBuffer();
    return {
      ok: true,
      dataUrl: `data:${mimeForFile(file)};base64,${bufferToBase64(buffer)}`,
      bytes: file.size,
    };
  } catch {
    return { ok: false, reason: "io" };
  }
}

function mapEncodeFailure(reason: EncodeFailure["reason"]): AttachmentError {
  switch (reason) {
    case "invalid_mime":
    case "magic_mismatch":
      return "magic_mismatch";
    case "too_large_after_normalize":
      return "too_large";
    case "io":
      return "io";
    case "decode_failed":
    default:
      return "decode_failed";
  }
}

export interface UseAttachedImagesApi {
  images: AttachedAttachment[];
  /** Enqueue new files. Returns the list of rejected files so the caller can
   * surface inline errors. Files rejected client-side (wrong MIME, limit) are
   * *not* added to ``images`` — only recoverable read/encoding failures show
   * up as error chips. */
  enqueue: (files: Iterable<File>) => {
    rejected: Array<{ file: File; reason: AttachmentError }>;
  };
  remove: (id: string) => { nextFocusId: string | null };
  /** Revoke every staged blob URL and drop all attachments. Called after a
   * successful submit — the optimistic bubble holds onto an independent
   * ``data:`` URL so tearing down blob previews here is safe. */
  clear: () => void;
  /** Restore already-encoded attachments, e.g. a queued composer draft moving
   * back into the input. These entries are immediately sendable and use image
   * ``data:`` URLs as stable previews. */
  restoreReadyImages: (images: RestoredReadyAttachment[]) => void;
  /** ``true`` when at least one attachment is still encoding — Send should wait. */
  encoding: boolean;
  /** ``true`` when we've hit ``MAX_ATTACHMENTS_PER_MESSAGE``. */
  full: boolean;
}

interface UseAttachedImagesOptions {
  ingressLimits?: WebUIIngressLimits | null;
}

/** Manage the lifecycle of attachments in the Composer.
 *
 * Responsibilities in one place:
 *   - validation (MIME whitelist, count cap)
 *   - blob URL creation + revocation
 *   - Worker orchestration
 *   - focus bookkeeping so keyboard delete doesn't strand the user
 */
export function useAttachedImages({
  ingressLimits = null,
}: UseAttachedImagesOptions = {}): UseAttachedImagesApi {
  const [images, setImages] = useState<AttachedAttachment[]>([]);
  const maxAttachments = positiveLimit(
    ingressLimits?.attachments.max_count,
    MAX_ATTACHMENTS_PER_MESSAGE,
  );
  const maxFileBytes = positiveLimit(
    ingressLimits?.attachments.max_file_bytes,
    MAX_ATTACHMENT_BYTES,
  );
  const maxTotalBytes = positiveLimit(
    ingressLimits?.attachments.max_total_bytes,
    MAX_TOTAL_ATTACHMENT_BYTES,
  );
  // Ref mirror so ``enqueue`` can see the authoritative length when invoked
  // multiple times in a single tick (rapid file selection, drag of many
  // files, paste storms). ``state`` is stale for that second + call.
  const imagesRef = useRef<AttachedAttachment[]>([]);
  imagesRef.current = images;

  const setEntry = useCallback((id: string, patch: Partial<AttachedAttachment>) => {
    setImages((prev) => {
      const next = prev.map((img) => (img.id === id ? { ...img, ...patch } : img));
      imagesRef.current = next;
      return next;
    });
  }, []);

  const enqueue = useCallback(
    (files: Iterable<File>) => {
      const rejected: Array<{ file: File; reason: AttachmentError }> = [];
      const toAdd: AttachedAttachment[] = [];
      let slot = maxAttachments - imagesRef.current.length;
      const payloadBudget = attachmentPayloadBudget(ingressLimits);
      let projectedWireBytes = imagesRef.current.reduce(
        (total, image) => total + (
          image.dataUrl?.length
          ?? projectedDataUrlBytes(image.file, image.kind, maxFileBytes)
        ),
        0,
      );
      let projectedDecodedBytes = imagesRef.current.reduce(
        (total, image) => total + (
          image.encodedBytes
          ?? (image.kind === "image" ? Math.min(image.file.size, maxFileBytes) : image.file.size)
        ),
        0,
      );

      for (const file of files) {
        const kind = acceptedAttachmentKind(file);
        if (!kind) {
          rejected.push({ file, reason: "unsupported_type" });
          continue;
        }
        if (file.size === 0) {
          rejected.push({ file, reason: "empty_file" });
          continue;
        }
        if (kind === "file" && file.size > maxFileBytes) {
          rejected.push({ file, reason: "too_large" });
          continue;
        }
        if (slot <= 0) {
          rejected.push({ file, reason: "too_many_attachments" });
          continue;
        }
        const nextDecodedBytes = kind === "image" ? Math.min(file.size, maxFileBytes) : file.size;
        if (projectedDecodedBytes + nextDecodedBytes > maxTotalBytes) {
          rejected.push({ file, reason: "total_too_large" });
          continue;
        }
        const nextWireBytes = projectedDataUrlBytes(file, kind, maxFileBytes);
        if (payloadBudget !== null && projectedWireBytes + nextWireBytes > payloadBudget) {
          rejected.push({ file, reason: "transport_too_large" });
          continue;
        }
        slot -= 1;
        projectedDecodedBytes += nextDecodedBytes;
        projectedWireBytes += nextWireBytes;
        toAdd.push({
          id: uuid(),
          kind,
          file,
          ...(kind === "image" ? { previewUrl: URL.createObjectURL(file) } : {}),
          status: "encoding",
        });
      }

      if (toAdd.length > 0) {
        const next = [...imagesRef.current, ...toAdd];
        imagesRef.current = next;
        setImages(next);
        // Fire the Worker after the commit so chips render first (good INP).
        for (const entry of toAdd) {
          queueMicrotask(() => {
            const work = entry.kind === "image"
              ? encodeImage(entry.file)
              : encodeFile(entry.file, maxFileBytes);
            work.then(
              (result) => {
                if (result.ok) {
                  setEntry(entry.id, {
                    status: "ready",
                    dataUrl: result.dataUrl,
                    encodedBytes: result.bytes,
                    normalized: "normalized" in result ? result.normalized : false,
                  });
                } else {
                  setEntry(entry.id, {
                    status: "error",
                    error: entry.kind === "image"
                      ? mapEncodeFailure(result.reason as EncodeFailure["reason"])
                      : result.reason as AttachmentError,
                  });
                }
              },
              () => {
                setEntry(entry.id, {
                  status: "error",
                  error: "decode_failed",
                });
              },
            );
          });
        }
      }
      return { rejected };
    },
    [ingressLimits, maxAttachments, maxFileBytes, maxTotalBytes, setEntry],
  );

  const remove = useCallback((id: string) => {
    let nextFocusId: string | null = null;
    setImages((prev) => {
      const idx = prev.findIndex((img) => img.id === id);
      if (idx === -1) return prev;
      const target = prev[idx];
      if (target.previewUrl) {
        try {
          URL.revokeObjectURL(target.previewUrl);
        } catch {
          // No-op: previewUrl revocation is best-effort.
        }
      }
      const next = [...prev.slice(0, idx), ...prev.slice(idx + 1)];
      imagesRef.current = next;
      // Prefer moving focus to the chip at the same index, else previous.
      const candidate = next[idx] ?? next[idx - 1];
      nextFocusId = candidate?.id ?? null;
      void gr_check(next, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_VULN_SEC_005"] }).catch((_grExc) => {
        if (_grExc instanceof GRBlockedError) {
          console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
        }
      }); // fire-and-forget (sync context)
      return next;
    });
    return { nextFocusId };
  }, []);

  const clear = useCallback(() => {
    setImages((prev) => {
      for (const img of prev) {
        if (img.previewUrl) {
          try {
            URL.revokeObjectURL(img.previewUrl);
          } catch {
            // revoke is best-effort
          }
        }
      }
      imagesRef.current = [];
      return [];
    });
  }, []);

  const restoreReadyImages = useCallback((restored: RestoredReadyAttachment[]) => {
    const toRestore = restored
      .filter((img) => acceptedAttachmentKind(dataUrlToFile(img.dataUrl, img.name)))
      .slice(0, maxAttachments)
      .map((img): AttachedAttachment => {
        const file = dataUrlToFile(img.dataUrl, img.name);
        const kind = img.kind ?? kindFromDataUrl(img.dataUrl);
        return {
          id: uuid(),
          kind,
          file,
          ...(kind === "image" ? { previewUrl: img.dataUrl } : {}),
          status: "ready",
          dataUrl: img.dataUrl,
          encodedBytes: file.size,
        };
      });
    setImages((prev) => {
      for (const img of prev) {
        if (img.previewUrl) {
          try {
            URL.revokeObjectURL(img.previewUrl);
          } catch {
            // revoke is best-effort
          }
        }
      }
      imagesRef.current = toRestore;
      void gr_check(toRestore, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_VULN_SEC_005"] }).catch((_grExc) => {
        if (_grExc instanceof GRBlockedError) {
          console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
        }
      }); // fire-and-forget (sync context)
      return toRestore;
    });
  }, [maxAttachments]);

  // Final safety net: revoke any outstanding blob URLs on unmount. Safe
  // under StrictMode double-invoke because revoked blob URLs are only
  // referenced from in-hook chip state, which is rebuilt on remount.
  useEffect(() => {
    return () => {
      for (const img of imagesRef.current) {
        if (img.previewUrl) {
          try {
            URL.revokeObjectURL(img.previewUrl);
          } catch {
            // best-effort cleanup on unmount
          }
        }
      }
    };
  }, []);

  const encoding = images.some((img) => img.status === "encoding");
  const full = images.length >= maxAttachments;

  return { images, enqueue, remove, clear, restoreReadyImages, encoding, full };
}
