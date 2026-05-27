"use client";

// PERM-04 — the live, as-you-type OPL validation hook.
//
// On each source change this hook waits ~400ms (debounce), then POSTs the
// editor text as { source } to the EXISTING backend passthrough
// `POST /api/keto/opl/validate` via @/lib/api. The returned
// CheckOplSyntaxResult.errors[] are mapped to Monaco `IMarkerData` (red
// squiggles) at each error's start/end line+column and applied to the model
// through the Plan 18-01 onMount handle (editor + monaco).
//
// Hardening / correctness invariants:
//   * DEBOUNCE (T-18-06): rapid edits collapse to ONE validate call for the
//     final value — no per-keystroke spam.
//   * CANCEL (T-18-06/T-18-10): a newer edit aborts the in-flight request via
//     AbortController; an aborted request NEVER applies (stale) markers.
//   * 502/TRANSPORT IS NOT "INVALID" (T-18-05, Pitfall 13): a non-422 ApiError
//     or any non-ApiError transport reject (excluding AbortError) degrades to a
//     NON-BLOCKING `unavailable` flag and CLEARS markers — it never produces an
//     error marker and is never labeled "invalid". ONLY a populated errors[]
//     (the 200/422-class success body) produces error markers.
//   * CLEAR-ON-CLEAN / CLEAR-ON-UNMOUNT (T-18-10): a clean result and unmount/
//     disable both clear the owner's markers so a stale squiggle never persists.
//   * The hook is ADDITIVE UX ONLY (T-18-07): it owns nothing in the page's
//     pre-save Validate/Save gate — it returns markers + an `unavailable` flag.

import * as React from "react";

import type { editor as MonacoEditorNS } from "monaco-editor";

import { api, ApiError } from "@/lib/api";

// The Keto CheckOplSyntaxResult shape (mirrors the page's PERM-01 types).
type SourcePosition = { line?: number; column?: number };
type ParseError = {
  message?: string;
  start?: SourcePosition;
  end?: SourcePosition;
};
type CheckOplSyntaxResult = { errors?: ParseError[] | null };

// A stable, hook-owned marker owner string (distinct from any other diagnostics
// provider on the model — clearing/setting it never touches JSON-schema markers).
export const LIVE_OPL_MARKER_OWNER = "ory-opl-live";

// The debounce window (~400ms) between the last edit and the validate call.
const DEBOUNCE_MS = 400;

// The (editor, monaco) handle delivered by MonacoEditor's onMount (Plan 18-01).
// Kept structural so the hook does not pin a specific monaco import identity
// (the page passes whatever @monaco-editor/react's OnMount yields).
export interface OplEditorHandle {
  editor: {
    // The model is treated opaquely — it is only ever handed back to
    // monaco.editor.setModelMarkers — so we accept any non-null model handle.
    getModel: () => unknown;
  };
  monaco: {
    editor: {
      setModelMarkers: (
        model: unknown,
        owner: string,
        markers: MonacoEditorNS.IMarkerData[],
      ) => void;
    };
    // Monaco's MarkerSeverity enum (we read .Error off the live handle so we
    // never need a runtime monaco-editor import).
    MarkerSeverity: { Error: number };
  };
}

export interface UseLiveOplValidateArgs {
  /** The current editor text. */
  source: string;
  /** The (editor, monaco) handle from MonacoEditor onMount, or null pre-mount. */
  handle: OplEditorHandle | null;
  /** When false the hook makes no calls and clears any markers. */
  enabled: boolean;
}

export interface UseLiveOplValidateResult {
  /** True when the live check could not run (502/transport) — render a subtle,
   *  NON-BLOCKING hint. Never means the model is "invalid". */
  unavailable: boolean;
}

/** Clamp a 1-based position to >= 1 (Keto + Monaco are both 1-based). */
function clampPos(n: number | undefined): number {
  return typeof n === "number" && n >= 1 ? Math.floor(n) : 1;
}

/** Map a ParseError to a Monaco IMarkerData (severity Error). Missing/<1
 *  positions clamp to 1; a missing end spans to start column + 1. */
function toMarker(
  err: ParseError,
  errorSeverity: number,
): MonacoEditorNS.IMarkerData {
  const startLineNumber = clampPos(err.start?.line);
  const startColumn = clampPos(err.start?.column);
  const endLineNumber = clampPos(err.end?.line ?? err.start?.line);
  // If end column is missing, span one column past the start so the squiggle is
  // visible (a zero-width marker would not render).
  const endColumn =
    err.end?.column != null ? clampPos(err.end.column) : startColumn + 1;
  return {
    startLineNumber,
    startColumn,
    endLineNumber,
    endColumn,
    message: err.message ?? "Syntax error",
    severity: errorSeverity,
  };
}

/**
 * Live, debounced, cancellable OPL validation. Returns `{ unavailable }`; the
 * markers are applied as a side effect onto the editor model via the handle.
 */
export function useLiveOplValidate({
  source,
  handle,
  enabled,
}: UseLiveOplValidateArgs): UseLiveOplValidateResult {
  const [unavailable, setUnavailable] = React.useState(false);

  // Refs so the debounced callback always sees the latest handle/abort without
  // re-arming the effect on every keystroke.
  const handleRef = React.useRef<OplEditorHandle | null>(handle);
  handleRef.current = handle;
  const abortRef = React.useRef<AbortController | null>(null);
  const timerRef = React.useRef<ReturnType<typeof setTimeout> | null>(null);

  // Clear the live markers for our owner (no-op if no handle/model yet).
  const clearMarkers = React.useCallback(() => {
    const h = handleRef.current;
    const model = h?.editor.getModel();
    if (h && model) {
      h.monaco.editor.setModelMarkers(model, LIVE_OPL_MARKER_OWNER, []);
    }
  }, []);

  React.useEffect(() => {
    // Disabled or pre-mount: never call the API. Clear any prior markers so a
    // stale squiggle never persists (defence-in-depth).
    if (!enabled || !handle) {
      if (timerRef.current) clearTimeout(timerRef.current);
      clearMarkers();
      setUnavailable(false);
      return;
    }

    if (timerRef.current) clearTimeout(timerRef.current);
    timerRef.current = setTimeout(() => {
      // Supersede any in-flight request (cancel -> the prior promise rejects
      // with AbortError, which the handler ignores).
      abortRef.current?.abort();
      const controller = new AbortController();
      abortRef.current = controller;

      void (async () => {
        try {
          const res = await api<CheckOplSyntaxResult>(
            "/api/keto/opl/validate",
            {
              method: "POST",
              body: JSON.stringify({ source }),
              signal: controller.signal,
            },
          );
          // A newer request superseded this one between await and resolve:
          // do not apply stale markers.
          if (controller.signal.aborted) return;

          const h = handleRef.current;
          const model = h?.editor.getModel();
          if (!h || !model) return;

          const errors = res?.errors ?? [];
          if (errors.length === 0) {
            // Clean parse — clear markers, clear any prior unavailable hint.
            h.monaco.editor.setModelMarkers(model, LIVE_OPL_MARKER_OWNER, []);
            setUnavailable(false);
            return;
          }
          const errorSeverity = h.monaco.MarkerSeverity.Error;
          const markers = errors.map((e) => toMarker(e, errorSeverity));
          h.monaco.editor.setModelMarkers(
            model,
            LIVE_OPL_MARKER_OWNER,
            markers,
          );
          setUnavailable(false);
        } catch (e) {
          // The cancellation itself (a superseding edit / unmount) -> no-op.
          if (e instanceof DOMException && e.name === "AbortError") return;
          if (e instanceof Error && e.name === "AbortError") return;
          if (controller.signal.aborted) return;

          // A 422 (populated errors come through the SUCCESS body, not the
          // throw path; but if a 422 ever throws, treat its field errors as a
          // clean-unknown — DO clear, NOT unavailable, NEVER "invalid").
          if (e instanceof ApiError && e.status === 422) {
            clearMarkers();
            setUnavailable(false);
            return;
          }

          // Any other ApiError (e.g. 502) OR a non-ApiError transport reject:
          // degrade to a NON-BLOCKING unavailable hint + clear markers. This is
          // NEVER rendered as "invalid" (T-18-05 / Pitfall 13).
          clearMarkers();
          setUnavailable(true);
        }
      })();
    }, DEBOUNCE_MS);

    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [source, enabled, handle, clearMarkers]);

  // On unmount: abort any in-flight request and clear the live markers so a
  // stale squiggle never persists after the page is torn down.
  React.useEffect(() => {
    return () => {
      abortRef.current?.abort();
      clearMarkers();
    };
  }, [clearMarkers]);

  return { unavailable };
}

// Type re-exports for callers that want the validate-result shape.
export type { ParseError, CheckOplSyntaxResult };
