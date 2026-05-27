import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Unit test for the PERM-04 live-validate hook. The hook debounces source
// changes (~400ms), cancels the in-flight validate via AbortController when a
// newer edit supersedes, maps a CheckOplSyntaxResult's errors[] to Monaco
// IMarkerData (1-based, clamped), clears markers on a clean result and on
// unmount, and renders a 502/transport failure as `unavailable` (NEVER as an
// error marker, NEVER "invalid"). AbortError is a no-op.

import { ApiError } from "@/lib/api";

// --- Mock the single backend egress. The hook calls api<...>("/api/keto/opl/
//     validate", { method:"POST", body, signal }); we capture every call and
//     resolve/reject it per-test. ---
const apiMock = vi.fn();
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, api: (...args: unknown[]) => apiMock(...args) };
});

import { useLiveOplValidate } from "./use-live-opl-validate";

// --- A fake Monaco handle capturing setModelMarkers calls. The hook is given
//     the (editor, monaco) handle from MonacoEditor's onMount. ---
const MarkerSeverity = { Hint: 1, Info: 2, Warning: 4, Error: 8 } as const;

type MarkerCall = { owner: string; markers: unknown[] };

function makeHandle() {
  const setModelMarkers = vi.fn();
  const model = { uri: "model://opl" };
  const editor = { getModel: () => model };
  const monaco = {
    editor: { setModelMarkers },
    MarkerSeverity,
  };
  const calls = () =>
    setModelMarkers.mock.calls.map(
      ([, owner, markers]): MarkerCall => ({ owner, markers }),
    );
  return { handle: { editor, monaco }, setModelMarkers, model, calls };
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.useFakeTimers();
});

afterEach(() => {
  vi.runOnlyPendingTimers();
  vi.useRealTimers();
});

describe("useLiveOplValidate (PERM-04)", () => {
  it("debounces rapid edits into a SINGLE validate call for the final value", async () => {
    apiMock.mockResolvedValue({ errors: [] });
    const { handle } = makeHandle();

    const { rerender } = renderHook(
      ({ source }) => useLiveOplValidate({ source, handle, enabled: true }),
      { initialProps: { source: "a" } },
    );
    // Rapid successive edits within the debounce window.
    rerender({ source: "ab" });
    rerender({ source: "abc" });
    rerender({ source: "abcd" });

    expect(apiMock).not.toHaveBeenCalled();

    await act(async () => {
      vi.advanceTimersByTime(400);
    });

    expect(apiMock).toHaveBeenCalledTimes(1);
    const body = JSON.parse(String(apiMock.mock.calls[0][1].body));
    expect(body.source).toBe("abcd");
    expect(apiMock.mock.calls[0][0]).toBe("/api/keto/opl/validate");
    expect(apiMock.mock.calls[0][1].method).toBe("POST");
  });

  it("passes an AbortController signal and aborts the prior in-flight request on a newer edit", async () => {
    // First call never resolves until we let it; second call supersedes it.
    let resolveFirst: ((v: unknown) => void) | null = null;
    apiMock
      .mockImplementationOnce(
        () => new Promise((res) => (resolveFirst = res)),
      )
      .mockResolvedValueOnce({ errors: [] });
    const { handle, calls } = makeHandle();

    const { rerender } = renderHook(
      ({ source }) => useLiveOplValidate({ source, handle, enabled: true }),
      { initialProps: { source: "first" } },
    );
    await act(async () => {
      vi.advanceTimersByTime(400);
    });
    expect(apiMock).toHaveBeenCalledTimes(1);
    const firstSignal = apiMock.mock.calls[0][1].signal as AbortSignal;
    expect(firstSignal).toBeInstanceOf(AbortSignal);
    expect(firstSignal.aborted).toBe(false);

    // A newer edit fires a second debounced call — the first signal aborts.
    rerender({ source: "second" });
    await act(async () => {
      vi.advanceTimersByTime(400);
    });
    expect(firstSignal.aborted).toBe(true);

    // Resolving the aborted first request must NOT apply stale markers.
    await act(async () => {
      resolveFirst?.({ errors: [{ message: "stale", start: { line: 1, column: 1 } }] });
      await Promise.resolve();
    });
    // No error markers from the stale resolution (only clean [] from the 2nd).
    const errorMarkerCalls = calls().filter((c) => c.markers.length > 0);
    expect(errorMarkerCalls).toHaveLength(0);
  });

  it("maps errors[] start/end line/column to IMarkerData with severity Error", async () => {
    apiMock.mockResolvedValue({
      errors: [
        {
          message: "unexpected token",
          start: { line: 2, column: 5 },
          end: { line: 2, column: 9 },
        },
      ],
    });
    const { handle, calls } = makeHandle();

    renderHook(() =>
      useLiveOplValidate({ source: "class X {", handle, enabled: true }),
    );
    await act(async () => {
      vi.advanceTimersByTime(400);
      await Promise.resolve();
    });

    const lastWithMarkers = calls()
      .filter((c) => c.markers.length > 0)
      .at(-1);
    expect(lastWithMarkers?.owner).toBe("ory-opl-live");
    const m = lastWithMarkers?.markers[0] as Record<string, unknown>;
    expect(m).toMatchObject({
      startLineNumber: 2,
      startColumn: 5,
      endLineNumber: 2,
      endColumn: 9,
      message: "unexpected token",
      severity: MarkerSeverity.Error,
    });
  });

  it("clamps missing/<1 positions to 1 and spans end to start+1 when end is missing", async () => {
    apiMock.mockResolvedValue({
      errors: [{ message: "bad", start: { line: 0, column: 0 } }],
    });
    const { handle, calls } = makeHandle();

    renderHook(() =>
      useLiveOplValidate({ source: "x", handle, enabled: true }),
    );
    await act(async () => {
      vi.advanceTimersByTime(400);
      await Promise.resolve();
    });

    const m = calls()
      .filter((c) => c.markers.length > 0)
      .at(-1)?.markers[0] as Record<string, unknown>;
    expect(m.startLineNumber).toBe(1);
    expect(m.startColumn).toBe(1);
    expect(m.endLineNumber).toBe(1);
    // end missing -> spans to start column + 1.
    expect(m.endColumn).toBe(2);
  });

  it("clears markers on a CLEAN result (errors null/empty) and reports unavailable=false", async () => {
    apiMock.mockResolvedValue({ errors: [] });
    const { handle, calls } = makeHandle();

    const { result } = renderHook(() =>
      useLiveOplValidate({ source: "class Ok {}", handle, enabled: true }),
    );
    await act(async () => {
      vi.advanceTimersByTime(400);
      await Promise.resolve();
    });

    const last = calls().at(-1);
    expect(last?.owner).toBe("ory-opl-live");
    expect(last?.markers).toEqual([]);
    expect(result.current.unavailable).toBe(false);
  });

  it("502 (non-422 ApiError) -> unavailable=true, markers cleared, ZERO error markers (never invalid)", async () => {
    apiMock.mockRejectedValue(new ApiError(502));
    const { handle, calls } = makeHandle();

    const { result } = renderHook(() =>
      useLiveOplValidate({ source: "class X {", handle, enabled: true }),
    );
    await act(async () => {
      vi.advanceTimersByTime(400);
      await Promise.resolve();
      await Promise.resolve();
    });

    expect(result.current.unavailable).toBe(true);
    // Markers cleared (set to []) and never any error marker.
    const errorMarkerCalls = calls().filter((c) => c.markers.length > 0);
    expect(errorMarkerCalls).toHaveLength(0);
    const last = calls().at(-1);
    expect(last?.markers).toEqual([]);
  });

  it("a non-ApiError transport reject (NOT AbortError) -> unavailable=true + cleared", async () => {
    apiMock.mockRejectedValue(new TypeError("Failed to fetch"));
    const { handle, calls } = makeHandle();

    const { result } = renderHook(() =>
      useLiveOplValidate({ source: "class X {", handle, enabled: true }),
    );
    await act(async () => {
      vi.advanceTimersByTime(400);
      await Promise.resolve();
      await Promise.resolve();
    });

    expect(result.current.unavailable).toBe(true);
    expect(calls().filter((c) => c.markers.length > 0)).toHaveLength(0);
  });

  it("AbortError reject -> NO state change (not unavailable, no markers applied)", async () => {
    const abortErr = new DOMException("aborted", "AbortError");
    apiMock.mockRejectedValue(abortErr);
    const { handle, setModelMarkers } = makeHandle();

    const { result } = renderHook(() =>
      useLiveOplValidate({ source: "class X {", handle, enabled: true }),
    );
    await act(async () => {
      vi.advanceTimersByTime(400);
      await Promise.resolve();
      await Promise.resolve();
    });

    expect(result.current.unavailable).toBe(false);
    expect(setModelMarkers).not.toHaveBeenCalled();
  });

  it("clears markers on unmount (no stale squiggle persists)", async () => {
    apiMock.mockResolvedValue({
      errors: [{ message: "e", start: { line: 1, column: 1 } }],
    });
    const { handle, calls } = makeHandle();

    const { unmount } = renderHook(() =>
      useLiveOplValidate({ source: "class X {", handle, enabled: true }),
    );
    await act(async () => {
      vi.advanceTimersByTime(400);
      await Promise.resolve();
    });

    unmount();
    // The final setModelMarkers call clears the owner's markers.
    const last = calls().at(-1);
    expect(last?.owner).toBe("ory-opl-live");
    expect(last?.markers).toEqual([]);
  });

  it("does NOT call the API when disabled, and clears markers", async () => {
    apiMock.mockResolvedValue({ errors: [] });
    const { handle, setModelMarkers } = makeHandle();

    renderHook(() =>
      useLiveOplValidate({ source: "class X {}", handle, enabled: false }),
    );
    await act(async () => {
      vi.advanceTimersByTime(400);
      await Promise.resolve();
    });

    expect(apiMock).not.toHaveBeenCalled();
    // Disabled still clears any prior markers defensively.
    const cleared = setModelMarkers.mock.calls.some(
      ([, , markers]) => Array.isArray(markers) && markers.length === 0,
    );
    expect(cleared).toBe(true);
  });

  it("is a no-op (no throw, no API) when the handle is not yet mounted", async () => {
    apiMock.mockResolvedValue({ errors: [] });

    const { result } = renderHook(() =>
      useLiveOplValidate({ source: "class X {}", handle: null, enabled: true }),
    );
    await act(async () => {
      vi.advanceTimersByTime(400);
      await Promise.resolve();
    });

    expect(apiMock).not.toHaveBeenCalled();
    expect(result.current.unavailable).toBe(false);
  });
});
