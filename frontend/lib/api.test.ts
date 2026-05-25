import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, api, setCsrfToken } from "./api";

// Unit tests for the FE-05 sole-egress fetch wrapper (lib/api.ts).
// We mock the global `fetch` so no network is hit, and assert the wrapper's
// contract: same-origin /backend base, credentials:'include' always, the
// X-CSRF-Token header on mutations only (sourced from the /me csrf_token via
// setCsrfToken), centralized 401 -> /login redirect, and typed 422 ApiError.

function mockResponse(
  status: number,
  body?: unknown,
  init: { ok?: boolean } = {},
): Response {
  return {
    status,
    ok: init.ok ?? (status >= 200 && status < 300),
    json: async () => body,
  } as unknown as Response;
}

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  fetchMock = vi.fn();
  vi.stubGlobal("fetch", fetchMock);
  // Reset any cached CSRF token between tests.
  setCsrfToken(null);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("api() egress + base", () => {
  it("prefixes the path with the /backend same-origin base", async () => {
    fetchMock.mockResolvedValue(mockResponse(200, { ok: true }));
    await api("/api/console/me");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url] = fetchMock.mock.calls[0];
    expect(url).toBe("/backend/api/console/me");
  });

  it("never targets an absolute/Ory host (sole-egress invariant)", async () => {
    // The Ory service names appear as backend *path* segments (the proxy
    // forwards /backend/api/kratos/*). The invariant is about the egress HOST:
    // it must be same-origin (no scheme/host), so the URL is always a path
    // beginning with /backend and never an absolute http(s) URL.
    fetchMock.mockResolvedValue(mockResponse(200, {}));
    await api("/api/kratos/identities");
    const [url] = fetchMock.mock.calls[0];
    expect(url).not.toMatch(/^https?:\/\//i);
    expect(String(url).startsWith("/backend/")).toBe(true);
  });

  it("always sends credentials:'include'", async () => {
    fetchMock.mockResolvedValue(mockResponse(200, {}));
    await api("/api/console/me");
    const [, init] = fetchMock.mock.calls[0];
    expect(init.credentials).toBe("include");
  });

  it("sets Accept: application/json", async () => {
    fetchMock.mockResolvedValue(mockResponse(200, {}));
    await api("/api/console/me");
    const [, init] = fetchMock.mock.calls[0];
    const headers = new Headers(init.headers);
    expect(headers.get("Accept")).toBe("application/json");
  });
});

describe("CSRF header behavior", () => {
  it("GET requests do NOT send X-CSRF-Token", async () => {
    fetchMock.mockResolvedValue(mockResponse(200, {}));
    setCsrfToken("tok-123");
    await api("/api/console/me");
    const [, init] = fetchMock.mock.calls[0];
    const headers = new Headers(init.headers);
    expect(headers.has("X-CSRF-Token")).toBe(false);
  });

  it("mutations send X-CSRF-Token from the /me-sourced token", async () => {
    fetchMock.mockResolvedValue(mockResponse(204));
    setCsrfToken("tok-123");
    await api("/api/config/kratos/smtp", {
      method: "PUT",
      body: JSON.stringify({ host: "x" }),
    });
    const [, init] = fetchMock.mock.calls[0];
    const headers = new Headers(init.headers);
    expect(headers.get("X-CSRF-Token")).toBe("tok-123");
  });

  it("sets Content-Type: application/json when a body is present", async () => {
    fetchMock.mockResolvedValue(mockResponse(204));
    setCsrfToken("tok-123");
    await api("/x", { method: "POST", body: JSON.stringify({ a: 1 }) });
    const [, init] = fetchMock.mock.calls[0];
    const headers = new Headers(init.headers);
    expect(headers.get("Content-Type")).toBe("application/json");
  });

  it("attaches X-CSRF-Token to POST/PUT/PATCH/DELETE", async () => {
    setCsrfToken("tok-xyz");
    for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
      fetchMock.mockResolvedValue(mockResponse(204));
      await api("/x", { method });
      const [, init] = fetchMock.mock.calls.at(-1)!;
      const headers = new Headers(init.headers);
      expect(headers.get("X-CSRF-Token")).toBe("tok-xyz");
    }
  });
});

describe("response handling", () => {
  it("resolves parsed JSON for 200", async () => {
    fetchMock.mockResolvedValue(mockResponse(200, { id: "1", email: "a@b.c" }));
    const out = await api<{ id: string; email: string }>("/api/console/me");
    expect(out).toEqual({ id: "1", email: "a@b.c" });
  });

  it("resolves undefined for 204", async () => {
    fetchMock.mockResolvedValue(mockResponse(204));
    const out = await api("/x", { method: "DELETE" });
    expect(out).toBeUndefined();
  });
});

describe("401 centralized redirect", () => {
  it("redirects to /login and throws ApiError(401) in a browser context", async () => {
    const assign = vi.fn();
    vi.stubGlobal("window", {
      location: { assign },
    } as unknown as Window & typeof globalThis);
    fetchMock.mockResolvedValue(mockResponse(401, { error: "unauthenticated" }));

    await expect(api("/api/console/me")).rejects.toMatchObject({
      status: 401,
    });
    expect(assign).toHaveBeenCalledWith("/login");
  });

  it("throws ApiError(401) without crashing when window is undefined (server)", async () => {
    // No window stub: simulate server context.
    vi.stubGlobal("window", undefined);
    fetchMock.mockResolvedValue(mockResponse(401, {}));
    const err = await api("/api/console/me").catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(401);
  });
});

describe("422 typed field errors", () => {
  it("parses the backend's `fields` key (real {error,fields:[{path,message}]} shape)", async () => {
    // Mirrors AppError::Validation in backend/src/error.rs:149-151, which
    // renders `{"error":"validation_failed","fields":[{path,message}]}`. The
    // wrapper MUST read `fields` (not `errors`) or inline validation is dead.
    const fieldErrors = [
      { path: "smtp.host", message: "required" },
      { path: "smtp.port", message: "must be a number" },
    ];
    fetchMock.mockResolvedValue(
      mockResponse(
        422,
        { error: "validation_failed", fields: fieldErrors },
        { ok: false },
      ),
    );
    setCsrfToken("t");
    const err = await api("/api/config/kratos/smtp", {
      method: "PUT",
      body: "{}",
    }).catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(422);
    expect((err as ApiError).fieldErrors).toEqual(fieldErrors);
  });

  it("ignores the legacy `errors` key when the real `fields` shape is present", async () => {
    // Pins the contract: a body using the backend's real `fields` shape must
    // surface those errors (regressing to the old `errors`-only read would
    // break this).
    const fieldErrors = [{ path: "email", message: "invalid" }];
    fetchMock.mockResolvedValue(
      mockResponse(422, { fields: fieldErrors }, { ok: false }),
    );
    const err = await api("/x", { method: "POST" }).catch((e) => e);
    expect((err as ApiError).fieldErrors).toEqual(fieldErrors);
  });

  it("tolerates a legacy `errors` key as a fallback (forward/backward compat)", async () => {
    const fieldErrors = [{ path: "email", message: "invalid" }];
    fetchMock.mockResolvedValue(
      mockResponse(422, { errors: fieldErrors }, { ok: false }),
    );
    const err = await api("/x", { method: "POST" }).catch((e) => e);
    expect((err as ApiError).fieldErrors).toEqual(fieldErrors);
  });

  it("tolerates a 422 body without a fields array", async () => {
    fetchMock.mockResolvedValue(mockResponse(422, {}, { ok: false }));
    const err = await api("/x", { method: "POST" }).catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(422);
    expect((err as ApiError).fieldErrors).toEqual([]);
  });
});

describe("other non-ok statuses", () => {
  it("throws ApiError(status) on 500", async () => {
    fetchMock.mockResolvedValue(mockResponse(500, {}, { ok: false }));
    const err = await api("/x").catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(500);
  });
});
