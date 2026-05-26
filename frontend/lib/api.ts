// FE-05 — the single backend egress for the whole console.
//
// Every data access in the app (DataTable fetchers, SettingsForm saves, auth
// pages, the shell's client calls) routes through `api()`. This file is the
// enforcement point for three invariants:
//
//   1. Sole egress (T-05-06): the ONLY base literal is `/backend` — a
//      same-origin path served by the Next rewrite (05-01). No Ory/internal
//      host or NEXT_PUBLIC_ URL ever appears here, so none can leak into the
//      client bundle (asserted by scripts/verify/bundle-egress.sh).
//   2. CSRF double-submit (T-05-07): mutations (POST/PUT/PATCH/DELETE) echo the
//      readable per-session CSRF token in `X-CSRF-Token`. The token is sourced
//      from `GET /api/console/me` (the 05-02 `csrf_token` contract) and injected
//      via `setCsrfToken()`; we also fall back to a readable `csrf_token` cookie
//      if present. GETs never send the header. The session cookie itself is
//      HttpOnly and flows automatically via `credentials:'include'`.
//   3. Centralized auth/error handling (T-05-08/T-05-10): a 401 redirects to
//      /login (browser) and throws; a 422 surfaces typed field errors for the
//      SettingsForm; other non-ok statuses throw a typed ApiError.

// The ONLY base literal in the frontend. Never an Ory or internal host.
const BASE = "/backend";

/** One field-level validation error from a backend 422 response. */
export type FieldError = { path: string; message: string };

/** Typed error thrown by {@link api} for any non-2xx response. */
export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly fieldErrors: FieldError[] = [],
  ) {
    super(`API request failed with status ${status}`);
    this.name = "ApiError";
    // Restore the prototype chain so `instanceof ApiError` works after the
    // TS->JS class transpilation (Error subclassing caveat).
    Object.setPrototypeOf(this, ApiError.prototype);
  }
}

// Module-level cache of the readable CSRF token. The shell/providers populate
// this after the authenticated `/me` fetch resolves; it is intentionally NOT a
// React state (the wrapper is framework-agnostic and isomorphic-safe).
let csrfToken: string | null = null;

/**
 * Set (or clear, with `null`) the cached CSRF token. Call this once the
 * authenticated `/api/console/me` response (05-02 contract) resolves, passing
 * its `csrf_token` field. Subsequent mutations will echo it in `X-CSRF-Token`.
 */
export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}

/** Current cached CSRF token, or `null` if not yet set. */
export function getCsrfToken(): string | null {
  return csrfToken;
}

// Fallback: read a readable (non-HttpOnly) `csrf_token` cookie if the backend
// ever delivers it that way (forward-compatible with 05-RESEARCH Pattern 2).
function csrfFromCookie(): string | null {
  if (typeof document === "undefined") return null;
  return document.cookie.match(/(?:^|;\s*)csrf_token=([^;]+)/)?.[1] ?? null;
}

function resolveCsrf(): string | null {
  return csrfToken ?? csrfFromCookie();
}

const MUTATING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/**
 * The single typed backend egress.
 *
 * @param path   A backend path beginning with `/` (e.g. `/api/console/me`). It
 *               is prefixed with the same-origin `/backend` base.
 * @param init   Standard `fetch` init. `credentials` and the CSRF/Accept/
 *               Content-Type headers are managed for you.
 * @returns      The parsed JSON body typed as `T`, or `undefined` for 204.
 * @throws       {@link ApiError} on any non-2xx response (401 also redirects to
 *               /login in a browser context; 422 carries typed `fieldErrors`).
 */
export async function api<T = unknown>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const method = (init.method ?? "GET").toUpperCase();
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  // Set the JSON content-type for string bodies only. For a `FormData` body
  // (the BRAND-03 multipart logo upload) we MUST NOT set Content-Type: the
  // browser sets `multipart/form-data` with the correct boundary itself, and
  // forcing application/json would corrupt the multipart parse on the backend.
  if (init.body && !(init.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }
  if (MUTATING_METHODS.has(method)) {
    const token = resolveCsrf();
    if (token) headers.set("X-CSRF-Token", token);
  }

  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers,
    credentials: "include",
  });

  if (res.status === 401) {
    // Centralized auth failure: bounce to /login in the browser. On the server
    // (no `window`) the layout guard handles redirect via next/navigation —
    // here we just surface the typed error without crashing.
    if (typeof window !== "undefined") window.location.assign("/login");
    throw new ApiError(401);
  }

  if (res.status === 422) {
    // The backend (AppError::Validation, backend/src/error.rs:149-151) renders
    // 422 as `{"error":"validation_failed","fields":[{path,message}]}` — the
    // field errors live under `fields`, NOT `errors`. Read the real key and
    // keep a tolerant `errors` fallback for forward/backward compatibility.
    const body = (await res.json().catch(() => ({}))) as {
      fields?: FieldError[];
      errors?: FieldError[];
    };
    const fieldErrors = Array.isArray(body.fields)
      ? body.fields
      : Array.isArray(body.errors)
        ? body.errors
        : [];
    throw new ApiError(422, fieldErrors);
  }

  if (!res.ok) throw new ApiError(res.status);

  return res.status === 204 ? (undefined as T) : ((await res.json()) as T);
}
