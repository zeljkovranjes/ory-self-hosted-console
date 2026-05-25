import "server-only";
import { cookies } from "next/headers";

// FE-01 — server-only backend access for the (console) auth guard
// (05-RESEARCH Pattern 3, T-05-14).
//
// The `__Host-console_session` cookie is HttpOnly: its VALIDITY cannot be
// checked in client JS. The authoritative auth gate is therefore a server-side
// fetch to the backend `/api/console/me`, forwarding the incoming request
// cookies. We use the internal backend URL directly here (the browser-origin
// `/backend` rewrite is a client concern) — `BACKEND_INTERNAL_URL` is a
// server-only env var that never reaches the bundle.
//
// `import "server-only"` makes the build fail loudly if this module is ever
// imported into a Client Component, preventing the internal URL from leaking.

/** The authenticated operator, as returned by `GET /api/console/me`. */
export type Me = {
  id: string;
  email: string;
  name: string;
  github_linked: boolean;
  csrf_token: string;
};

const BACKEND_INTERNAL_URL =
  process.env.BACKEND_INTERNAL_URL ?? "http://backend:8080";

/**
 * Fetch the authenticated operator from the backend, forwarding the incoming
 * request cookies. Returns the parsed {@link Me} on 200, or `null` for any
 * non-200 (401/unauthenticated, network error, etc.) so callers can redirect.
 *
 * Server-only. `cache: "no-store"` because auth state must never be cached.
 */
export async function getMe(): Promise<Me | null> {
  const cookieHeader = (await cookies()).toString();
  try {
    const res = await fetch(`${BACKEND_INTERNAL_URL}/api/console/me`, {
      headers: { cookie: cookieHeader },
      cache: "no-store",
    });
    if (!res.ok) return null;
    return (await res.json()) as Me;
  } catch {
    // Backend unreachable / malformed response → treat as unauthenticated.
    return null;
  }
}
