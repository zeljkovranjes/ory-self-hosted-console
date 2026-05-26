import { NextRequest, NextResponse } from "next/server"

// =============================================================================
// AX server route: the narrowly-scoped domain->SSO HINT proxy (AX-01 / SSO-06).
//
// This is the AX's OWN server-side endpoint the login screen's browser code
// calls. It forwards an `?email=` (or `?domain=`) query to the BACKEND's narrow
// public hint route (`GET /api/sso/hint`) over the EDGE network, using a
// SERVER-ONLY `BACKEND_INTERNAL_URL` env.
//
// WHY this indirection (the AX never lets the browser hit the backend directly):
//   - BACK-01 boundary: the org lookup MUST go through the backend, not Kratos.
//     The AX's sanctioned Kratos-public exception is ONLY the self-service flow
//     proxy (middleware.ts) — NOT this lookup.
//   - T-15-18 (no internal-host leak): `BACKEND_INTERNAL_URL` is a server-only
//     env (NOT NEXT_PUBLIC_), so the internal backend hostname never reaches the
//     client bundle. The browser only ever sees this same-origin AX route.
//   - T-15-16 (no enumeration): the backend hint returns only `{ provider }` or
//     404; this route forwards exactly that shape, mapping any non-200 / error to
//     a 404 so the client treats it uniformly as "no SSO route".
//
// Runtime: force the Node.js runtime (NOT edge) — this route reads a server-only
// env and performs an outbound fetch to an internal hostname, neither of which
// belongs on the edge runtime.
// =============================================================================

export const runtime = "nodejs"
export const dynamic = "force-dynamic"

/** Server-only backend base URL on the edge network (NEVER NEXT_PUBLIC_). */
function backendBaseUrl(): string | null {
  const url = process.env.BACKEND_INTERNAL_URL
  return url && url.trim().length > 0 ? url.replace(/\/+$/, "") : null
}

export async function GET(req: NextRequest): Promise<NextResponse> {
  const base = backendBaseUrl()
  if (!base) {
    // Misconfiguration (no backend URL): fail closed as "no SSO route" so the
    // login still proceeds normally. Never 500 the login experience.
    return NextResponse.json({ error: "not_found" }, { status: 404 })
  }

  const email = req.nextUrl.searchParams.get("email")?.trim() ?? ""
  const domain = req.nextUrl.searchParams.get("domain")?.trim() ?? ""
  if (!email && !domain) {
    return NextResponse.json({ error: "bad_request" }, { status: 400 })
  }

  // Build the backend query, forwarding only the single allowed parameter. We do
  // NOT pass through arbitrary query params (no SSRF/parameter-injection surface);
  // the backend re-validates + normalizes the value authoritatively.
  const qs = new URLSearchParams()
  if (email) qs.set("email", email)
  else qs.set("domain", domain)

  try {
    const upstream = await fetch(`${base}/api/sso/hint?${qs.toString()}`, {
      method: "GET",
      headers: { Accept: "application/json" },
      // Server-side fetch on the edge network; no cookies/credentials (the hint
      // is unauthenticated). Bound the wait so a slow backend never hangs login.
      signal: AbortSignal.timeout(5000),
      cache: "no-store",
    })

    if (upstream.status === 200) {
      const body = (await upstream.json().catch(() => null)) as
        | { provider?: unknown }
        | null
      if (body && typeof body.provider === "string" && body.provider.length > 0) {
        return NextResponse.json({ provider: body.provider }, { status: 200 })
      }
    }
    // 404 / feature-off / malformed / non-200 — uniformly "no SSO route".
    return NextResponse.json({ error: "not_found" }, { status: 404 })
  } catch {
    // Network/timeout/parse error — fail closed as "no SSO route" (login proceeds).
    return NextResponse.json({ error: "not_found" }, { status: 404 })
  }
}
