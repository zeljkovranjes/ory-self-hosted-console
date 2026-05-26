// =============================================================================
// AX login-time domain->SSO HINT client (AX-01 / SSO-06 surfacing).
//
// The browser-side helper the login screen calls when an email is entered. It
// queries the AX's OWN server route (`/api/sso-lookup`), which proxies to the
// backend's narrow public hint endpoint (`GET /api/sso/hint`) on the edge
// network. The browser NEVER talks to the backend (or Kratos) directly for the
// lookup — it talks to the same-origin AX server route, which holds the
// server-only `BACKEND_INTERNAL_URL` (the internal backend hostname never
// reaches the client bundle — threat T-15-18).
//
// Contract (mirrors the backend hint, T-15-16): an org-domain email with a
// linked SSO connection resolves to `{ provider }`; an unknown domain, a domain
// with no linked connection, the Organizations feature being OFF, OR any
// transport/parse error ALL resolve to `null` — i.e. "no SSO route, proceed with
// the normal password login". The lookup is best-effort and never throws: a
// hint failure must never block the standard login.
// =============================================================================

/** The AX same-origin server route that proxies the backend SSO hint. */
const SSO_LOOKUP_PATH = "/api/sso-lookup"

/** The resolved SSO hint: the provider tenant to route the end-user to. */
export type SsoHint = { provider: string }

/**
 * Look up the SSO provider hint for an email's domain via the AX server route.
 *
 * @param email The raw email the user typed. The domain is extracted + matched
 *              server-side (the backend normalizes it the same way it does on
 *              write, so a case/IDNA/sub-domain variant resolves identically).
 * @returns `{ provider }` when the domain maps to an org's linked SSO connection,
 *          or `null` for ANY non-match (unknown domain, no linked connection,
 *          feature OFF, or an error). Never throws.
 */
export async function lookupSsoHint(
  email: string,
  signal?: AbortSignal,
): Promise<SsoHint | null> {
  const trimmed = email.trim()
  // Only query once the input looks like an email with a domain part. This is a
  // cheap client guard; the backend re-validates + normalizes authoritatively.
  if (!trimmed || !trimmed.includes("@") || trimmed.endsWith("@")) {
    return null
  }
  try {
    const res = await fetch(
      `${SSO_LOOKUP_PATH}?email=${encodeURIComponent(trimmed)}`,
      {
        method: "GET",
        headers: { Accept: "application/json" },
        // Same-origin AX route; no credentials needed (the hint is unauthenticated).
        signal,
      },
    )
    if (!res.ok) {
      // 404 (no SSO route), 4xx (bad/feature-off), 5xx — all mean "no hint".
      return null
    }
    const body = (await res.json().catch(() => null)) as { provider?: unknown } | null
    if (body && typeof body.provider === "string" && body.provider.length > 0) {
      return { provider: body.provider }
    }
    return null
  } catch {
    // AbortError, network failure, parse failure — all non-fatal: no SSO route.
    return null
  }
}
