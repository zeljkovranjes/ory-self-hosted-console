"use client"

import { useEffect, useRef, useState } from "react"
import { lookupSsoHint } from "@/lib/sso-lookup"

// =============================================================================
// AX login org-domain->SSO routing affordance (AX-01 / SSO-06 surfacing).
//
// CLIENT component layered ABOVE the Elements <Login> flow. UX (the implementer's
// discretion per the plan — inline-on-blur detection): the operator's end-user
// types their email; on blur (debounced) we ask the AX server route for a domain
// ->SSO provider hint. If the domain maps to an org's linked SSO connection, we
// surface a "Continue with <provider> SSO" affordance that routes the user to
// that provider's Kratos OIDC initiate URL on the active login flow. An unknown
// domain (404 / null) surfaces NOTHING — the normal password login proceeds.
//
// SECURITY/PRIVACY:
//   - The hint goes browser -> AX server route -> backend (BACK-01; never Kratos
//     directly, never the internal backend host in the bundle — T-15-18/19).
//   - A 404/null is treated as "no SSO route" — the affordance simply does not
//     appear, so an unknown vs. known-non-SSO domain is indistinguishable to the
//     end-user (T-15-16 enumeration discipline preserved client-side too).
//
// ROUTING: `providerInitiateUrls` is the map of `{ providerId -> initiateUrl }`
// extracted server-side from the flow's `methods.oidc` UI nodes (the Kratos
// provider buttons). When a hint's `provider` matches a known provider id we
// route to its initiate URL (a real Kratos OIDC node); when the hint names a
// provider not present as a flow node (e.g. the flow has no oidc method wired),
// we surface a non-routing informational notice rather than a dead link.
// =============================================================================

export type SsoRoutingProps = {
  /** Map of Kratos OIDC provider id -> its initiate URL, from the flow nodes. */
  providerInitiateUrls: Record<string, string>
}

const DEBOUNCE_MS = 400

export function SsoRouting({ providerInitiateUrls }: SsoRoutingProps) {
  const [email, setEmail] = useState("")
  const [hint, setHint] = useState<{ provider: string } | null>(null)
  const [checking, setChecking] = useState(false)
  const abortRef = useRef<AbortController | null>(null)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  // Debounced lookup driven by the email value. Cancels any in-flight request.
  useEffect(() => {
    if (timerRef.current) clearTimeout(timerRef.current)
    abortRef.current?.abort()
    if (!email.includes("@") || email.trim().endsWith("@")) {
      setHint(null)
      setChecking(false)
      return
    }
    const controller = new AbortController()
    abortRef.current = controller
    setChecking(true)
    timerRef.current = setTimeout(async () => {
      const result = await lookupSsoHint(email, controller.signal)
      if (!controller.signal.aborted) {
        setHint(result)
        setChecking(false)
      }
    }, DEBOUNCE_MS)
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current)
      controller.abort()
    }
  }, [email])

  // Resolve the routing target: a matching Kratos OIDC provider node, if any.
  const initiateUrl = hint ? providerInitiateUrls[hint.provider] : undefined

  return (
    <div data-testid="ax-sso-routing" style={{ marginBottom: "0.75rem" }}>
      <label htmlFor="ax-sso-email" style={{ display: "block", fontSize: "0.875rem", marginBottom: "0.25rem" }}>
        Work email
      </label>
      <input
        id="ax-sso-email"
        type="email"
        name="ax-sso-email"
        autoComplete="email"
        placeholder="you@company.com"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        data-testid="ax-sso-email-input"
        style={{ width: "100%", padding: "0.5rem", boxSizing: "border-box" }}
      />
      {checking ? (
        <p data-testid="ax-sso-checking" style={{ fontSize: "0.75rem", opacity: 0.7 }}>
          Checking for single sign-on…
        </p>
      ) : null}
      {hint && initiateUrl ? (
        <a
          data-testid="ax-sso-continue"
          href={initiateUrl}
          role="button"
          style={{
            display: "block",
            marginTop: "0.5rem",
            padding: "0.5rem 0.75rem",
            textAlign: "center",
            border: "1px solid currentColor",
            borderRadius: "0.375rem",
            textDecoration: "none",
          }}
        >
          Continue with {hint.provider} SSO
        </a>
      ) : null}
      {hint && !initiateUrl ? (
        <p data-testid="ax-sso-notice" style={{ fontSize: "0.75rem", marginTop: "0.5rem" }}>
          Single sign-on is configured for your organization ({hint.provider}). If
          you do not see a sign-in button, contact your administrator.
        </p>
      ) : null}
    </div>
  )
}
