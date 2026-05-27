"use client"

import { useEffect, useRef, useState } from "react"
import { lookupSsoHint } from "@/lib/sso-lookup"

// =============================================================================
// AX login org-domain->SSO routing affordance (AX-01 / SSO-06 surfacing).
//
// CLIENT component rendered alongside the Elements <Login> flow. It is now a
// COLLAPSED secondary entry point ("Sign in with SSO") rather than an always-on
// email field at the top of the form (which read as a confusing stray input):
//
//   - It renders NOTHING unless the active login flow actually carries an
//     SSO/SAML/OIDC provider to route to (`providerInitiateUrls` non-empty). With
//     no provider the org-domain lookup can never route, so the affordance would
//     be pure noise — so SSO is only surfaced "when SSO is enabled".
//   - When SSO IS available, it shows a single "Sign in with SSO" button. Only on
//     click does it reveal the work-email input that drives the domain->provider
//     hint. If the typed domain maps to an org's linked SSO connection we surface
//     a "Continue with <provider> SSO" link to that provider's Kratos OIDC
//     initiate URL; an unknown domain surfaces nothing (normal password login).
//
// SECURITY/PRIVACY (unchanged):
//   - The hint goes browser -> AX server route -> backend (BACK-01; never Kratos
//     directly, never the internal backend host in the bundle — T-15-18/19).
//   - A 404/null is treated as "no SSO route" — indistinguishable from a
//     known-non-SSO domain (T-15-16 enumeration discipline preserved client-side).
//
// ROUTING: `providerInitiateUrls` is the map of `{ providerId -> initiateUrl }`
// extracted server-side from the flow's `methods.oidc` UI nodes (the Kratos
// provider buttons). A matched hint routes to that provider's initiate URL; a
// hint naming a provider not present as a flow node surfaces an informational
// notice rather than a dead link.
// =============================================================================

export type SsoRoutingProps = {
  /** Map of Kratos OIDC provider id -> its initiate URL, from the flow nodes. */
  providerInitiateUrls: Record<string, string>
}

const DEBOUNCE_MS = 400

export function SsoRouting({ providerInitiateUrls }: SsoRoutingProps) {
  const hasSso = Object.keys(providerInitiateUrls).length > 0

  const [open, setOpen] = useState(false)
  const [email, setEmail] = useState("")
  const [hint, setHint] = useState<{ provider: string } | null>(null)
  const [checking, setChecking] = useState(false)
  const abortRef = useRef<AbortController | null>(null)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  // Debounced lookup driven by the email value, only once the field is revealed.
  // Cancels any in-flight request.
  useEffect(() => {
    if (!open) return
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
  }, [email, open])

  // Only surface the SSO entry point when the flow actually has a provider.
  if (!hasSso) {
    return null
  }

  // Resolve the routing target: a matching Kratos OIDC provider node, if any.
  const initiateUrl = hint ? providerInitiateUrls[hint.provider] : undefined

  return (
    <div data-testid="ax-sso-routing" className="mt-4">
      {!open ? (
        <button
          type="button"
          data-testid="ax-sso-toggle"
          onClick={() => setOpen(true)}
          className="w-full rounded-md border border-current px-3 py-2 text-sm font-medium transition-opacity hover:opacity-80"
        >
          Sign in with SSO
        </button>
      ) : (
        <div className="flex flex-col gap-1">
          <label htmlFor="ax-sso-email" className="text-sm font-medium">
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
            autoFocus
            className="w-full rounded-md border border-current px-3 py-2 text-sm"
          />
          {checking ? (
            <p data-testid="ax-sso-checking" className="text-xs opacity-70">
              Checking for single sign-on…
            </p>
          ) : null}
          {hint && initiateUrl ? (
            <a
              data-testid="ax-sso-continue"
              href={initiateUrl}
              role="button"
              className="mt-2 block rounded-md border border-current px-3 py-2 text-center text-sm no-underline transition-opacity hover:opacity-80"
            >
              Continue with {hint.provider} SSO
            </a>
          ) : null}
          {hint && !initiateUrl ? (
            <p data-testid="ax-sso-notice" className="mt-2 text-xs">
              Single sign-on is configured for your organization ({hint.provider}).
              If you do not see a sign-in button, contact your administrator.
            </p>
          ) : null}
        </div>
      )}
    </div>
  )
}
