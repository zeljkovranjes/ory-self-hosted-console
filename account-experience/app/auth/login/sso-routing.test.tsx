import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import { render, screen, fireEvent, waitFor } from "@testing-library/react"
import { SsoRouting } from "./sso-routing"

// =============================================================================
// AX login org-domain->SSO routing (AX-01 / SSO-06 surfacing) unit tests.
//
// The affordance is now a COLLAPSED secondary entry: it renders nothing unless
// the flow carries an SSO provider, and the work-email field appears only after
// the user clicks the "Sign in with SSO" toggle. Tests prove:
//   0. No provider on the flow (`providerInitiateUrls` empty) -> renders NOTHING
//      (no toggle, no stray email field).
//   1. Clicking the toggle reveals the email field; an org-domain email (the AX
//      server route returns a provider) surfaces a "Continue with <provider> SSO"
//      control routing to the matching Kratos OIDC initiate URL.
//   2. An unknown-domain email (the AX server route 404s -> null) surfaces NO
//      SSO affordance (the normal password login proceeds).
//   3. The lookup targets the AX's OWN server route (`/api/sso-lookup`), NOT
//      Kratos directly (BACK-01 boundary, T-15-19).
//
// `fetch` is mocked: the component's `lib/sso-lookup` calls the AX server route,
// which we intercept here — no live backend/Kratos needed.
// =============================================================================

const FETCH_CALLS: string[] = []

function mockFetchProvider(provider: string | null) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      FETCH_CALLS.push(String(input))
      if (provider) {
        return new Response(JSON.stringify({ provider }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        })
      }
      // Unknown domain -> the AX server route 404s (uniform "no SSO route").
      return new Response(JSON.stringify({ error: "not_found" }), { status: 404 })
    }) as unknown as typeof fetch,
  )
}

describe("AX login org-domain->SSO routing", () => {
  beforeEach(() => {
    FETCH_CALLS.length = 0
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })

  it("renders nothing when the flow carries no SSO provider", () => {
    mockFetchProvider("org-acme")
    const { container } = render(<SsoRouting providerInitiateUrls={{}} />)
    expect(screen.queryByTestId("ax-sso-toggle")).toBeNull()
    expect(screen.queryByTestId("ax-sso-email-input")).toBeNull()
    expect(container).toBeEmptyDOMElement()
  })

  it("surfaces a 'Continue with SSO' affordance for an org-domain email", async () => {
    mockFetchProvider("org-acme")
    render(
      <SsoRouting providerInitiateUrls={{ "org-acme": "/self-service/login?flow=abc&provider=org-acme" }} />,
    )
    // The email field is hidden until the SSO entry point is opened.
    expect(screen.queryByTestId("ax-sso-email-input")).toBeNull()
    fireEvent.click(screen.getByTestId("ax-sso-toggle"))
    const input = screen.getByTestId("ax-sso-email-input")
    fireEvent.change(input, { target: { value: "user@corp.com" } })

    const cta = await screen.findByTestId("ax-sso-continue")
    expect(cta).toBeTruthy()
    expect(cta.textContent).toContain("org-acme")
    // It routes to the matching Kratos OIDC initiate URL (the flow node target).
    expect(cta.getAttribute("href")).toBe(
      "/self-service/login?flow=abc&provider=org-acme",
    )
  })

  it("surfaces NO SSO affordance for an unknown-domain email (password login proceeds)", async () => {
    mockFetchProvider(null)
    render(<SsoRouting providerInitiateUrls={{ "org-acme": "/self-service/login?provider=org-acme" }} />)
    fireEvent.click(screen.getByTestId("ax-sso-toggle"))
    const input = screen.getByTestId("ax-sso-email-input")
    fireEvent.change(input, { target: { value: "user@unknown-domain.example" } })

    // Wait for the debounced lookup to resolve, then assert no affordance.
    await waitFor(() => {
      expect(screen.queryByTestId("ax-sso-checking")).toBeNull()
    })
    expect(screen.queryByTestId("ax-sso-continue")).toBeNull()
    expect(screen.queryByTestId("ax-sso-notice")).toBeNull()
  })

  it("queries the AX server route (/api/sso-lookup), never Kratos directly", async () => {
    mockFetchProvider("org-acme")
    render(<SsoRouting providerInitiateUrls={{ "org-acme": "/self-service/login?provider=org-acme" }} />)
    fireEvent.click(screen.getByTestId("ax-sso-toggle"))
    fireEvent.change(screen.getByTestId("ax-sso-email-input"), {
      target: { value: "user@corp.com" },
    })
    await screen.findByTestId("ax-sso-continue")

    expect(FETCH_CALLS.length).toBeGreaterThan(0)
    for (const url of FETCH_CALLS) {
      // The lookup must target the AX's own same-origin server route…
      expect(url).toContain("/api/sso-lookup")
      // …and NEVER hit Kratos public/admin or the internal backend host directly.
      expect(url).not.toMatch(/kratos|:4433|:4434|:8080/i)
      expect(url).not.toMatch(/self-service/i)
    }
    // The typed email is forwarded as the email query param.
    expect(FETCH_CALLS.some((u) => u.includes("email=user%40corp.com"))).toBe(true)
  })
})
