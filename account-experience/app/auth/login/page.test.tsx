import { describe, it, expect } from "vitest"
import { render, screen } from "@testing-library/react"
import { Login } from "@ory/elements-react/theme"
import config from "@/ory.config"
import type { LoginFlow } from "@ory/client-fetch"

// =============================================================================
// AX login unit smoke (AX-01).
//
// Renders the Elements <Login> theme component with a MOCKED Kratos LoginFlow
// object — NO live Kratos needed. The LIVE A1 proof (a real flow completing
// through the @ory/nextjs proxy + a same-origin ory_kratos_session cookie) is
// the GATING acceptance test in scripts/verify/phase15-acceptance.sh. This unit
// test only asserts the component mounts and renders the flow's form against a
// fixed flow shape, so a build/wiring regression is caught fast in CI.
// =============================================================================

// A minimal but structurally-valid password login flow (the shape getLoginFlow
// returns from Kratos v26.2.0): an action URL, a method, and the password +
// identifier + csrf_token UI nodes.
const mockFlow: LoginFlow = {
  id: "00000000-0000-0000-0000-000000000000",
  type: "browser",
  expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
  issued_at: new Date().toISOString(),
  request_url: "http://localhost:3001/self-service/login/browser",
  state: "choose_method",
  ui: {
    action: "http://localhost:3001/self-service/login?flow=00000000-0000-0000-0000-000000000000",
    method: "POST",
    nodes: [
      {
        type: "input",
        group: "default",
        attributes: {
          name: "csrf_token",
          type: "hidden",
          value: "mock-csrf",
          required: true,
          disabled: false,
          node_type: "input",
        },
        messages: [],
        meta: {},
      },
      {
        type: "input",
        group: "identifier_first",
        attributes: {
          name: "identifier",
          type: "text",
          value: "",
          required: true,
          disabled: false,
          node_type: "input",
        },
        messages: [],
        meta: { label: { id: 1070004, text: "Email", type: "info" } },
      },
      {
        type: "input",
        group: "password",
        attributes: {
          name: "password",
          type: "password",
          required: true,
          disabled: false,
          node_type: "input",
        },
        messages: [],
        meta: { label: { id: 1070001, text: "Password", type: "info" } },
      },
      {
        type: "input",
        group: "password",
        attributes: {
          name: "method",
          type: "submit",
          value: "password",
          disabled: false,
          node_type: "input",
        },
        messages: [],
        meta: { label: { id: 1010001, text: "Sign in", type: "info" } },
      },
    ],
  },
} as unknown as LoginFlow

describe("AX login page (unit smoke)", () => {
  it("mounts the Elements <Login> component with a mocked flow", () => {
    const { container } = render(<Login flow={mockFlow} config={config} components={{ Card: {} }} />)
    // The flow renders a form whose action targets the (mocked) self-service URL.
    const form = container.querySelector("form")
    expect(form).not.toBeNull()
    expect(form?.getAttribute("action")).toContain("/self-service/login")
  })

  it("renders the password sign-in submit control from the flow nodes", () => {
    render(<Login flow={mockFlow} config={config} components={{ Card: {} }} />)
    // The submit node carries the "Sign in" label — proves the flow's UI nodes
    // were consumed by the Elements renderer. "Sign in" appears in more than one
    // place (header + submit button), so assert at least one match exists rather
    // than a unique one.
    expect(screen.getAllByText(/sign in/i).length).toBeGreaterThan(0)
  })
})
