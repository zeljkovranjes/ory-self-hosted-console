import { Login } from "@ory/elements-react/theme"
import { getLoginFlow, OryPageParams } from "@ory/nextjs/app"
import config from "@/ory.config"
import { SsoRouting } from "./sso-routing"

// Login self-service flow (AX-01). Server component: fetch the flow server-side
// through the @ory/nextjs proxy (-> Kratos public), then render the Elements
// <Login> theme component. Layered ABOVE it is the org-domain->SSO routing
// affordance (SSO-06 surfacing): the user's email is matched (via the AX server
// route -> backend hint) to their org's linked SSO connection, routing them to
// the matching Kratos OIDC provider's initiate URL. An unknown domain surfaces
// nothing and the normal password login proceeds.

/**
 * Extract `{ providerId -> initiateUrl }` from the flow's `methods.oidc` UI
 * nodes. Kratos renders each social/oidc provider as an `input` node in the
 * `oidc` group with `attributes.name === "provider"` and `attributes.value` =
 * the provider id; the node's form action is the initiate URL. We map the
 * provider id to the flow's `ui.action` (the same submit target the Elements
 * provider button posts to) so the SSO affordance routes through the real flow.
 */
function oidcProviderInitiateUrls(flow: {
  ui?: { action?: string; nodes?: Array<Record<string, unknown>> }
}): Record<string, string> {
  const action = flow.ui?.action
  const nodes = flow.ui?.nodes ?? []
  if (!action) return {}
  const map: Record<string, string> = {}
  for (const node of nodes) {
    const group = node["group"]
    const attrs = node["attributes"] as Record<string, unknown> | undefined
    if (
      group === "oidc" &&
      attrs &&
      attrs["name"] === "provider" &&
      typeof attrs["value"] === "string" &&
      (attrs["value"] as string).length > 0
    ) {
      // The provider button posts to the flow action with method=oidc &
      // provider=<id>. The initiate URL is that action with the provider
      // pre-selected as a GET-friendly fallback link.
      const id = attrs["value"] as string
      const url = new URL(action, "http://localhost")
      url.searchParams.set("provider", id)
      // Preserve a relative/same-origin URL where possible (the flow action is
      // rewritten to the AX origin by the proxy for browser navigations).
      map[id] = action.startsWith("http")
        ? `${action}${action.includes("?") ? "&" : "?"}provider=${encodeURIComponent(id)}`
        : `${url.pathname}${url.search}`
    }
  }
  return map
}

export default async function LoginPage(props: OryPageParams) {
  const flow = await getLoginFlow(config, props.searchParams)
  if (!flow) {
    return null
  }
  const providerInitiateUrls = oidcProviderInitiateUrls(
    flow as unknown as { ui?: { action?: string; nodes?: Array<Record<string, unknown>> } },
  )
  return (
    <>
      <Login flow={flow} config={config} components={{ Card: {} }} />
      {/* SSO is a SECONDARY entry below the primary password/login card; it
          renders nothing unless the flow actually carries an SSO provider. */}
      <SsoRouting providerInitiateUrls={providerInitiateUrls} />
    </>
  )
}
