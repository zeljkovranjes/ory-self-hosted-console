import { Login } from "@ory/elements-react/theme"
import { getLoginFlow, OryPageParams } from "@ory/nextjs/app"
import config from "@/ory.config"

// Login self-service flow (AX-01). Server component: fetch the flow server-side
// through the @ory/nextjs proxy (-> Kratos public), then render the Elements
// <Login> theme component. Verbatim from examples/nextjs-app-router.
export default async function LoginPage(props: OryPageParams) {
  const flow = await getLoginFlow(config, props.searchParams)
  if (!flow) {
    return null
  }
  return <Login flow={flow} config={config} components={{ Card: {} }} />
}
