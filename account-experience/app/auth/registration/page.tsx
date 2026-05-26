import { Registration } from "@ory/elements-react/theme"
import { getRegistrationFlow, OryPageParams } from "@ory/nextjs/app"
import config from "@/ory.config"

// Registration self-service flow (AX-01).
export default async function RegistrationPage(props: OryPageParams) {
  const flow = await getRegistrationFlow(config, props.searchParams)
  if (!flow) {
    return null
  }
  return <Registration flow={flow} config={config} components={{ Card: {} }} />
}
