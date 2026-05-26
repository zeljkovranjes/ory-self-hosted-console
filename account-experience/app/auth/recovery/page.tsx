import { Recovery } from "@ory/elements-react/theme"
import { getRecoveryFlow, OryPageParams } from "@ory/nextjs/app"
import config from "@/ory.config"

// Recovery self-service flow (AX-01).
export default async function RecoveryPage(props: OryPageParams) {
  const flow = await getRecoveryFlow(config, props.searchParams)
  if (!flow) {
    return null
  }
  return <Recovery flow={flow} config={config} components={{ Card: {} }} />
}
