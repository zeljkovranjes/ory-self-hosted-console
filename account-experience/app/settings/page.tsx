import "@ory/elements-react/theme/styles.css"
import { Settings } from "@ory/elements-react/theme"
import { getSettingsFlow, OryPageParams } from "@ory/nextjs/app"
import config from "@/ory.config"

// Settings (account management) self-service flow (AX-01). Lives outside /auth,
// so it imports the Elements theme stylesheet directly (the auth/layout.tsx
// import does not cover this subtree).
export default async function SettingsPage(props: OryPageParams) {
  const flow = await getSettingsFlow(config, props.searchParams)
  if (!flow) {
    return null
  }
  return <Settings flow={flow} config={config} components={{ Card: {} }} />
}
