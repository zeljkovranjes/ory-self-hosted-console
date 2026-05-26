import { Error as OryErrorComponent } from "@ory/elements-react/theme"
import { OryPageParams } from "@ory/nextjs/app"
import config from "@/ory.config"
import type { OryError } from "@ory/elements-react/theme"

// =============================================================================
// Self-service error flow (AX-01).
//
// Unlike login/registration/recovery/verification/settings, @ory/nextjs/app does
// NOT export a `getErrorFlow`. Kratos surfaces flow errors at the self-service
// errors endpoint (`/self-service/errors?id=<error_id>`), which the middleware
// proxies same-origin to Kratos public. We fetch it server-side via ORY_SDK_URL
// (the same server-only proxy target the rest of the service uses) and hand the
// error object to the Elements <Error> theme component.
//
// If no `id` is present, or the fetch fails, we render a minimal fallback rather
// than throwing — an error page must never itself error.
// =============================================================================

const ORY_SDK_URL = process.env.ORY_SDK_URL ?? "http://ory-kratos:4433"

async function fetchFlowError(id: string): Promise<OryError | null> {
  try {
    const res = await fetch(
      `${ORY_SDK_URL}/self-service/errors?id=${encodeURIComponent(id)}`,
      { headers: { Accept: "application/json" }, cache: "no-store" },
    )
    if (!res.ok) {
      return null
    }
    return (await res.json()) as OryError
  } catch {
    return null
  }
}

export default async function ErrorPage(props: OryPageParams) {
  const searchParams = await props.searchParams
  const idParam = searchParams?.id
  const id = Array.isArray(idParam) ? idParam[0] : idParam

  const error = id ? await fetchFlowError(id) : null

  if (!error) {
    return (
      <main style={{ padding: "2rem", textAlign: "center" }}>
        <h1>Something went wrong</h1>
        <p>An unexpected error occurred. Please try again.</p>
      </main>
    )
  }

  return <OryErrorComponent error={error} config={config} />
}
