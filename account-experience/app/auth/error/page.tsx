import { OryPageParams } from "@ory/nextjs/app"

// =============================================================================
// Self-service error flow (AX-01).
//
// Kratos surfaces flow errors at the self-service errors endpoint
// (`/self-service/errors?id=<error_id>`), which the middleware proxies same-origin
// to Kratos public. We fetch it server-side via ORY_SDK_URL (the same server-only
// proxy target the rest of the service uses) and render the error ourselves.
//
// We deliberately do NOT use Ory Elements' <Error> theme component here: in
// @ory/elements-react 1.1.0 it renders `error.timestamp.toUTCString()`, but the
// Kratos error payload carries `created_at`/`updated_at` as ISO STRINGS (no
// `Date`), so the component throws "toUTCString is not a function" and turns every
// flow-error into an HTTP 500 — an error page must never itself error. A small
// self-contained card sidesteps the upstream bug and stays robust for any error
// shape (a missing id, a fetch failure, a partial payload).
// =============================================================================

const ORY_SDK_URL = process.env.ORY_SDK_URL ?? "http://kratos:4433"

type FlowError = {
  id?: string
  error?: {
    code?: number
    status?: string
    reason?: string
    message?: string
  }
  created_at?: string
}

async function fetchFlowError(id: string): Promise<FlowError | null> {
  try {
    const res = await fetch(
      `${ORY_SDK_URL}/self-service/errors?id=${encodeURIComponent(id)}`,
      { headers: { Accept: "application/json" }, cache: "no-store" },
    )
    if (!res.ok) {
      return null
    }
    return (await res.json()) as FlowError
  } catch {
    return null
  }
}

function ErrorCard({
  title,
  message,
  detail,
  id,
}: {
  title: string
  message: string
  detail?: string
  id?: string
}) {
  return (
    <div className="flex flex-col gap-3 rounded-lg border border-current/15 p-6 text-center">
      <h1 className="text-lg font-semibold">{title}</h1>
      <p className="text-sm opacity-80">{message}</p>
      {detail ? <p className="text-sm opacity-70">{detail}</p> : null}
      <a
        href="/auth/login"
        className="mt-2 inline-block rounded-md border border-current px-3 py-2 text-sm no-underline transition-opacity hover:opacity-80"
      >
        Back to sign in
      </a>
      {id ? <p className="text-xs opacity-50">Reference: {id}</p> : null}
    </div>
  )
}

export default async function ErrorPage(props: OryPageParams) {
  const searchParams = await props.searchParams
  const idParam = searchParams?.id
  const id = Array.isArray(idParam) ? idParam[0] : idParam

  const error = id ? await fetchFlowError(id) : null

  if (!error) {
    return (
      <ErrorCard
        title="Something went wrong"
        message="An unexpected error occurred. Please try again."
      />
    )
  }

  const e = error.error ?? {}
  return (
    <ErrorCard
      title={e.reason || e.status || "Something went wrong"}
      message={e.message || "An unexpected error occurred. Please try again."}
      id={error.id ?? id}
    />
  )
}
