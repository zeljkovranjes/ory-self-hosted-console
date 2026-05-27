import { redirect } from "next/navigation"

// Root index route.
//
// The AX app defines flows under /auth/* and /settings but has no page at "/",
// so a bare hit on the AX origin (http://localhost:3001/) previously fell through
// to Next's catch-all 404. `ory.config.ts` also sets `default_redirect_url: "/"`,
// so a completed flow would land here too — both want a real destination.
//
// Send the root at the login flow, the canonical AX entry point. An already-
// authenticated visitor is not trapped in a loop: Kratos's
// `selfservice.default_browser_return_url` (config/kratos/kratos.yml) points at
// the console origin, not back here, so the login flow forwards them onward.
export default function RootPage() {
  redirect("/auth/login")
}
