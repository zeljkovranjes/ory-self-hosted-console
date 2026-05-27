// AX self-service flow layout. Imports the Elements default theme stylesheet
// (a PACKAGE import — `dist/theme/default/index.css`, NO remote CDN) so every
// flow page (login/registration/recovery/verification/error) is styled. The
// `settings` page lives outside /auth but also imports this theme via its own
// tree; the styles.css import here covers the auth flows.
import "@ory/elements-react/theme/styles.css"

export default function AuthLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  // Center every self-service flow card both axes, with a sane max width so the
  // Elements <Card> doesn't stretch full-bleed on desktop. `min-h-screen` makes
  // the viewport the centering context; the inner wrapper constrains + stacks the
  // flow card and any sibling affordances (e.g. the SSO entry on the login page).
  return (
    <main className="flex min-h-screen flex-col items-center justify-center gap-4 p-4">
      <div className="w-full max-w-md">{children}</div>
    </main>
  )
}
