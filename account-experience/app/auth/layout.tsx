// AX self-service flow layout. Imports the Elements default theme stylesheet
// (a PACKAGE import — `dist/theme/default/index.css`, NO remote CDN) so every
// flow page (login/registration/recovery/verification/error) is styled. The
// `settings` page lives outside /auth but also imports this theme via its own
// tree; the styles.css import here covers the auth flows.
import "@ory/elements-react/theme/styles.css"

export default function AuthLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return <main>{children}</main>
}
