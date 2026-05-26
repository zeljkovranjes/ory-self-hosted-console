import type { Metadata } from "next"
import localFont from "next/font/local"
import "./globals.css"
import { readThemeOverride } from "@/lib/overrides"

// =============================================================================
// AX root layout.
//
// LOCAL FONT (zero-CDN — 15-RESEARCH Pitfall 4 / threat T-15-05): the official
// `examples/nextjs-app-router` imports `Inter` from `next/font/google`, which
// fetches the font from Google Fonts at build time — a CDN-egress violation of
// this project's zero-CDN discipline. We SWAP it for `next/font/local` pointing
// at a vendored Geist woff2 under `public/fonts/` (OFL-licensed, redistribution-
// safe). No `next/font/google` import exists anywhere in this service; the AX
// bundle-egress gate asserts no CDN/Google-Fonts URL in the built output.
// =============================================================================

const geist = localFont({
  src: [
    { path: "../public/fonts/geist-latin.woff2", weight: "100 900", style: "normal" },
  ],
  variable: "--font-sans",
  display: "swap",
  fallback: ["system-ui", "Segoe UI", "Helvetica Neue", "Arial", "sans-serif"],
})

export const metadata: Metadata = {
  title: "Account Experience",
  description: "Self-hosted Ory Account Experience",
}

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  // AX-02: read the console-written CSS-variable override at boot (server-only
  // `fs` read — lib/overrides.ts). It is injected as a `<style>` at the END of
  // <body> so it cascades AFTER the Elements theme styles (imported in the
  // nested auth/settings layouts), letting the override `--ui-*`/`--button-*`
  // custom properties win. Because the AX server re-reads this on process start,
  // a console edit + AX broker RESTART applies the new theme with NO rebuild
  // (15-RESEARCH A3 / Pitfall 6). A missing/empty file → no injection (stock
  // theme). The content is CSS placed inside <style>; it is never executed as
  // script, and the backend already rejects binary on write (T-15-06).
  const themeOverride = readThemeOverride()

  return (
    <html lang="en" className={geist.variable}>
      <body>
        {children}
        {themeOverride ? (
          <style
            id="ax-theme-override"
            // eslint-disable-next-line react/no-danger -- CSS custom-property
            // override read from the console-owned override file; placed in a
            // <style> element (never executed as script). The sole writer is the
            // backend, which rejects binary content (T-15-06).
            dangerouslySetInnerHTML={{ __html: themeOverride }}
          />
        ) : null}
      </body>
    </html>
  )
}
