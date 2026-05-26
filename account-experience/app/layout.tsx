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

/**
 * CR-01 SINK HARDENING (defense-in-depth LAYER 2): neutralize any `<` before the
 * CSS override is injected into a `<style>` element via `dangerouslySetInnerHTML`.
 *
 * A `<style>` is an HTML RAW-TEXT element: the tokenizer does NOT CSS-parse its
 * body, it ends the element at the first literal `</style` and resumes markup
 * parsing — so a stored `…</style><script>…</script>` would break out and inject
 * an executable script. The backend write-path already rejects any `<` (LAYER 1),
 * but this sink must NOT trust the file: a pre-existing or out-of-band-written
 * malicious `theme.css` must still be neutralized here.
 *
 * We escape `<` to its CSS-harmless backslash form `\3C` (a valid CSS escape the
 * HTML tokenizer will NOT treat as the start of a tag). This keeps any legitimate
 * CSS rendering correct while making `</style>`, `<script>`, `<!--`, etc. inert.
 */
function defangThemeCss(css: string): string {
  // Replace EVERY '<' so `</style`, `<script`, `<!--`, and any other markup
  // start can never close the <style> element or open a tag. `\3C ` is the CSS
  // numeric escape for U+003C; the trailing space terminates the escape so an
  // adjacent hex digit is not absorbed. Legitimate CSS never contains '<'.
  return css.replace(/</g, "\\3C ")
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
  // theme).
  //
  // CR-01 (stored XSS): the override is DEFANGED at this sink (`defangThemeCss`,
  // escaping every '<') before injection, so even a maliciously-written theme.css
  // (bypassing the backend write-guard) cannot break out of the <style> element
  // into an executable <script>. The backend write-path is the primary guard
  // (rejects any '<', LAYER 1); this is the independent second layer.
  const themeOverride = readThemeOverride()
  const safeThemeOverride = themeOverride ? defangThemeCss(themeOverride) : ""

  return (
    <html lang="en" className={geist.variable}>
      <body>
        {children}
        {safeThemeOverride ? (
          <style
            id="ax-theme-override"
            // eslint-disable-next-line react/no-danger -- CSS custom-property
            // override read from the console-owned override file; placed in a
            // <style> element and DEFANGED (every '<' escaped to `\3C `) so it
            // cannot break out of the style block (CR-01 sink hardening). The
            // backend also rejects any '<' on write (LAYER 1).
            dangerouslySetInnerHTML={{ __html: safeThemeOverride }}
          />
        ) : null}
      </body>
    </html>
  )
}
