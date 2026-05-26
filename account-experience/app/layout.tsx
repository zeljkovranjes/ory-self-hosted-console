import type { Metadata } from "next"
import localFont from "next/font/local"
import "./globals.css"

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
  return (
    <html lang="en" className={geist.variable}>
      <body>{children}</body>
    </html>
  )
}
