// =============================================================================
// AX runtime override-file reader (AX-02 theming + AX-03 localization).
//
// SERVER-ONLY. The console (Rust backend) is the SOLE writer of these two files
// to the mounted config volume (`{config_dir}/account-experience/{theme.css,
// translations.json}` — see backend/src/account_experience). The AX reads them
// at BOOT / module init here, so a broker restart of the AX container re-runs
// `node server.js`, which re-imports these modules and re-reads the files —
// applying a console edit on the next AX RESTART with NO rebuild (15-RESEARCH
// A3 / Pitfall 6).
//
// Mount path: the compose volume bind-mounts the host `./config/account-
// experience` directory READ-ONLY into the AX container at the path given by
// `AX_OVERRIDES_DIR` (default `/etc/account-experience-config`). The AX never
// writes here; a missing/empty/corrupt file falls back to a safe default (the
// stock theme / `{}` translations) so first boot and a malformed write never
// brick the UI (T-15-08 read-side defense).
//
// EDGE-SAFETY (blocking correctness fix): `ory.config.ts` is imported by BOTH
// the per-flow server components (Node runtime — they need the translations) AND
// `middleware.ts`, which @ory/nextjs runs on the EDGE runtime, where `node:fs` is
// unavailable. So this reader MUST NOT statically import `node:fs`: a top-level
// `import "node:fs"` here would be bundled into the edge middleware and crash the
// proxy at runtime. We therefore read the files via a runtime-guarded dynamic
// `require("node:fs")`, returning the safe default on the Edge runtime (where the
// overrides are irrelevant anyway — the proxy renders no UI). The Node server
// render path (layout.tsx + the flow pages) is where the real read happens.
// The read is server-side only; it is never bundled into client JS.
// =============================================================================

import type { OryClientConfiguration } from "@ory/elements-react"

/** The directory the console-owned override files are mounted at (read-only). */
function overridesDir(): string {
  return process.env.AX_OVERRIDES_DIR ?? "/etc/account-experience-config"
}

/**
 * Read a file as UTF-8, EDGE-SAFE. Returns `null` on the Edge runtime (no fs) or
 * on any read error (ENOENT/EACCES/decode). Uses a runtime-guarded dynamic
 * `require` so `node:fs` is never statically bundled into the edge middleware.
 */
function readFileSafe(name: string): string | null {
  // `NEXT_RUNTIME === "edge"` in edge middleware; "nodejs" in server components.
  if (process.env.NEXT_RUNTIME === "edge") return null
  try {
    // EDGE-SAFETY: BOTH `node:fs` AND `node:path` are loaded via a guarded
    // dynamic `require` (NOT a static top-level import). A static
    // `import { join } from "node:path"` (or `import "node:fs"`) gets bundled
    // into the @ory/nextjs EDGE middleware (ory.config.ts -> overrides.ts ->
    // middleware.ts) and crashes it at runtime ("Native module not found:
    // node:path") — the edge runtime has no Node built-ins. Keeping both dynamic
    // and behind the `NEXT_RUNTIME==="edge"` guard keeps them out of the edge
    // bundle entirely; the read only ever runs on the Node render path.
    // eslint-disable-next-line @typescript-eslint/no-require-imports -- guarded
    const fs = require("node:fs") as typeof import("node:fs")
    // eslint-disable-next-line @typescript-eslint/no-require-imports -- guarded
    const { join } = require("node:path") as typeof import("node:path")
    return fs.readFileSync(join(overridesDir(), name), "utf8")
  } catch {
    return null
  }
}

/**
 * Read the console-written theming CSS-variable override at boot. Returns the
 * raw CSS text to inject as a `:root{…}` `<style>` block AFTER the Elements
 * styles import (so the override custom properties win). A missing/empty/
 * unreadable file → empty string (no injection → the stock Elements theme).
 *
 * The text is injected verbatim; the console backend already rejects binary
 * content on write (T-15-06), and the AX only ever places it inside a `<style>`
 * element (it is CSS, never executed as script).
 */
export function readThemeOverride(): string {
  const css = readFileSafe("theme.css")
  // Missing / Edge runtime / unreadable → no override (stock theme). Never throw:
  // a theming-file problem must not take down the auth UI.
  return css && css.trim().length > 0 ? css : ""
}

/**
 * Read the console-written `customTranslations` catalog at boot. Returns a
 * `Partial<LocaleMap>` suitable for `OryClientConfiguration.intl.custom-
 * Translations`. A missing/empty file → `undefined` (Elements uses its built-in
 * catalog); a present-but-MALFORMED file → `undefined` too (the read-side
 * fallback for T-15-08 — the backend already 422-rejects malformed writes, so a
 * corrupt file here means a foreign/partial write, which we ignore rather than
 * crash boot).
 */
export function readTranslationsOverride():
  | NonNullable<OryClientConfiguration["intl"]>["customTranslations"]
  | undefined {
  const raw = readFileSafe("translations.json")
  if (!raw || raw.trim().length === 0) return undefined
  try {
    const parsed = JSON.parse(raw)
    // Only an object is a valid LocaleMap; anything else is ignored.
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as NonNullable<
        OryClientConfiguration["intl"]
      >["customTranslations"]
    }
    return undefined
  } catch {
    return undefined
  }
}
