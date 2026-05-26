// Monaco local-bundle init (FE-04, threat T-05-11) — the proven spike strategy.
//
// STRATEGY B (bundler-agnostic, the spike winner; see frontend/MONACO.md):
// @monaco-editor/react defaults to loading Monaco from jsDelivr (a CDN) — which
// is unacceptable for an air-gapped, self-hosted console and is an uncontrolled
// external egress / supply-chain surface. Instead we point the loader at a copy
// of Monaco's self-contained AMD distribution served from our OWN origin under
// `/monaco/vs` (copied from node_modules/monaco-editor/min/vs by
// scripts/copy-monaco.mjs at prebuild/predev). The AMD `loader.js` then fetches
// `editor/editor.main.js` AND the language Web Workers (min/vs/assets/*.worker-*)
// all relative to that same base — so the editor AND its language features
// (JSON validation squiggles, formatting, etc.) work with ZERO requests to the
// default jsDelivr CDN and ZERO dependency on Turbopack's worker transform.
//
// Why NOT Strategy A (`loader.config({ monaco })` + `?worker` ESM imports):
// the `?worker` import suffix is a webpack/Vite convention; Next 16 defaults to
// Turbopack where it does not apply the same way (05-RESEARCH Open Question A1).
// Strategy B sidesteps the bundler entirely.
//
// This module is imported only on the client (the wrapper is dynamic/ssr:false)
// and `setupMonaco()` is idempotent — safe to call before every editor mount.

import { loader } from "@monaco-editor/react";

// Same-origin base where scripts/copy-monaco.mjs places Monaco's `vs` tree.
// The ONLY URL Monaco will hit; it is a same-origin path (never a CDN host),
// so it cannot leak an external egress into the bundle (bundle-egress gate).
const MONACO_VS_PATH = "/monaco/vs";

let configured = false;

/**
 * Configure @monaco-editor/react to load Monaco (and its workers) from the
 * locally-served, same-origin `/monaco/vs` assets instead of the default CDN.
 *
 * Idempotent: only the first call wires the loader; subsequent calls are no-ops,
 * so it is safe to invoke on every MonacoEditor mount. Client-only (the loader
 * touches browser globals); guarded so an accidental server import is harmless.
 */
export function setupMonaco(): void {
  if (configured) return;
  if (typeof window === "undefined") return; // never run during SSR
  loader.config({ paths: { vs: MONACO_VS_PATH } });
  configured = true;
}

/** The same-origin Monaco base path (exported for tests / asset checks). */
export const monacoVsPath = MONACO_VS_PATH;
