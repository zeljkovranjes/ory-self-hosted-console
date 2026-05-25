// Copy Monaco's self-contained AMD distribution (monaco-editor/min/vs) into
// public/monaco/vs so the editor + its language Web Workers load from the
// SAME ORIGIN with ZERO external (jsDelivr/CDN) egress — the air-gapped /
// supply-chain requirement (FE-04, threat T-05-11; see frontend/MONACO.md).
//
// This is Strategy B from 05-RESEARCH (Pitfall 1 / Pattern 6): bundler-agnostic.
// @monaco-editor/react is pointed at /monaco/vs via loader.config({ paths }) in
// lib/monaco-setup.ts; the AMD loader.js then fetches editor.main.js and the
// pre-built workers (min/vs/assets/*.worker-*.js) all relative to that same
// base — so nothing depends on Turbopack's worker transform (the `?worker`
// suffix is a webpack/Vite convention that does NOT apply under Next 16
// Turbopack).
//
// Run automatically via the `prebuild` npm script (and `postinstall` so a fresh
// `npm ci` in the Docker builder stage primes public/ before `next build`).
// Node-only, cross-platform (the operator develops on Windows, builds on Linux).

import { cpSync, existsSync, mkdirSync, rmSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const frontendDir = join(here, "..");

const src = join(frontendDir, "node_modules", "monaco-editor", "min", "vs");
const dest = join(frontendDir, "public", "monaco", "vs");

if (!existsSync(src)) {
  // Not fatal: in some environments (e.g. a lint-only CI without deps) the
  // package may be absent. Warn loudly but do not break the run — the build
  // gate (bundle-egress.sh) and the live offline check will catch a genuinely
  // missing asset set.
  console.warn(
    `[copy-monaco] monaco-editor not found at ${src}; skipping copy. ` +
      `Run \`npm install\` first if you need the editor assets.`,
  );
  process.exit(0);
}

// Idempotent: clear any stale copy so a Monaco version bump can't leave
// orphaned files behind, then recopy the whole vs/ tree.
rmSync(dest, { recursive: true, force: true });
mkdirSync(dirname(dest), { recursive: true });
cpSync(src, dest, { recursive: true });

// Sanity assertions — the load-bearing files must be present, otherwise the
// editor would silently fall back / fail. Fail hard here rather than ship a
// broken editor.
const required = [
  "loader.js",
  join("editor", "editor.main.js"),
  join("assets", "editor.worker-Be8ye1pW.js"),
];
const missing = required.filter((rel) => !existsSync(join(dest, rel)));
if (missing.length) {
  console.error(
    `[copy-monaco] expected Monaco files missing after copy: ${missing.join(", ")}`,
  );
  console.error(
    `[copy-monaco] the monaco-editor min/vs layout may have changed across ` +
      `versions — update this manifest and lib/monaco-setup.ts to match.`,
  );
  process.exit(1);
}

const { size } = statSync(join(dest, "loader.js"));
console.log(
  `[copy-monaco] copied monaco min/vs -> public/monaco/vs ` +
    `(loader.js ${size} bytes). Served same-origin; no CDN.`,
);
