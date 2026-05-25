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

import {
  cpSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const frontendDir = join(here, "..");

const src = join(frontendDir, "node_modules", "monaco-editor", "min", "vs");
const dest = join(frontendDir, "public", "monaco", "vs");

// -----------------------------------------------------------------------------
// FE-05 / threat T-05-11 — eliminate the CDN literal at its source.
//
// @monaco-editor/loader ships a hard-coded default config whose `paths.vs`
// points at `https://cdn.jsdelivr.net/npm/monaco-editor@<ver>/min/vs`. Even
// though setupMonaco() overrides this at runtime via loader.config({ paths }),
// the DEFAULT string is a module-level literal that Next inlines into the built
// client bundle — so `cdn.jsdelivr.net` shows up in `.next` and trips the
// air-gap bundle-egress gate. We rewrite the loader's bundled default to our
// own same-origin `/monaco/vs` so the CDN host NEVER reaches the build.
//
// This runs as part of the existing postinstall/prebuild step, so it is applied
// after every `npm ci` (the literal is reintroduced by a fresh install and
// patched out again here — fully reproducible in the Docker builder stage). The
// rewrite is idempotent: a file already pointing at `/monaco/vs` is left alone.
// The runtime override in lib/monaco-setup.ts is kept too (defense in depth).
// -----------------------------------------------------------------------------
const LOCAL_VS = "/monaco/vs";
// Match the loader's default jsDelivr base for ANY monaco-editor version
// (`@x.y.z`), capturing only the host+package+path so we swap it wholesale.
const CDN_VS_RE =
  /https:\/\/cdn\.jsdelivr\.net\/npm\/monaco-editor@[^/'"]+\/min\/vs/g;

function patchLoaderDefaultCdn() {
  const loaderDir = join(frontendDir, "node_modules", "@monaco-editor", "loader");
  if (!existsSync(loaderDir)) {
    console.warn(
      `[copy-monaco] @monaco-editor/loader not found at ${loaderDir}; ` +
        `skipping CDN-default patch.`,
    );
    return;
  }

  // Rewrite every shipped loader variant a bundler could resolve (es is what
  // Next/Turbopack picks via `module`; cjs is the `main` fallback; the umd
  // builds round it out so a repo-wide grep is clean too).
  const targets = [
    join(loaderDir, "lib", "es", "config", "index.js"),
    join(loaderDir, "lib", "cjs", "config", "index.js"),
    join(loaderDir, "lib", "umd", "monaco-loader.js"),
    join(loaderDir, "lib", "umd", "monaco-loader.min.js"),
  ];

  let patched = 0;
  for (const file of targets) {
    if (!existsSync(file)) continue;
    const before = readFileSync(file, "utf8");
    if (!CDN_VS_RE.test(before)) continue; // already clean — idempotent no-op
    CDN_VS_RE.lastIndex = 0; // reset after .test()
    const after = before.replace(CDN_VS_RE, LOCAL_VS);
    if (after !== before) {
      writeFileSync(file, after);
      patched += 1;
    }
  }

  console.log(
    patched > 0
      ? `[copy-monaco] patched @monaco-editor/loader default CDN -> ${LOCAL_VS} ` +
          `(${patched} file${patched === 1 ? "" : "s"}); no jsDelivr literal ships.`
      : `[copy-monaco] @monaco-editor/loader default already local (${LOCAL_VS}); nothing to patch.`,
  );
}

// Patch the loader's default CDN base FIRST — independent of the editor asset
// copy below, and required even on a lint-only CI so the built bundle never
// inlines `cdn.jsdelivr.net`.
patchLoaderDefaultCdn();

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
//
// loader.js and editor/editor.main.js are stable, UNHASHED entrypoint names —
// assert them exactly. The editor Web Worker, however, ships with a
// content-hash in its filename (e.g. `editor.worker-Be8ye1pW.js`) that changes
// on virtually every monaco-editor version bump. Asserting the exact hash made
// a routine patch bump fail `npm ci` (this script runs as postinstall) with a
// misleading "Monaco files missing" error even though the editor works. So the
// worker is matched by a version-AGNOSTIC pattern instead (WR-04).
const requiredExact = ["loader.js", join("editor", "editor.main.js")];
const missing = requiredExact.filter((rel) => !existsSync(join(dest, rel)));

// The editor worker lives under assets/ with a hashed name: assert at least one
// `editor.worker-*.js` exists rather than pinning the exact hash.
const assetsDir = join(dest, "assets");
const hasEditorWorker =
  existsSync(assetsDir) &&
  readdirSync(assetsDir).some((f) => /^editor\.worker-.*\.js$/.test(f));
if (!hasEditorWorker) {
  missing.push(join("assets", "editor.worker-*.js"));
}

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
