# Monaco editor — local-bundle spike record (FE-04)

**Phase 5, Plan 04.** Day-1 de-risking of the phase's highest-risk item
(05-RESEARCH Pitfall 1 / Open Question A1): make the Monaco editor load
**from our own origin with zero CDN egress** under Next 16.2.6 + Turbopack, so
the air-gapped self-hosted console works and no supply-chain/SSRF surface
(threat **T-05-11**) is introduced.

## Outcome: Strategy B wins (same-origin static `vs/`)

`@monaco-editor/react` 4.7 + `@monaco-editor/loader` 1.7 default to fetching
Monaco from **jsDelivr (a CDN)**. That is unacceptable here. Two candidate
local-bundle strategies were considered:

| | Strategy A — `loader.config({ monaco })` + `?worker` ESM imports | Strategy B — same-origin static `vs/` (**CHOSEN**) |
|---|---|---|
| How | Import `monaco-editor` + `editor.worker?worker` / `json.worker?worker`, wire `self.MonacoEnvironment.getWorker`, `loader.config({ monaco })` | Copy `monaco-editor/min/vs` → `public/monaco/vs`; `loader.config({ paths: { vs: "/monaco/vs" } })` |
| Bundler dependency | **Yes** — the `?worker` suffix is a webpack/Vite convention | **None** — the AMD `loader.js` self-loads everything |
| Turbopack (Next 16 default) | `?worker` does **not** apply the same way → high risk of "getWorker is not a function" / silent worker failure | Unaffected — Turbopack never sees a worker import |
| CDN egress | none (if it works) | **none** |
| Verdict | Bundler-fragile under Turbopack (A1) | **Offline-clean, bundler-agnostic** |

**Why B is correct for monaco-editor 0.55.1:** its `min/vs` distribution ships
the classic AMD `loader.js`, `editor/editor.main.js`, and **pre-built language
workers** under `min/vs/assets/*.worker-*.js`. The bundle's internal
`MonacoEnvironment.getWorkerUrl` resolves the workers **relative to the `vs`
base path** the loader was configured with. Point that base at our same-origin
`/monaco/vs` and the editor **and** its language services (JSON validation
squiggles, formatting) load entirely first-party — no `?worker` transform, no
`monaco-editor-webpack-plugin`, no CDN.

## Implementation

- **`scripts/copy-monaco.mjs`** — does two things, both idempotent and wired as
  npm **`prebuild`**, **`predev`**, and **`postinstall`** (so they run for
  `next build`, `next dev`, and every fresh `npm ci` in the Docker builder
  stage):
  1. **Copies** `node_modules/monaco-editor/min/vs` → `frontend/public/monaco/vs`
     (asserts the load-bearing files exist). The `vs/` tree is also committed
     under `public/monaco/vs` so the editor works even without re-running the
     copy.
  2. **Eliminates the CDN literal at its source.** `@monaco-editor/loader`
     ships a module-level default config whose `paths.vs` is
     `https://cdn.jsdelivr.net/npm/monaco-editor@<ver>/min/vs`. Even with the
     runtime override below, that DEFAULT string is inlined by Next into the
     built client bundle, tripping the air-gap bundle-egress gate. The script
     rewrites the loader's bundled default (`lib/es`, `lib/cjs`, and both
     `lib/umd` variants) to the same-origin `/monaco/vs` so `cdn.jsdelivr.net`
     **never reaches the build**. The rewrite is version-agnostic
     (`monaco-editor@*`) and idempotent (a file already pointing at
     `/monaco/vs` is left alone), and because it runs at `postinstall` it is
     re-applied after every `npm ci` — verified to survive a clean
     `rm -rf node_modules && npm ci && npm run build`.
- **`lib/monaco-setup.ts`** — `setupMonaco()` calls
  `loader.config({ paths: { vs: "/monaco/vs" } })` exactly once (idempotent,
  client-only). The MonacoEditor wrapper invokes it before the first mount.
  This is now **defense in depth**: the source rewrite already removes the CDN
  default, and this guarantees the running loader points at our origin even if
  the rewrite were ever skipped.
- **`next.config.ts`** — **no change required.** Next serves `public/` at the
  origin root, so `/monaco/vs/*` is same-origin automatically; the existing
  `/backend` rewrite + `output:"standalone"` are untouched. The Dockerfile
  already `COPY`s `public/` into the standalone runtime stage.

## Offline proof (no jsDelivr request)

1. **Build gate** — `bash scripts/verify/bundle-egress.sh` forbids
   `cdn.jsdelivr.net|cdnjs.cloudflare.com|unpkg.com` (and every Ory
   host/port/SDK) in the built bundle. It passes **with no CDN exception
   clause** — because the loader's CDN default is rewritten at its source
   (above), the literal is simply absent from `.next`, so the gate stays
   maximally strict (the FE-05 invariant is enforced verbatim).
2. **Static-asset scan** — `grep -rIE 'cdn\.jsdelivr\.net|...'` over
   `public/monaco` finds nothing; the only `https://` in `loader.js` is a
   `github.com` license comment, not a runtime fetch.
3. **Loader config** — the ONLY URL Monaco is given is the bare same-origin path
   `/monaco/vs` (no scheme/host), so no external egress can be inlined.
4. **Manual network check (repeated in 05-07's offline acceptance):** open an
   editor page in `next dev`/built output with DevTools → Network; confirm
   editor renders, invalid JSON shows red squiggles (= workers loaded), and
   there is **no request to `cdn.jsdelivr.net`** — every Monaco request targets
   `localhost:3000/monaco/vs/*`.

## Keeping assets in sync on a Monaco upgrade

Bump `monaco-editor` in `package.json`, then `npm install` (the `postinstall`
recopy runs automatically). If the `min/vs` layout changes, `copy-monaco.mjs`'s
required-file manifest will fail loudly — update it (and this doc) to match.
