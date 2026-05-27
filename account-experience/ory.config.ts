import type { OryClientConfiguration } from "@ory/elements-react"
import { AccountExperienceConfigurationLocaleBehaviorEnum } from "@ory/client-fetch"
import { readTranslationsOverride } from "@/lib/overrides"

// =============================================================================
// Account Experience (AX) Ory client configuration (AX-01 / AX-05).
//
// This config drives BOTH the @ory/nextjs middleware proxy (middleware.ts) and
// the per-flow server components (app/auth/*/page.tsx). It is build-time + boot-
// time data (read at module init), NOT a live API.
//
// SDK URL (Pattern 3 / threat T-15-04): the proxy target — Kratos PUBLIC :4433 —
// is supplied via the SERVER-ONLY `ORY_SDK_URL` env var, NEVER `NEXT_PUBLIC_*`.
// @ory/nextjs's `orySdkUrl()` reads `NEXT_PUBLIC_ORY_SDK_URL` first, then the
// bare `ORY_SDK_URL`. We deliberately set ONLY the bare form in compose so the
// internal Kratos hostname (`http://ory-kratos:4433`) is read by the Next SERVER
// and never inlined into the client JS bundle (asserted by the AX bundle-egress
// gate). `ORY_PROJECT_API_TOKEN` is left UNSET (Network-only; getProjectApiKey()
// returns "" when absent — harmless for self-hosted).
//
// The six `*_ui_url` paths are AX SAME-ORIGIN paths (the browser only ever talks
// to the AX origin; the middleware proxies the Kratos API calls). They MUST match
// the rebound Kratos `selfservice.flows.*.ui_url` keys in config/kratos/kratos.yml.
//
// `intl.customTranslations` (AX-03) is read at MODULE INIT from the console-
// written `translations.json` on the mounted override volume (lib/overrides.ts,
// server-only `fs` read). Because Next re-imports this module when the AX server
// process starts, a console edit + AX broker RESTART applies the new catalog
// with NO rebuild (15-RESEARCH A3 / Pitfall 6). A missing/empty/malformed file
// falls back to Elements' built-in catalog (`undefined`).
// =============================================================================

// AX-03: load the console-written customTranslations catalog at boot. Evaluated
// once at module init; an AX restart re-reads the file.
const customTranslations = readTranslationsOverride()

const config: OryClientConfiguration = {
  // sdk.url is the PUBLIC, BROWSER-REACHABLE Account-Experience origin — NOT the
  // internal Kratos URL. Ory Elements uses THIS value, in the BROWSER, for two
  // things: (a) the in-page affordance links it renders —
  // `config.sdk.url + "/self-service/<registration|recovery|verification>/browser"`
  // (the "Sign up" / "Forgot password?" links) — and (b) the base for client-side
  // flow submission (`updateLoginFlow` et al). Both must be same-origin so the
  // middleware proxies `/self-service/*` to internal Kratos. It is DISTINCT from
  // the server-only `ORY_SDK_URL` that @ory/nextjs reads via `orySdkUrl()` for the
  // proxy upstream + server-side flow fetch. Leaving this UNSET made Elements fall
  // back to resolving the SDK URL from `ORY_SDK_URL` (the internal host), so the
  // affordance links and the flow submission pointed the browser at an unreachable
  // `http://kratos:4433/...`. Resolved server-side at module init (runtime
  // `AX_PUBLIC_URL`, default the local compose origin) and serialized to the client
  // via the `<Login config>` prop — only the PUBLIC origin reaches the bundle, the
  // internal Kratos host never does.
  sdk: {
    url: (process.env.AX_PUBLIC_URL ?? "http://localhost:3001").replace(/\/$/, ""),
  },
  intl: {
    locale: "en",
    // AX-03: the console-written catalog (read at boot). `undefined` when no
    // override file exists → Elements uses its built-in translations.
    customTranslations,
  },
  project: {
    name: "Account Experience",
    default_redirect_url: "/",
    registration_enabled: true,
    verification_enabled: true,
    recovery_enabled: true,
    login_ui_url: "/auth/login",
    registration_ui_url: "/auth/registration",
    recovery_ui_url: "/auth/recovery",
    verification_ui_url: "/auth/verification",
    settings_ui_url: "/settings",
    error_ui_url: "/auth/error",
    // Locale config (required by AccountExperienceConfiguration in client-fetch
    // 1.22.x). `en` default; respect the browser's Accept-Language so a future
    // multi-locale catalog (AX-03, Plan 02) is honored without restructuring.
    // `translations` is the console-written customTranslations catalog — empty
    // here; Plan 02 populates it via the Localization editor.
    default_locale: "en",
    enabled_locales: ["en"],
    locale_behavior:
      AccountExperienceConfigurationLocaleBehaviorEnum.RespectAcceptLanguage,
    translations: [],
  },
}

export default config
