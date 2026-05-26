import type { OryClientConfiguration } from "@ory/elements-react"
import { AccountExperienceConfigurationLocaleBehaviorEnum } from "@ory/client-fetch"

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
// `intl.customTranslations` is intentionally absent here (Plan 02 wires the
// console-written translations override). The `intl` object is structured so a
// later `customTranslations` import slots in without restructuring (AX-03).
// =============================================================================

const config: OryClientConfiguration = {
  // sdk.url is an ALTERNATIVE to the ORY_SDK_URL env var. We rely on the env var
  // (read by @ory/nextjs internally) so the internal hostname stays server-only;
  // setting it here from process.env would be equivalent, but the env path keeps
  // the value out of any bundled module graph that a client import might drag in.
  intl: {
    locale: "en",
    // customTranslations: <wired in Plan 02 — console-written translations.json>
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
