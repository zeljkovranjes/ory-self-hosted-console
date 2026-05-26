//! Editable-key allowlist + hard sensitive denylist (BACK-06 — the security linchpin).
//!
//! The incoming config patch is UNTRUSTED. Schema validity is NOT sufficient to
//! write a key: a `dsn` or `secrets.*` value can be perfectly schema-valid yet must
//! never be written through the console. The allowlist is the authoritative security
//! boundary (BACK-06): only a CODE-DEFINED, per-section set of RFC-6901 JSON-Pointer
//! paths may survive into the merged doc, and a hard `SENSITIVE_PREFIXES` denylist
//! rejects sensitive pointers REGARDLESS of any allowlist (defense in depth).
//!
//! Two ordered gates per `(pointer, value)` (RESEARCH Pattern 6 algorithm):
//!   1. DENYLIST — reject if the pointer is under any `SENSITIVE_PREFIXES` entry
//!      (`/dsn`, `/secrets`, `/serve/admin`, `/serve/public/tls`,
//!      `/courier/smtp/connection_uri`) -> `AppError::Forbidden`. The denylist WINS
//!      even if a path was (mistakenly) added to an allowlist.
//!   2. ALLOWLIST — reject if the FULL pointer is not an exact member of the
//!      section's `allowed_paths` (default-deny, full-pointer match — guards the
//!      Pitfall 5 nested/array bypass where allowing `/courier` would otherwise let
//!      `/courier/smtp/connection_uri` slip through) -> `AppError::Forbidden`.
//!
//! Allowlists are NEVER client-supplied — they are `const` data compiled into the
//! binary. The error body is a generic `forbidden_key` (mapped from
//! `AppError::Forbidden`); we deliberately never echo the rejected pointer's value.

use crate::config_edit::yaml::{canonical_pointer, pointer_tokens};
use crate::error::AppError;
use serde_json::Value;

/// A code-defined, per-section editable-key allowlist.
///
/// `allowed_paths` is an exhaustive list of the EXACT RFC-6901 JSON-Pointers a
/// given config section may edit. Default-deny: anything not listed is rejected.
#[derive(Debug, Clone, Copy)]
pub struct SectionAllowlist {
    /// Ory service this section belongs to (`kratos`/`hydra`/`keto`/`oathkeeper`).
    pub service: &'static str,
    /// Logical section name (e.g. `session`) — used for the registry lookup.
    pub section: &'static str,
    /// The EXACT JSON-Pointers this section may edit (full-pointer match).
    pub allowed_paths: &'static [&'static str],
}

/// Hard sensitive-key denylist — rejected for ALL sections regardless of any
/// allowlist or schema validity (RESEARCH Pattern 6 + Pitfall 5).
///
/// A pointer is sensitive iff it equals one of these entries OR begins with one
/// followed by `/` (so `/secrets` blocks `/secrets/cookie/0`, but a hypothetical
/// `/secretsX` is NOT matched). Covers: the env-injected DSN, all crypto secrets
/// (Hydra `secrets.system` / Kratos `secrets.cipher` are immutable post-init —
/// editing them corrupts stored data, Pitfall 7), the admin listener, TLS private
/// keys, and the SMTP connection URI (carries the SMTP password).
pub const SENSITIVE_PREFIXES: &[&str] = &[
    "/dsn",
    "/secrets",
    "/serve/admin",
    "/serve/public/tls",
    "/courier/smtp/connection_uri",
];

/// PROOF allowlist (RESEARCH Open Question 1 — RESOLVED: Kratos `session`).
///
/// These are low-risk, schema-valid Kratos keys (verified against
/// `kratos.config.schema.json`: `session.lifespan` is a duration `string`,
/// `session.cookie.persistent` is a `boolean`, `session.cookie.same_site` is an
/// `enum [Strict, Lax, None]`). The real PAGE that edits them lands in Phase 7;
/// here we only prove the allowlist MECHANISM. The live `config/kratos/kratos.yml`
/// ships with NO `session:` block, so patching `/session/lifespan` exercises
/// Task 2's create-on-absent intermediate-object behavior.
pub const KRATOS_SESSION: SectionAllowlist = SectionAllowlist {
    service: "kratos",
    section: "session",
    allowed_paths: &[
        "/session/lifespan",
        "/session/cookie/persistent",
        "/session/cookie/same_site",
    ],
};

// ─── Phase 7 — Kratos authentication config sections (07-RESEARCH SECTION→ALLOWLIST) ───
//
// Every JSON-Pointer below is VERIFIED against the vendored v26.2.0
// `backend/config/schemas/kratos.config.schema.json` at the line numbers cited in
// 07-RESEARCH.md. All array-of-objects config (OIDC providers, courier channels,
// flow hooks) is allowlisted at the ARRAY-ROOT pointer ONLY (whole-array replace,
// Pitfall 4) — never per-index. `courier.smtp.connection_uri` is NEVER listed here
// (it stays on the hard `SENSITIVE_PREFIXES` denylist; its write path is Plan 02).

/// AUTH-01 — General / Methods page (RESEARCH Page 1, schema lines 1504–1998).
///
/// Each supported auth method's `.enabled` boolean. `b2b` (enterprise, lines
/// 1462–1502) is intentionally EXCLUDED.
pub const KRATOS_METHODS: SectionAllowlist = SectionAllowlist {
    service: "kratos",
    section: "methods",
    allowed_paths: &[
        "/selfservice/methods/password/enabled",
        "/selfservice/methods/code/enabled",
        "/selfservice/methods/oidc/enabled",
        "/selfservice/methods/totp/enabled",
        "/selfservice/methods/lookup_secret/enabled",
        "/selfservice/methods/webauthn/enabled",
        "/selfservice/methods/passkey/enabled",
        "/selfservice/methods/link/enabled",
        "/selfservice/methods/profile/enabled",
    ],
};

/// AUTH-02 — Passwordless & Passkeys page (RESEARCH Page 2, schema lines
/// 1786–1963 webauthn/passkey, 1546–1625 code).
///
/// Uses `origins` (array), NOT the deprecated singular `origin` (line 1824).
pub const KRATOS_PASSWORDLESS: SectionAllowlist = SectionAllowlist {
    service: "kratos",
    section: "passwordless",
    allowed_paths: &[
        "/selfservice/methods/passkey/config/rp/id",
        "/selfservice/methods/passkey/config/rp/display_name",
        "/selfservice/methods/passkey/config/rp/origins",
        "/selfservice/methods/webauthn/config/passwordless",
        "/selfservice/methods/webauthn/config/rp/id",
        "/selfservice/methods/webauthn/config/rp/display_name",
        "/selfservice/methods/webauthn/config/rp/origins",
        "/selfservice/methods/code/passwordless_enabled",
    ],
};

/// AUTH-03 — Two-Factor / MFA page (RESEARCH Page 3, schema lines 1752–1903
/// totp/lookup_secret/webauthn, 1235/2801 required_aal, `featureRequiredAal`
/// def 877–883).
///
/// CONTEXT CORRECTION: the `required_aal` enum is `["aal1","highest_available"]`
/// (schema line 881) — NOT `highest_aal`. The literal `highest_aal` MUST NOT
/// appear anywhere in this const.
pub const KRATOS_MFA: SectionAllowlist = SectionAllowlist {
    service: "kratos",
    section: "mfa",
    allowed_paths: &[
        "/selfservice/methods/totp/enabled",
        "/selfservice/methods/totp/config/issuer",
        "/selfservice/methods/lookup_secret/enabled",
        "/selfservice/methods/webauthn/enabled",
        "/selfservice/methods/code/mfa_enabled",
        "/selfservice/flows/login/required_aal",
        "/session/whoami/required_aal",
    ],
};

/// AUTH-06 — Sessions page (RESEARCH Page 5, schema lines 2792–2904).
///
/// The real Sessions page. The Phase-4 proof const `KRATOS_SESSION` (section
/// `session`) stays untouched and registered; this NEW const owns section
/// `sessions`. `/session/whoami/required_aal` is shared with the MFA page — the
/// canonical EDIT owner in the UI is the MFA page (RESEARCH Open Q2 / Pitfall 7);
/// both backend allowlists may list it harmlessly (the engine merges one doc).
pub const KRATOS_SESSIONS: SectionAllowlist = SectionAllowlist {
    service: "kratos",
    section: "sessions",
    allowed_paths: &[
        "/session/lifespan",
        "/session/cookie/persistent",
        "/session/cookie/same_site",
        "/session/cookie/domain",
        "/session/cookie/path",
        "/session/cookie/name",
        "/session/whoami/required_aal",
        "/session/earliest_possible_extend",
    ],
};

/// AUTH-07 — Account Recovery page (RESEARCH Page 6, schema lines 1394–1440
/// flow, 1515–1544 link method, 1546+ code method).
///
/// `recovery.use` enum is `[link,code]` (line 1431, default `code`). `ui_url`
/// is OMITTED — owned by BRAND-02/Phase-10 (RESEARCH A4).
pub const KRATOS_RECOVERY: SectionAllowlist = SectionAllowlist {
    service: "kratos",
    section: "recovery",
    allowed_paths: &[
        "/selfservice/flows/recovery/enabled",
        "/selfservice/flows/recovery/use",
        "/selfservice/flows/recovery/lifespan",
        "/selfservice/flows/recovery/notify_unknown_recipients",
        "/selfservice/methods/code/enabled",
        "/selfservice/methods/link/enabled",
    ],
};

/// AUTH-08 — Account Verification page (RESEARCH Page 7, schema lines 1346–1392).
///
/// `verification.use` enum is `[link,code]`. `ui_url` is OMITTED (BRAND-02/P10,
/// RESEARCH A4).
pub const KRATOS_VERIFICATION: SectionAllowlist = SectionAllowlist {
    service: "kratos",
    section: "verification",
    allowed_paths: &[
        "/selfservice/flows/verification/enabled",
        "/selfservice/flows/verification/use",
        "/selfservice/flows/verification/lifespan",
        "/selfservice/flows/verification/notify_unknown_recipients",
    ],
};

/// AUTH-09 (non-secret half) — Email / SMTP page (RESEARCH Page 8, schema lines
/// 2165–2233).
///
/// The non-secret SMTP keys only. `/courier/smtp/connection_uri` is DELIBERATELY
/// ABSENT — it is on the hard `SENSITIVE_PREFIXES` denylist (Pitfall 2/3) and gets
/// a dedicated write-only handler in Plan 02. Listing it here would be a no-op
/// (Gate-1 denylist wins) but the omission keeps intent explicit.
pub const KRATOS_SMTP: SectionAllowlist = SectionAllowlist {
    service: "kratos",
    section: "smtp",
    allowed_paths: &[
        "/courier/smtp/from_address",
        "/courier/smtp/from_name",
        "/courier/smtp/headers",
        "/courier/smtp/local_name",
        "/courier/smtp/client_cert_path",
        "/courier/smtp/client_key_path",
    ],
};

/// AUTH-04 — Social Sign-In / OIDC page (RESEARCH Page 4, schema lines 430–696).
///
/// ARRAY-ROOT only (Pattern 1 / Pitfall 4): the whole providers array is replaced
/// at ONE pointer; per-index pointers (`/.../providers/0/client_id`) are NEVER
/// allowlisted. `oidc.enabled` toggles the method (shared with the Methods page).
pub const KRATOS_OIDC: SectionAllowlist = SectionAllowlist {
    service: "kratos",
    section: "oidc",
    allowed_paths: &[
        "/selfservice/methods/oidc/config/providers",
        "/selfservice/methods/oidc/enabled",
    ],
};

/// AUTH-10 — SMS page (RESEARCH Page 9, schema lines 2234–2260).
///
/// ARRAY-ROOT only: the whole courier `channels` array is replaced at one pointer
/// (the single `sms`/`http` channel). Per-index pointers are never allowlisted.
pub const KRATOS_SMS: SectionAllowlist = SectionAllowlist {
    service: "kratos",
    section: "sms",
    allowed_paths: &["/courier/channels"],
};

/// AUTH-11 / HOOK-04 — Actions & Webhooks page (RESEARCH Page 10, schema lines
/// 217–355 `selfServiceWebHook`).
///
/// ARRAY-ROOT only: each `hooks` array is its own whole-array-replace pointer; no
/// per-index pointers. This ships the COMMON default attach points (login,
/// registration, recovery, verification, settings — each `before` + `after`
/// default `hooks` array). The full per-method matrix in RESEARCH Page-10 is the
/// authoritative superset; default-deny means unlisted per-method attach points
/// (e.g. `/selfservice/flows/login/after/oidc/hooks`) are simply not editable —
/// safe to expand later (RESEARCH A3).
pub const KRATOS_WEBHOOKS: SectionAllowlist = SectionAllowlist {
    service: "kratos",
    section: "webhooks",
    allowed_paths: &[
        "/selfservice/flows/login/before/hooks",
        "/selfservice/flows/login/after/hooks",
        "/selfservice/flows/registration/before/hooks",
        "/selfservice/flows/registration/after/hooks",
        "/selfservice/flows/recovery/before/hooks",
        "/selfservice/flows/recovery/after/hooks",
        "/selfservice/flows/verification/before/hooks",
        "/selfservice/flows/verification/after/hooks",
        "/selfservice/flows/settings/before/hooks",
        "/selfservice/flows/settings/after/hooks",
    ],
};

// ─── Phase 8 — Hydra (OAuth2/OIDC) server config sections (08-RESEARCH SECTION→ALLOWLIST) ───
//
// Every JSON-Pointer below is VERIFIED against the vendored v26.2.0
// `backend/config/schemas/hydra.config.schema.json` (and the resolved `ory://`
// serve sub-schema in `backend/config/schemas/ory/serve-config.json` +
// `cors-config.json` for the General-page `serve.public.*` keys — Assumption A2,
// RESOLVED: `/serve/public/{host,port,cors/enabled}` all exist). All six sections
// are SCALAR (no array-of-objects), so none uses the array merge/mask pipeline.
//
// `dsn`, `secrets.*` (covers cookie secrets at `/secrets/cookie`), `serve.admin.*`
// and `serve.public.tls` are NEVER listed here — they stay on the hard
// `SENSITIVE_PREFIXES` denylist (INFRA-05 / Pitfall 5). `oidc.pairwise.salt` IS
// listed in `HYDRA_OIDC` for engine routing but is treated WRITE-ONLY via the
// dedicated handler in `routes.rs` (mask on GET, preserve-on-blank PUT).

/// OAUTH2-03 — General / Issuer page (08-RESEARCH Page 1, schema lines 115–147
/// serve.public via the `ory://serve-config` + `ory://cors-config` refs; 480 issuer).
///
/// NO top-level `issuer` key exists — the issuer is `urls.self.issuer`.
/// `serve.admin.*` and `serve.public.tls` stay DENYLISTED (INFRA-05).
pub const HYDRA_GENERAL: SectionAllowlist = SectionAllowlist {
    service: "hydra",
    section: "general",
    allowed_paths: &[
        "/urls/self/issuer",
        "/urls/self/public",
        "/serve/public/host",
        "/serve/public/port",
        "/serve/public/cors/enabled",
    ],
};

/// OAUTH2-04 — OIDC page (08-RESEARCH Page 2, schema lines 397–470).
///
/// `supported_types` enum=[public,pairwise]. `pairwise/salt` is WRITE-ONLY: it is
/// listed here for engine ROUTING only — the dedicated `routes.rs` salt handler is
/// the actual reader/writer (mask on GET, preserve-on-blank PUT), exactly like the
/// SMTP connection_uri pattern.
pub const HYDRA_OIDC: SectionAllowlist = SectionAllowlist {
    service: "hydra",
    section: "oidc",
    allowed_paths: &[
        "/oidc/subject_identifiers/supported_types",
        "/oidc/subject_identifiers/pairwise/salt",
        "/oidc/dynamic_client_registration/enabled",
        "/oidc/dynamic_client_registration/default_scope",
    ],
};

/// OAUTH2-05 — URLs page (08-RESEARCH Page 3, schema lines 480–571).
///
/// All strings. `urls.self.issuer`/`urls.self.public` are shared with the General
/// page — both allowlists may list them harmlessly (the engine merges one doc);
/// the canonical UI editor for the issuer is the General page.
pub const HYDRA_URLS: SectionAllowlist = SectionAllowlist {
    service: "hydra",
    section: "urls",
    allowed_paths: &[
        "/urls/login",
        "/urls/consent",
        "/urls/logout",
        "/urls/error",
        "/urls/post_logout_redirect",
        "/urls/self/issuer",
        "/urls/self/public",
    ],
};

/// OAUTH2-06 — Token Lifespans page (08-RESEARCH Page 4, schema lines 648–700).
///
/// All duration strings (e.g. `"1h"`).
pub const HYDRA_TTL: SectionAllowlist = SectionAllowlist {
    service: "hydra",
    section: "ttl",
    allowed_paths: &[
        "/ttl/access_token",
        "/ttl/refresh_token",
        "/ttl/id_token",
        "/ttl/auth_code",
        "/ttl/login_consent_request",
    ],
};

/// OAUTH2-07 — Token Strategies & PKCE page (08-RESEARCH Page 5, schema lines
/// 631–656 strategies, 817–828 pkce, 878–889 grant.jwt).
///
/// `access_token` enum=[opaque,jwt]; `scope` enum=[exact,wildcard];
/// `jwt/scope_claim` enum=[list,string,both]. Enum-value validity is the schema
/// validator's job (live gate); the allowlist only gates the POINTERS.
pub const HYDRA_STRATEGIES: SectionAllowlist = SectionAllowlist {
    service: "hydra",
    section: "strategies",
    allowed_paths: &[
        "/strategies/access_token",
        "/strategies/scope",
        "/strategies/jwt/scope_claim",
        "/oauth2/pkce/enforced",
        "/oauth2/pkce/enforced_for_public_clients",
        "/oauth2/grant/jwt/jti_optional",
        "/oauth2/grant/jwt/iat_optional",
        "/oauth2/grant/jwt/max_ttl",
    ],
};

/// OAUTH2-08 — Cookies page (08-RESEARCH Page 6, schema lines 151–207).
///
/// `same_site_mode` enum=[Strict,Lax,None]. Cookie SECRETS live under
/// `/secrets/cookie` (denylisted), NOT here — only behavior keys are editable.
pub const HYDRA_COOKIES: SectionAllowlist = SectionAllowlist {
    service: "hydra",
    section: "cookies",
    allowed_paths: &[
        "/serve/cookies/same_site_mode",
        "/serve/cookies/same_site_legacy_workaround",
        "/serve/cookies/domain",
        "/serve/cookies/secure",
        "/serve/cookies/names/login_csrf",
        "/serve/cookies/names/consent_csrf",
        "/serve/cookies/names/device_csrf",
        "/serve/cookies/names/session",
    ],
};

// ─── Phase 10 — Kratos Branding config sections (10-RESEARCH BRAND-01/02) ───
//
// Two new Kratos config sections, both VERIFIED against the vendored v26.2.0
// `kratos.config.schema.json`. Both restart Kratos ONLY through the reused
// Phase-4 engine. Neither lists a sensitive pointer (templates + UI URLs are
// non-secret); the `SENSITIVE_PREFIXES` denylist (Gate-1) still applies as
// defense-in-depth.

/// BRAND-02 — UI URLs & Redirects page (10-RESEARCH Pattern 5 / Pitfall 1).
///
/// The self-service flow `ui_url` keys plus `allowed_return_urls` (array-root)
/// and `default_browser_return_url`. The Phase-7 `KRATOS_RECOVERY`/
/// `KRATOS_VERIFICATION` allowlists deliberately OMITted their `ui_url` keys,
/// reserving them for THIS section (see their "ui_url is OMITTED (BRAND-02/
/// Phase-10)" comments).
///
/// PITFALL 1 (the logout trap): `/selfservice/flows/logout/ui_url` is
/// DELIBERATELY ABSENT — the v26.2.0 schema gives `logout` NO `ui_url` (only
/// `logout.after.default_browser_return_url`) and is `additionalProperties:false`,
/// so including `logout/ui_url` would fail full-config validation and BRICK every
/// save. The `ui_urls_omits_logout_ui_url` test asserts its absence. If a logout
/// redirect is ever wanted, add `/selfservice/flows/logout/after/default_browser_return_url`
/// instead — NEVER `logout/ui_url`.
pub const KRATOS_UI_URLS: SectionAllowlist = SectionAllowlist {
    service: "kratos",
    section: "ui-urls",
    allowed_paths: &[
        "/selfservice/flows/login/ui_url",
        "/selfservice/flows/registration/ui_url",
        "/selfservice/flows/recovery/ui_url",
        "/selfservice/flows/verification/ui_url",
        "/selfservice/flows/settings/ui_url",
        "/selfservice/flows/error/ui_url",
        "/selfservice/default_browser_return_url",
        // Array-root (whole-array replace) — NOT an array-section (no per-item
        // secret/Jsonnet); it carries plain string URLs, so it flows through the
        // scalar engine unchanged. Per-index pointers are never allowlisted.
        "/selfservice/allowed_return_urls",
        // DO NOT add `/selfservice/flows/logout/ui_url` (Pitfall 1).
    ],
};

/// BRAND-01 — Email Templates page (10-RESEARCH Pattern 4 / Pitfall 2).
///
/// The inline `courier.templates.*` body/subject keys. Body values are URI
/// strings (`format:uri`, `pattern ^(http|https|file|base64)://`), so the
/// editor's raw text is wrapped as `base64://<b64>` by the per-section template
/// codec in `routes.rs` (dispatched by SECTION NAME "email-templates") before it
/// lands in the doc, and decoded back to source on GET.
///
/// Scope (10-RESEARCH Open Q1): the `valid/email` html+plaintext bodies + subject
/// for the six courier template types. The `invalid/email` + `valid/sms` variants
/// are a safe later expansion under default-deny (unlisted = not editable). NO
/// sensitive pointer is listed (`/courier/smtp/*` stays denylisted / out of scope).
pub const KRATOS_EMAIL_TEMPLATES: SectionAllowlist = SectionAllowlist {
    service: "kratos",
    section: "email-templates",
    allowed_paths: &[
        "/courier/templates/recovery/valid/email/body/html",
        "/courier/templates/recovery/valid/email/body/plaintext",
        "/courier/templates/recovery/valid/email/subject",
        "/courier/templates/recovery_code/valid/email/body/html",
        "/courier/templates/recovery_code/valid/email/body/plaintext",
        "/courier/templates/recovery_code/valid/email/subject",
        "/courier/templates/verification/valid/email/body/html",
        "/courier/templates/verification/valid/email/body/plaintext",
        "/courier/templates/verification/valid/email/subject",
        "/courier/templates/verification_code/valid/email/body/html",
        "/courier/templates/verification_code/valid/email/body/plaintext",
        "/courier/templates/verification_code/valid/email/subject",
        "/courier/templates/registration_code/valid/email/body/html",
        "/courier/templates/registration_code/valid/email/body/plaintext",
        "/courier/templates/registration_code/valid/email/subject",
        "/courier/templates/login_code/valid/email/body/html",
        "/courier/templates/login_code/valid/email/body/plaintext",
        "/courier/templates/login_code/valid/email/subject",
    ],
};

/// Code-defined registry of every shipped section allowlist. The lookup is the
/// ONLY way to obtain an allowlist — it is never assembled from client input.
///
/// Phase-4 proof (`KRATOS_SESSION`) + the 10 Phase-7 Kratos auth sections (7
/// scalar + 3 array-root) + the 6 Phase-8 Hydra config sections (all scalar) +
/// the 2 Phase-10 Kratos branding sections (`ui-urls` scalar/array-root +
/// `email-templates` base64-codec).
const REGISTRY: &[&SectionAllowlist] = &[
    &KRATOS_SESSION,
    &KRATOS_METHODS,
    &KRATOS_PASSWORDLESS,
    &KRATOS_MFA,
    &KRATOS_SESSIONS,
    &KRATOS_RECOVERY,
    &KRATOS_VERIFICATION,
    &KRATOS_SMTP,
    &KRATOS_OIDC,
    &KRATOS_SMS,
    &KRATOS_WEBHOOKS,
    &HYDRA_GENERAL,
    &HYDRA_OIDC,
    &HYDRA_URLS,
    &HYDRA_TTL,
    &HYDRA_STRATEGIES,
    &HYDRA_COOKIES,
    &KRATOS_UI_URLS,
    &KRATOS_EMAIL_TEMPLATES,
];

/// Look up the allowlist for a `(service, section)` pair.
///
/// Returns `AppError::NotFound` for an unknown section so an unrecognised page
/// cannot fall through to an empty/permissive default.
pub fn lookup(service: &str, section: &str) -> Result<&'static SectionAllowlist, AppError> {
    REGISTRY
        .iter()
        .copied()
        .find(|a| a.service == service && a.section == section)
        .ok_or(AppError::NotFound)
}

/// True if `canonical` is sensitive: it equals a `SENSITIVE_PREFIXES` entry or
/// sits directly under one (segment-boundary match, so `/secrets` blocks
/// `/secrets/cookie/0` but never a sibling like `/secretsX`).
///
/// CR-01: the argument MUST be the CANONICAL pointer form produced by
/// `canonical_pointer(&pointer_tokens(raw))` — the SAME normalisation the
/// writer ([`super::yaml::apply_patch`]) addresses the doc with. Because the
/// `SENSITIVE_PREFIXES` entries themselves contain no `~`/`/`-escaped segment,
/// they are already canonical, so a denylist node reached via ANY escape
/// spelling (e.g. `/secrets/cipher~0/0`) canonicalises here and is still caught
/// — the gate no longer depends on the implicit "a literal `/` cannot be encoded
/// past the split" invariant.
pub(crate) fn is_sensitive(canonical: &str) -> bool {
    SENSITIVE_PREFIXES.iter().any(|prefix| {
        canonical == *prefix
            || canonical
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

/// Normalise a raw client pointer to its canonical RFC-6901 spelling: decode the
/// escapes ONCE and re-encode. `canonicalize("/a/b~1c")` and
/// `canonicalize("/a/b~1c")` agree; an over/odd-escaped spelling that decodes to
/// the same tokens yields the same canonical string the writer will address.
///
/// This is the single normal form the gate matches on so the allowlist and the
/// writer can never disagree about the target (CR-01).
fn canonicalize(pointer: &str) -> String {
    canonical_pointer(&pointer_tokens(pointer))
}

/// Filter an incoming patch against a section allowlist + the sensitive denylist.
///
/// `patch` is a list of `(json_pointer, value)` edits. Applies the two ordered
/// gates per entry (denylist first, then full-pointer allowlist membership). On
/// the FIRST violation returns `AppError::Forbidden` (rendered to the client as the
/// generic `forbidden_key` code — the rejected value is never echoed). On success
/// returns the patch unchanged (cloned), ready for `yaml::apply_patch`.
///
/// The `allowlist` argument is always a `&'static SectionAllowlist` obtained from
/// [`lookup`] — the signature CANNOT accept a client-supplied path set, so the
/// allowlist's server-side authority is compile-enforced. Schema validity is checked
/// LATER (by the caller) and is NOT a substitute for this gate (BACK-06).
pub fn filter(
    allowlist: &SectionAllowlist,
    patch: &[(String, Value)],
) -> Result<Vec<(String, Value)>, AppError> {
    let mut accepted = Vec::with_capacity(patch.len());
    for (pointer, value) in patch {
        // CR-01: canonicalise the incoming pointer ONCE (decode escapes, then
        // re-encode) so BOTH gates AND the downstream writer address the exact
        // same node. The gate's verdict can no longer disagree with the location
        // `yaml::apply_patch` will write.
        let canonical = canonicalize(pointer);

        // Gate 1: hard sensitive denylist — wins over any allowlist. Run on the
        // canonical form so a sensitive node reached via any escape spelling is
        // still denied.
        if is_sensitive(&canonical) {
            return Err(AppError::Forbidden);
        }
        // Gate 2: default-deny full-pointer allowlist membership. Compare the
        // canonical incoming pointer against the canonical spelling of each
        // allowed path so an allowlisted key whose name needs escaping matches
        // regardless of the (equivalent) escape spelling the client sent.
        let allowed = allowlist
            .allowed_paths
            .iter()
            .any(|allowed| canonicalize(allowed) == canonical);
        if !allowed {
            return Err(AppError::Forbidden);
        }
        // Forward the CANONICAL pointer (not the raw client spelling) so the
        // writer addresses exactly the node the gate just authorised.
        accepted.push((canonical, value.clone()));
    }
    Ok(accepted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejects_out_of_scope() {
        // A pointer NOT in the section allowlist is rejected (default-deny)...
        let patch = vec![("/identity/default_schema_id".to_string(), json!("evil"))];
        let err = filter(&KRATOS_SESSION, &patch).expect_err("out-of-scope must be Forbidden");
        assert!(matches!(err, AppError::Forbidden));

        // ...while the proof-target allowlisted path is accepted.
        let ok = vec![("/session/lifespan".to_string(), json!("24h"))];
        let accepted = filter(&KRATOS_SESSION, &ok).expect("allowlisted path must pass");
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].0, "/session/lifespan");
    }

    #[test]
    fn rejects_sensitive_dsn_secrets() {
        // Each of these is sensitive and must be rejected even though this
        // throwaway allowlist (wrongly) lists every one of them — the denylist
        // wins over the allowlist (Gate 1 runs before Gate 2).
        let permissive = SectionAllowlist {
            service: "kratos",
            section: "evil",
            allowed_paths: &[
                "/dsn",
                "/secrets/cookie/0",
                "/serve/admin/base_url",
                "/courier/smtp/connection_uri",
                "/serve/public/tls/key/path",
            ],
        };
        for p in [
            "/dsn",
            "/secrets/cookie/0",
            "/serve/admin/base_url",
            "/courier/smtp/connection_uri",
            "/serve/public/tls/key/path",
        ] {
            let patch = vec![(p.to_string(), json!("x"))];
            assert!(
                matches!(filter(&permissive, &patch), Err(AppError::Forbidden)),
                "{p} must be denied by the sensitive denylist"
            );
        }
    }

    #[test]
    fn rejects_sensitive_even_when_allowlisted() {
        // Cleaner form of the denylist-wins assertion: a sensitive pointer that is
        // ALSO present in allowed_paths is still rejected (Gate 1 runs first).
        let permissive = SectionAllowlist {
            service: "kratos",
            section: "evil",
            allowed_paths: &["/secrets/cipher/0"],
        };
        let patch = vec![("/secrets/cipher/0".to_string(), json!("newsecret"))];
        assert!(matches!(
            filter(&permissive, &patch),
            Err(AppError::Forbidden)
        ));
    }

    #[test]
    fn allowlist_is_server_side() {
        // The proof allowlist is a compile-time `const` value (not assembled from
        // any client input). Referencing it in const context proves it.
        const _ASSERT_CONST: &SectionAllowlist = &KRATOS_SESSION;
        assert_eq!(KRATOS_SESSION.service, "kratos");
        assert_eq!(KRATOS_SESSION.section, "session");
        // `filter` accepts only a &SectionAllowlist (a server-side const), never a
        // client-supplied path slice — enforced by the signature at compile time.
    }

    #[test]
    fn pitfall5_nested_bypass_blocked() {
        // Allowing `/courier` must NOT permit `/courier/smtp/connection_uri`: the
        // SMTP URI is on the hard denylist AND would fail the full-pointer match.
        let courier = SectionAllowlist {
            service: "kratos",
            section: "courier",
            allowed_paths: &["/courier"],
        };
        let patch = vec![(
            "/courier/smtp/connection_uri".to_string(),
            json!("smtps://user:pass@smtp:465"),
        )];
        assert!(matches!(filter(&courier, &patch), Err(AppError::Forbidden)));

        // An array-index pointer not in the allowlist is rejected (full-match).
        let patch2 = vec![("/identity/schemas/0/url".to_string(), json!("file:///x"))];
        assert!(matches!(
            filter(&KRATOS_SESSION, &patch2),
            Err(AppError::Forbidden)
        ));
    }

    #[test]
    fn lookup_unknown_section_is_not_found() {
        assert!(matches!(lookup("kratos", "nope"), Err(AppError::NotFound)));
        assert!(matches!(lookup("hydra", "session"), Err(AppError::NotFound)));
        let found = lookup("kratos", "session").expect("kratos/session is registered");
        assert_eq!(found.allowed_paths.len(), 3);
    }

    #[test]
    fn escaped_pointer_gate_agrees_with_writer_target() {
        // CR-01: an allowlist whose key literally contains `~` and `/` must be
        // matched by the gate under ANY equivalent escape spelling, and the
        // location the gate authorises must be EXACTLY where apply_patch writes.
        use crate::config_edit::yaml;
        use serde_json::json;

        // Allowed key is `same~site` (contains `~`) nested under a key `a/b`
        // (contains `/`). Canonical spelling: `/a~1b/same~0site`.
        let al = SectionAllowlist {
            service: "kratos",
            section: "escaped",
            allowed_paths: &["/a~1b/same~0site"],
        };

        // The client sends the SAME canonical spelling -> accepted, and the
        // forwarded (canonical) pointer addresses the literal-keyed node.
        let patch = vec![("/a~1b/same~0site".to_string(), json!("Lax"))];
        let accepted = filter(&al, &patch).expect("canonical escaped pointer is allowlisted");
        assert_eq!(accepted.len(), 1);
        let mut doc = json!({});
        yaml::apply_patch(&mut doc, &accepted).expect("apply the accepted patch");
        // The decoded tokens are ["a/b", "same~site"]; serde_json::pointer
        // re-decodes the canonical pointer to the SAME tokens, so this resolves.
        assert_eq!(
            doc.pointer("/a~1b/same~0site"),
            Some(&json!("Lax")),
            "the gate-authorised canonical pointer addresses the literal-keyed node"
        );
        // Verify the actual object key is the DECODED literal name.
        assert_eq!(doc["a/b"]["same~site"], json!("Lax"));

        // A pointer that decodes to DIFFERENT tokens than the allowlist key is
        // rejected (no raw-string coincidence can sneak past the canonical match).
        let evil = vec![("/a~1b/same~1site".to_string(), json!("x"))]; // `same/site` != `same~site`
        assert!(matches!(filter(&al, &evil), Err(AppError::Forbidden)));
    }

    #[test]
    fn sensitive_via_escape_spelling_still_denied() {
        // CR-01: a sensitive node addressed with an escaped spelling that decodes
        // back onto a denylist prefix is still caught by the canonical denylist.
        // `/secrets~1x` decodes to the single token `secrets/x` (NOT under
        // `/secrets`), so it must NOT be falsely blocked...
        let permissive = SectionAllowlist {
            service: "kratos",
            section: "evil",
            allowed_paths: &["/secrets~1x"],
        };
        let patch = vec![("/secrets~1x".to_string(), json!("ok"))];
        assert!(
            filter(&permissive, &patch).is_ok(),
            "/secrets~1x is the single key `secrets/x`, not under /secrets"
        );

        // ...while `/secrets/cipher~00` (an over-escaped child of /secrets)
        // canonicalises under `/secrets` and is denied regardless of allowlisting.
        let denied = SectionAllowlist {
            service: "kratos",
            section: "evil2",
            allowed_paths: &["/secrets/cipher~00"],
        };
        let patch2 = vec![("/secrets/cipher~00".to_string(), json!("x"))];
        assert!(
            matches!(filter(&denied, &patch2), Err(AppError::Forbidden)),
            "an escaped child of /secrets must still be denied"
        );
    }

    #[test]
    fn sibling_of_sensitive_prefix_not_falsely_blocked() {
        // `/secretsX` is NOT under `/secrets` (segment-boundary match). If it were
        // allowlisted it would pass the denylist (it still must be allowlisted).
        let al = SectionAllowlist {
            service: "kratos",
            section: "x",
            allowed_paths: &["/secretsX"],
        };
        let patch = vec![("/secretsX".to_string(), json!("ok"))];
        assert!(filter(&al, &patch).is_ok(), "/secretsX is not under /secrets");
    }

    // ─── Phase 7 — per-section allowlist behaviors (07-01 Task 3) ───

    /// Every one of the 10 Phase-7 Kratos auth sections resolves via `lookup`.
    #[test]
    fn all_ten_kratos_auth_sections_resolve() {
        for section in [
            "methods",
            "passwordless",
            "mfa",
            "sessions",
            "recovery",
            "verification",
            "smtp",
            "oidc",
            "sms",
            "webhooks",
        ] {
            assert!(
                lookup("kratos", section).is_ok(),
                "section `{section}` must resolve via the registry"
            );
        }
        // The Phase-4 proof const stays registered alongside the new sections.
        assert!(lookup("kratos", "session").is_ok());
    }

    /// Each section accepts a representative allowlisted pointer and rejects an
    /// out-of-scope pointer (default-deny, full-pointer match).
    #[test]
    fn each_section_accepts_allowlisted_rejects_out_of_scope() {
        // (section const, an allowlisted pointer for that section)
        let cases: &[(&SectionAllowlist, &str)] = &[
            (&KRATOS_METHODS, "/selfservice/methods/password/enabled"),
            (&KRATOS_PASSWORDLESS, "/selfservice/methods/passkey/config/rp/id"),
            (&KRATOS_MFA, "/selfservice/methods/totp/enabled"),
            (&KRATOS_SESSIONS, "/session/lifespan"),
            (&KRATOS_RECOVERY, "/selfservice/flows/recovery/enabled"),
            (&KRATOS_VERIFICATION, "/selfservice/flows/verification/enabled"),
            (&KRATOS_SMTP, "/courier/smtp/from_address"),
            (&KRATOS_OIDC, "/selfservice/methods/oidc/config/providers"),
            (&KRATOS_SMS, "/courier/channels"),
            (&KRATOS_WEBHOOKS, "/selfservice/flows/login/after/hooks"),
        ];
        for (al, allowed) in cases {
            let ok = vec![(allowed.to_string(), json!(true))];
            assert!(
                filter(al, &ok).is_ok(),
                "section `{}`: `{allowed}` must be accepted",
                al.section
            );
            // A pointer no section owns is rejected for every section.
            let oos = vec![("/identity/default_schema_id".to_string(), json!("evil"))];
            assert!(
                matches!(filter(al, &oos), Err(AppError::Forbidden)),
                "section `{}`: out-of-scope pointer must be Forbidden",
                al.section
            );
        }
    }

    /// `/courier/smtp/connection_uri` is Forbidden through the `smtp` section
    /// (Gate-1 denylist wins) AND through every other Phase-7 section — it is on
    /// the hard `SENSITIVE_PREFIXES` denylist and never an allowlist member.
    #[test]
    fn connection_uri_denied_via_smtp_and_every_section() {
        let sections: &[&SectionAllowlist] = &[
            &KRATOS_METHODS,
            &KRATOS_PASSWORDLESS,
            &KRATOS_MFA,
            &KRATOS_SESSIONS,
            &KRATOS_RECOVERY,
            &KRATOS_VERIFICATION,
            &KRATOS_SMTP,
            &KRATOS_OIDC,
            &KRATOS_SMS,
            &KRATOS_WEBHOOKS,
        ];
        for al in sections {
            let patch = vec![(
                "/courier/smtp/connection_uri".to_string(),
                json!("smtps://user:pass@smtp:465"),
            )];
            assert!(
                matches!(filter(al, &patch), Err(AppError::Forbidden)),
                "section `{}`: connection_uri must stay denied",
                al.section
            );
        }
        // And it is absent from every Phase-7 allowlist's allowed_paths.
        for al in sections {
            assert!(
                !al.allowed_paths
                    .contains(&"/courier/smtp/connection_uri"),
                "section `{}` must not list connection_uri",
                al.section
            );
        }
    }

    /// Sensitive pointers (`/dsn`, `/secrets/*`, `/serve/admin/*`) are Forbidden
    /// for every Phase-7 section regardless of allowlist membership.
    #[test]
    fn sensitive_pointers_denied_for_every_section() {
        let sections: &[&SectionAllowlist] = &[
            &KRATOS_METHODS,
            &KRATOS_PASSWORDLESS,
            &KRATOS_MFA,
            &KRATOS_SESSIONS,
            &KRATOS_RECOVERY,
            &KRATOS_VERIFICATION,
            &KRATOS_SMTP,
            &KRATOS_OIDC,
            &KRATOS_SMS,
            &KRATOS_WEBHOOKS,
        ];
        for al in sections {
            for p in ["/dsn", "/secrets/cipher/0", "/serve/admin/base_url"] {
                let patch = vec![(p.to_string(), json!("x"))];
                assert!(
                    matches!(filter(al, &patch), Err(AppError::Forbidden)),
                    "section `{}`: `{p}` must be denied",
                    al.section
                );
            }
        }
    }

    /// AAL: both enum values pass the allowlist layer; the literal `highest_aal`
    /// (the CONTEXT typo) appears NOWHERE in the MFA section pointers. Enum-value
    /// validity is the schema validator's job (Plan 05) — here we only prove the
    /// `required_aal` pointer exists and accepts the canonical values.
    #[test]
    fn mfa_required_aal_pointer_and_no_highest_aal_literal() {
        for value in ["aal1", "highest_available"] {
            let patch = vec![(
                "/selfservice/flows/login/required_aal".to_string(),
                json!(value),
            )];
            assert!(
                filter(&KRATOS_MFA, &patch).is_ok(),
                "required_aal must accept `{value}` at the allowlist layer"
            );
        }
        assert!(
            KRATOS_MFA
                .allowed_paths
                .iter()
                .all(|p| !p.contains("highest_aal")),
            "no MFA pointer may contain the literal `highest_aal`"
        );
        // The pointer itself is present.
        assert!(KRATOS_MFA
            .allowed_paths
            .contains(&"/selfservice/flows/login/required_aal"));
    }

    /// Array sections allow ONLY the array-root pointer: a per-index pointer is
    /// Forbidden while the root is accepted (whole-array replace, Pitfall 4).
    #[test]
    fn array_sections_root_only_no_per_index() {
        // OIDC: root Ok, per-index Forbidden.
        let root = vec![(
            "/selfservice/methods/oidc/config/providers".to_string(),
            json!([]),
        )];
        assert!(filter(&KRATOS_OIDC, &root).is_ok());
        let per_index = vec![(
            "/selfservice/methods/oidc/config/providers/0/client_id".to_string(),
            json!("leaked"),
        )];
        assert!(matches!(
            filter(&KRATOS_OIDC, &per_index),
            Err(AppError::Forbidden)
        ));
        assert!(!KRATOS_OIDC
            .allowed_paths
            .iter()
            .any(|p| p.contains("providers/0")));

        // SMS: exactly the one array-root pointer.
        assert_eq!(KRATOS_SMS.allowed_paths, &["/courier/channels"]);
        let sms_index = vec![("/courier/channels/0/id".to_string(), json!("sms"))];
        assert!(matches!(
            filter(&KRATOS_SMS, &sms_index),
            Err(AppError::Forbidden)
        ));

        // WEBHOOKS: every pointer is a `hooks` array-root under /selfservice/flows/.
        assert!(KRATOS_WEBHOOKS.allowed_paths.iter().all(|p| {
            p.ends_with("/hooks") && p.starts_with("/selfservice/flows/")
        }));
        let hook_index = vec![(
            "/selfservice/flows/login/after/hooks/0/config/url".to_string(),
            json!("https://evil"),
        )];
        assert!(matches!(
            filter(&KRATOS_WEBHOOKS, &hook_index),
            Err(AppError::Forbidden)
        ));
    }

    // ─── Phase 8 — Hydra config-section allowlist behaviors (08-03 Task 1) ───

    /// The six Phase-8 Hydra config sections each resolve via `lookup`, and a
    /// non-existent hydra section is NotFound (no permissive fall-through).
    #[test]
    fn all_six_hydra_sections_resolve() {
        for section in ["general", "oidc", "urls", "ttl", "strategies", "cookies"] {
            assert!(
                lookup("hydra", section).is_ok(),
                "hydra section `{section}` must resolve via the registry"
            );
        }
        assert!(matches!(lookup("hydra", "nope"), Err(AppError::NotFound)));
        // `lookup("hydra","ttl")` resolves (explicit per the plan behavior).
        assert!(lookup("hydra", "ttl").is_ok());
    }

    /// Every hydra section accepts each of its allowlisted pointers and rejects an
    /// out-of-scope pointer (default-deny, full-pointer match).
    #[test]
    fn each_hydra_section_accepts_all_allowlisted_rejects_out_of_scope() {
        let sections: &[&SectionAllowlist] = &[
            &HYDRA_GENERAL,
            &HYDRA_OIDC,
            &HYDRA_URLS,
            &HYDRA_TTL,
            &HYDRA_STRATEGIES,
            &HYDRA_COOKIES,
        ];
        for al in sections {
            // EVERY allowlisted pointer is accepted.
            for ptr in al.allowed_paths {
                let ok = vec![((*ptr).to_string(), json!("v"))];
                assert!(
                    filter(al, &ok).is_ok(),
                    "hydra/{}: `{ptr}` must be accepted",
                    al.section
                );
            }
            // An out-of-scope pointer no hydra section owns is rejected.
            let oos = vec![("/identity/default_schema_id".to_string(), json!("evil"))];
            assert!(
                matches!(filter(al, &oos), Err(AppError::Forbidden)),
                "hydra/{}: out-of-scope pointer must be Forbidden",
                al.section
            );
        }
    }

    /// Every sensitive pointer is rejected for EVERY hydra section regardless of
    /// allowlist membership (the denylist wins). Covers `/dsn`, `/secrets/cookie/0`,
    /// `/serve/admin/host`, `/serve/public/tls/key/path`.
    #[test]
    fn sensitive_pointers_denied_for_every_hydra_section() {
        let sections: &[&SectionAllowlist] = &[
            &HYDRA_GENERAL,
            &HYDRA_OIDC,
            &HYDRA_URLS,
            &HYDRA_TTL,
            &HYDRA_STRATEGIES,
            &HYDRA_COOKIES,
        ];
        let sensitive = [
            "/dsn",
            "/secrets/cookie/0",
            "/secrets/system/0",
            "/serve/admin/host",
            "/serve/public/tls/key/path",
        ];
        for al in sections {
            for p in sensitive {
                let patch = vec![(p.to_string(), json!("x"))];
                assert!(
                    matches!(filter(al, &patch), Err(AppError::Forbidden)),
                    "hydra/{}: `{p}` must be denied by the sensitive denylist",
                    al.section
                );
            }
            // No hydra allowlist lists a sensitive pointer.
            for sp in SENSITIVE_PREFIXES {
                assert!(
                    !al.allowed_paths.iter().any(|p| p.starts_with(sp)),
                    "hydra/{} must not list a sensitive pointer ({sp})",
                    al.section
                );
            }
        }
    }

    /// The General page exposes ONLY the schema-valid `serve.public` sub-keys
    /// (A2: host/port/cors.enabled exist) and never the admin listener or TLS.
    #[test]
    fn hydra_general_serve_public_only_no_admin_no_tls() {
        assert!(HYDRA_GENERAL.allowed_paths.contains(&"/serve/public/host"));
        assert!(HYDRA_GENERAL.allowed_paths.contains(&"/serve/public/port"));
        assert!(HYDRA_GENERAL
            .allowed_paths
            .contains(&"/serve/public/cors/enabled"));
        assert!(HYDRA_GENERAL.allowed_paths.contains(&"/urls/self/issuer"));
        // Never the admin listener nor the public TLS private key.
        assert!(HYDRA_GENERAL
            .allowed_paths
            .iter()
            .all(|p| !p.starts_with("/serve/admin")));
        assert!(HYDRA_GENERAL
            .allowed_paths
            .iter()
            .all(|p| !p.starts_with("/serve/public/tls")));
    }

    /// The OIDC section lists `pairwise/salt` for engine routing (the dedicated
    /// write-only handler is the real reader/writer), and the cookies section
    /// never lists a cookie secret (those live under the denylisted `/secrets`).
    #[test]
    fn hydra_oidc_routes_salt_cookies_have_no_secret() {
        assert!(HYDRA_OIDC
            .allowed_paths
            .contains(&"/oidc/subject_identifiers/pairwise/salt"));
        // The cookies section edits only behavior keys, never `/secrets/cookie`.
        assert!(HYDRA_COOKIES
            .allowed_paths
            .iter()
            .all(|p| !p.contains("secret") && !p.starts_with("/secrets")));
    }

    // ─── Phase 10 — Kratos branding allowlist behaviors (10-02 Task 1) ───

    /// brand_allowlist: both new sections resolve via `lookup` and an unknown
    /// kratos branding section is NotFound (no permissive fall-through).
    #[test]
    fn brand_allowlist_sections_resolve() {
        assert!(lookup("kratos", "ui-urls").is_ok(), "ui-urls must resolve");
        assert!(
            lookup("kratos", "email-templates").is_ok(),
            "email-templates must resolve"
        );
        assert!(matches!(lookup("kratos", "branding-nope"), Err(AppError::NotFound)));
    }

    /// ui_urls: KRATOS_UI_URLS accepts each of its 8 pointers and rejects an
    /// out-of-scope pointer (default-deny, full-pointer match).
    #[test]
    fn ui_urls_allowlist_accepts_listed_rejects_out_of_scope() {
        for ptr in KRATOS_UI_URLS.allowed_paths {
            let ok = vec![((*ptr).to_string(), json!("https://ui.example/x"))];
            assert!(
                filter(&KRATOS_UI_URLS, &ok).is_ok(),
                "ui-urls: `{ptr}` must be accepted"
            );
        }
        // An out-of-scope selfservice pointer no section owns is rejected.
        let oos = vec![(
            "/selfservice/flows/login/lifespan".to_string(),
            json!("1h"),
        )];
        assert!(matches!(
            filter(&KRATOS_UI_URLS, &oos),
            Err(AppError::Forbidden)
        ));
        // The array-root is allowed; a per-index pointer is NOT (full-match).
        let root = vec![(
            "/selfservice/allowed_return_urls".to_string(),
            json!(["https://a.example", "https://b.example"]),
        )];
        assert!(filter(&KRATOS_UI_URLS, &root).is_ok());
        let per_index = vec![(
            "/selfservice/allowed_return_urls/0".to_string(),
            json!("https://evil.example"),
        )];
        assert!(matches!(
            filter(&KRATOS_UI_URLS, &per_index),
            Err(AppError::Forbidden)
        ));
    }

    /// ui_urls_omits_logout: `/selfservice/flows/logout/ui_url` is NOT a member
    /// of KRATOS_UI_URLS.allowed_paths (Pitfall 1 — including it would brick every
    /// save) AND it is rejected through the section filter. This is the explicit
    /// absence assertion the plan requires.
    #[test]
    fn ui_urls_omits_logout_ui_url() {
        assert!(
            !KRATOS_UI_URLS
                .allowed_paths
                .contains(&"/selfservice/flows/logout/ui_url"),
            "logout/ui_url must NEVER be allowlisted (schema additionalProperties:false bricks the save)"
        );
        // And it is rejected if a client tries to send it through this section.
        let patch = vec![(
            "/selfservice/flows/logout/ui_url".to_string(),
            json!("https://ui.example/logout"),
        )];
        assert!(matches!(
            filter(&KRATOS_UI_URLS, &patch),
            Err(AppError::Forbidden)
        ));
        // No allowlisted UI-URL pointer mentions `logout` at all.
        assert!(
            KRATOS_UI_URLS.allowed_paths.iter().all(|p| !p.contains("logout")),
            "no UI-URL pointer may reference the logout flow"
        );
    }

    /// email_templates: KRATOS_EMAIL_TEMPLATES accepts each courier-template
    /// body/subject pointer and rejects an out-of-scope courier pointer.
    #[test]
    fn email_templates_allowlist_accepts_listed_rejects_out_of_scope() {
        for ptr in KRATOS_EMAIL_TEMPLATES.allowed_paths {
            let ok = vec![((*ptr).to_string(), json!("base64://aGVsbG8="))];
            assert!(
                filter(&KRATOS_EMAIL_TEMPLATES, &ok).is_ok(),
                "email-templates: `{ptr}` must be accepted"
            );
        }
        // An out-of-scope courier pointer (e.g. a non-allowlisted template type or
        // the override path) is rejected.
        let oos = vec![(
            "/courier/template_override_path".to_string(),
            json!("/some/dir"),
        )];
        assert!(matches!(
            filter(&KRATOS_EMAIL_TEMPLATES, &oos),
            Err(AppError::Forbidden)
        ));
        // Every allowlisted pointer is a `valid/email` body/subject under courier.
        assert!(KRATOS_EMAIL_TEMPLATES.allowed_paths.iter().all(|p| {
            p.starts_with("/courier/templates/")
                && p.contains("/valid/email")
        }));
    }

    /// brand_allowlist sensitive_denied: a sensitive pointer (`/courier/smtp/
    /// connection_uri`, `/secrets/...`, `/dsn`) is rejected for BOTH new sections
    /// regardless of allowlist membership (Gate-1 denylist wins).
    #[test]
    fn sensitive_pointers_denied_for_branding_sections() {
        let sections: &[&SectionAllowlist] = &[&KRATOS_UI_URLS, &KRATOS_EMAIL_TEMPLATES];
        let sensitive = [
            "/courier/smtp/connection_uri",
            "/secrets/cipher/0",
            "/dsn",
            "/serve/admin/base_url",
        ];
        for al in sections {
            for p in sensitive {
                let patch = vec![(p.to_string(), json!("x"))];
                assert!(
                    matches!(filter(al, &patch), Err(AppError::Forbidden)),
                    "branding section `{}`: `{p}` must be denied",
                    al.section
                );
            }
            // And no branding allowlist lists a sensitive pointer.
            for sp in SENSITIVE_PREFIXES {
                assert!(
                    !al.allowed_paths.iter().any(|p| p.starts_with(sp)),
                    "branding section `{}` must not list a sensitive pointer ({sp})",
                    al.section
                );
            }
        }
    }
}
