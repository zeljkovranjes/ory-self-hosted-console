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

use std::path::PathBuf;

use crate::config_edit::yaml::write_atomic;
use crate::error::AppError;

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

/// Validate that `source` is plausible THEMING override TEXT (not binary). The
/// AX consumes it verbatim as a `:root{…}` CSS-variable block, so we do NOT
/// parse CSS — we only reject content with embedded NUL bytes (a binary-blob
/// marker). Returns the trimmed-of-trailing-newline source unchanged otherwise.
fn validate_theme_text(source: &str) -> Result<(), AppError> {
    if source.contains('\0') {
        return Err(AppError::BadRequest(
            "theme override must be plain text (CSS), not binary".into(),
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
    write_atomic(&theme_path(config_dir), source)
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
    write_atomic(&translations_path(config_dir), &pretty)?;
    Ok(value)
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
}
