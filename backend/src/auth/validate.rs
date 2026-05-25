//! Input validation + normalization for operator-supplied identity fields
//! (WR-02). Shared by `/setup` (admin creation) and `/login` (lookup) so the
//! stored value and the lookup key are normalized IDENTICALLY — `citext` gives
//! case-insensitive uniqueness but does NOT trim whitespace, so an un-normalized
//! `" owner@x.com "` and `"owner@x.com"` would otherwise be distinct rows.
//!
//! The email check is intentionally conservative (a single `@` with a non-empty
//! local part and a dotted host), mirroring the planned frontend Zod schema
//! rather than attempting full RFC 5322 — it rejects the obvious garbage
//! (empty, whitespace-only, no `@`, no host) without false-rejecting real
//! addresses. Length caps bound storage and mirror the Zod limits.

use crate::error::AppError;

/// Max email length (RFC 5321 caps an address at 254/320; 320 is the generous
/// SMTP path limit — anything longer is rejected as malformed).
pub const MAX_EMAIL_LEN: usize = 320;
/// Max display-name length.
pub const MAX_NAME_LEN: usize = 200;

/// Validate + normalize an email: trim, lowercase, and enforce a conservative
/// shape (`local@host` with a dotted host). Returns the normalized value or a
/// 400 `BadRequest`. Lowercasing matches the `citext` column's case-insensitive
/// uniqueness so login and setup agree on the stored key.
pub fn validate_email(raw: &str) -> Result<String, AppError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AppError::BadRequest("email is required".into()));
    }
    if trimmed.len() > MAX_EMAIL_LEN {
        return Err(AppError::BadRequest("email is too long".into()));
    }

    let normalized = trimmed.to_ascii_lowercase();

    // Conservative shape: exactly one `@`, non-empty local part, host has a dot
    // with non-empty labels on both sides, and no internal whitespace.
    if normalized.chars().any(|c| c.is_whitespace()) {
        return Err(AppError::BadRequest("email is malformed".into()));
    }
    let mut parts = normalized.split('@');
    let (local, host) = match (parts.next(), parts.next(), parts.next()) {
        (Some(l), Some(h), None) => (l, h),
        _ => return Err(AppError::BadRequest("email is malformed".into())),
    };
    if local.is_empty() {
        return Err(AppError::BadRequest("email is malformed".into()));
    }
    // Host must contain a dot with non-empty labels (e.g. `example.com`).
    let dot = host.find('.');
    match dot {
        Some(idx) if idx > 0 && idx < host.len() - 1 => {}
        _ => return Err(AppError::BadRequest("email is malformed".into())),
    }

    Ok(normalized)
}

/// Validate + normalize a display name: trim, reject empty, cap the length.
pub fn validate_name(raw: &str) -> Result<String, AppError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AppError::BadRequest("name is required".into()));
    }
    if trimmed.chars().count() > MAX_NAME_LEN {
        return Err(AppError::BadRequest("name is too long".into()));
    }
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_normalizes_trim_and_case() {
        assert_eq!(validate_email("  Owner@Example.COM ").unwrap(), "owner@example.com");
    }

    #[test]
    fn email_rejects_garbage() {
        for bad in ["", "   ", "no-at-sign", "@host.com", "local@", "a@b", "two@@host.com", "spa ce@host.com"] {
            assert!(validate_email(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn email_rejects_overlong() {
        let long = format!("{}@example.com", "a".repeat(MAX_EMAIL_LEN));
        assert!(validate_email(&long).is_err());
    }

    #[test]
    fn name_trims_and_rejects_empty() {
        assert_eq!(validate_name("  Owner  ").unwrap(), "Owner");
        assert!(validate_name("").is_err());
        assert!(validate_name("   ").is_err());
    }

    #[test]
    fn name_rejects_overlong() {
        let long = "x".repeat(MAX_NAME_LEN + 1);
        assert!(validate_name(&long).is_err());
    }
}
