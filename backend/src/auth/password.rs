//! Password hashing + bootstrap-token hashing (CAUTH-02, CAUTH-03).
//!
//! Two distinct hashing regimes, deliberately not interchangeable (RESEARCH
//! Pitfall 5):
//!
//! - **Passwords** are LOW-entropy → Argon2id (slow, memory-hard) with OWASP
//!   params (m = 19 456 KiB, t = 2, p = 1). `verify_password` is constant-time.
//! - **The bootstrap token** is a 256-bit CSPRNG value (HIGH entropy, no
//!   brute-force surface) → a fast SHA-256 digest with a constant-time compare
//!   (`subtle`). Argon2 here would only add latency for no security gain.
//!
//! `enforce_password_policy` rejects anything shorter than 12 characters
//! (CONTEXT: minimum password policy length >= 12).

use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::AppError;

/// Minimum local-admin password length (CONTEXT: policy >= 12). Sourced from the
/// shared `console_core` constant so the backend `/setup` policy and the CLI's
/// offline DB-direct admin path (WR-04) can never drift.
const MIN_PASSWORD_LEN: usize = console_core::MIN_PASSWORD_LEN;

/// OWASP-baseline Argon2id configuration (m = 19 456 KiB, t = 2, p = 1).
/// Centralized so hashing and verification always use identical parameters.
fn hasher() -> Argon2<'static> {
    let params = Params::new(19_456, 2, 1, None).expect("static Argon2 params are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Hash a password into an Argon2id PHC string (`$argon2id$...`) with a fresh
/// random salt. The PHC string is what is persisted in `admins.password_hash`.
pub fn hash_password(password: &str) -> Result<String, AppError> {
    let salt = SaltString::generate(&mut OsRng);
    hasher()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| AppError::Internal(format!("password hashing failed: {e}")))
}

/// Verify a password against a stored PHC string. Constant-time on a valid
/// hash; returns `false` (never errors) on a malformed/unparseable hash so a
/// corrupt row cannot leak a distinguishable error to the client.
pub fn verify_password(password: &str, phc: &str) -> bool {
    match PasswordHash::new(phc) {
        Ok(parsed) => hasher().verify_password(password.as_bytes(), &parsed).is_ok(),
        Err(_) => false,
    }
}

/// Enforce the minimum password policy. Returns `AppError::BadRequest` (400)
/// with an operator-safe message (never echoes the password) when too short.
pub fn enforce_password_policy(password: &str) -> Result<(), AppError> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(AppError::BadRequest(format!(
            "password must be at least {MIN_PASSWORD_LEN} characters"
        )));
    }
    Ok(())
}

/// Lowercase-hex SHA-256 of the input. Used for the bootstrap-token hash at
/// rest and the session `token_hash` (deterministic, fast — Pitfall 5).
pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Constant-time verify of a raw token against a stored SHA-256 hex hash. The
/// raw token is hashed and the two digests compared with `subtle` so the
/// comparison time does not depend on how many leading bytes match (avoids the
/// timing side-channel a plain `==` on strings would open — RESEARCH Pitfall 5
/// / Anti-Pattern "never `==` on secrets").
pub fn verify_token_ct(raw: &str, stored_hash_hex: &str) -> bool {
    let computed = sha256_hex(raw);
    // Compare the hex strings in constant time. Equal length is required for a
    // meaningful CT compare; SHA-256 hex is always 64 chars, but guard anyway.
    if computed.len() != stored_hash_hex.len() {
        return false;
    }
    computed
        .as_bytes()
        .ct_eq(stored_hash_hex.as_bytes())
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_password_produces_argon2id_phc() {
        let phc = hash_password("correct horse battery staple").unwrap();
        assert!(
            phc.starts_with("$argon2id$"),
            "PHC string must be Argon2id, got: {phc}"
        );
    }

    #[test]
    fn verify_password_true_for_correct_false_for_wrong() {
        let phc = hash_password("correct horse battery staple").unwrap();
        assert!(verify_password("correct horse battery staple", &phc));
        assert!(!verify_password("Correct Horse Battery Staple", &phc));
        assert!(!verify_password("wrong password entirely", &phc));
    }

    #[test]
    fn verify_password_false_for_malformed_hash() {
        assert!(!verify_password("anything", "not-a-phc-string"));
        assert!(!verify_password("anything", ""));
    }

    #[test]
    fn password_policy_rejects_short() {
        // 11 chars -> rejected, 12 -> accepted.
        assert!(enforce_password_policy("12345678901").is_err());
        assert!(enforce_password_policy("123456789012").is_ok());
    }

    #[test]
    fn sha256_hex_is_deterministic_and_64_chars() {
        let a = sha256_hex("token-value");
        let b = sha256_hex("token-value");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        assert_ne!(a, sha256_hex("different"));
        // Known vector for the empty string.
        assert_eq!(
            sha256_hex(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn verify_token_ct_only_for_matching_digest() {
        let raw = "a-high-entropy-token";
        let stored = sha256_hex(raw);
        assert!(verify_token_ct(raw, &stored));
        assert!(!verify_token_ct("a-different-token", &stored));
        // Wrong-length stored hash is rejected without panicking.
        assert!(!verify_token_ct(raw, "deadbeef"));
    }
}
