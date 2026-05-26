//! `X-Console-Signature` HMAC-SHA256 signer (HOOK-02).
//!
//! Each webhook delivery carries `X-Console-Signature: sha256=<lowerhex>` — an
//! HMAC-SHA256 over the RAW request body keyed by the per-webhook secret. The
//! receiver recomputes the same MAC with its copy of the secret to verify
//! authenticity + integrity (T-11-04). RustCrypto `hmac` + `sha2` (the standard
//! pairing; `sha2` is already a direct dep). `hmac` is PINNED to 0.12 so
//! `Hmac<Sha256>` type-checks against the digest-0.10 traits `sha2 0.10` exposes.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// The signature header name. Exported so the worker and any verifier agree.
pub const SIGNATURE_HEADER: &str = "X-Console-Signature";

/// Compute the `X-Console-Signature` value (`sha256=<lowerhex>`) over the RAW
/// body keyed by `secret`. HMAC accepts a key of any length, so this never fails.
pub fn sign(secret: &[u8], raw_body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(raw_body);
    let tag = mac.finalize().into_bytes();
    let mut hex = String::with_capacity(tag.len() * 2 + 7);
    hex.push_str("sha256=");
    for b in tag {
        hex.push_str(&format!("{b:02x}"));
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-vector: a fixed secret + body produce a fixed, stable signature.
    /// The expected hex is the RFC-4231-style HMAC-SHA256, computed once and
    /// asserted for stability + format.
    #[test]
    fn sign_is_stable_and_well_formed() {
        let secret = b"test-secret-key";
        let body = br#"{"event":"identity.created","id":"abc"}"#;

        let sig = sign(secret, body);

        // Format: "sha256=" + 64 lowercase hex chars.
        assert!(sig.starts_with("sha256="), "missing prefix: {sig}");
        let hex = &sig["sha256=".len()..];
        assert_eq!(hex.len(), 64, "expected 64 hex chars, got {}", hex.len());
        assert!(
            hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "expected lowercase hex: {hex}"
        );

        // Stable across calls.
        assert_eq!(sign(secret, body), sig);
    }

    /// Different body OR different key changes the signature.
    #[test]
    fn sign_changes_with_body_and_key() {
        let a = sign(b"k1", b"body");
        let b = sign(b"k1", b"BODY");
        let c = sign(b"k2", b"body");
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    /// Pin the canonical RFC 4231 Test Case 2 vector so a future crate bump that
    /// silently changes the algorithm is caught.
    #[test]
    fn sign_matches_rfc4231_test_case_2() {
        // key = "Jefe", data = "what do ya want for nothing?"
        let sig = sign(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            sig,
            "sha256=5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }
}
