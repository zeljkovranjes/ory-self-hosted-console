//! `base64://` Jsonnet-URI codec (07-RESEARCH Pattern 3 / fact 3).
//!
//! Several Kratos config fields are *not* plain strings but **URI references to a
//! Jsonnet source**: the OIDC provider `mapper_url`, the SMS channel
//! `request_config.body`, and the web_hook `config.body`. Kratos accepts these as
//! a `file://`, `http(s)://`, or — the form the console uses — a self-contained
//! `base64://<standard-base64-of-the-source>` URI, where the decoded payload IS
//! the Jsonnet source. Storing the source inline as `base64://` keeps the whole
//! config self-contained (no extra mounted files) AND avoids the runtime-fetch
//! SSRF surface that a `http(s)://` mapper would carry.
//!
//! This module is the SINGLE place that knows the `base64://` convention:
//!   - [`encode_base64_uri`] wraps operator-edited plaintext Jsonnet source into a
//!     `base64://…` URI before it lands in the config doc (PUT path);
//!   - [`decode_base64_uri`] turns a stored `base64://…` URI back into the source
//!     text for the editor (GET path), and PASSES THROUGH any non-`base64://` URI
//!     (`file://`, `http://`, `https://`) UNCHANGED — it never fetches a remote
//!     URI (SSRF deferred to HOOK-02 / Phase 11; the decoder is fetch-free by
//!     construction, threat T-07-08).
//!
//! Encoding uses the STANDARD base64 alphabet (RFC 4648 `+`/`/`, with padding),
//! which is what Kratos' `base64://` loader expects — NOT the URL-safe alphabet
//! the session-token module uses.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use crate::error::AppError;

/// The URI scheme prefix that marks an inline-base64 Jsonnet source.
pub const BASE64_SCHEME: &str = "base64://";

/// Encode operator-edited Jsonnet `src` text into a `base64://<standard-b64>` URI.
///
/// The decoded payload of the returned URI is byte-for-byte `src`. Always uses the
/// STANDARD (padded) base64 alphabet so Kratos' `base64://` loader decodes it.
pub fn encode_base64_uri(src: &str) -> String {
    format!("{BASE64_SCHEME}{}", STANDARD.encode(src.as_bytes()))
}

/// Decode a `base64://…` URI back to its Jsonnet source text.
///
/// - A `base64://<b64>` URI is decoded; an invalid base64 payload or non-UTF-8
///   decoded bytes is a value-free [`AppError::BadRequest`] (the offending bytes
///   are never echoed).
/// - Any OTHER URI (`file://`, `http://`, `https://`, or any non-`base64://`
///   string) is returned UNCHANGED — this function NEVER fetches a remote URI
///   (threat T-07-08: SSRF is out of scope here; the decoder is fetch-free).
pub fn decode_base64_uri(uri: &str) -> Result<String, AppError> {
    let Some(b64) = uri.strip_prefix(BASE64_SCHEME) else {
        // Non-base64 URI (file://, http(s)://, …): pass through verbatim. We do
        // NOT fetch it — remote-fetch hardening is HOOK-02 / Phase 11.
        return Ok(uri.to_string());
    };
    let bytes = STANDARD.decode(b64).map_err(|_| {
        // Value-free: never echo the offending base64 payload.
        AppError::BadRequest("invalid base64:// jsonnet uri".to_string())
    })?;
    String::from_utf8(bytes).map_err(|_| {
        AppError::BadRequest("base64:// jsonnet uri is not valid utf-8".to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_source_through_base64_uri() {
        let src = "function(ctx) {\n  identity: { id: ctx.subject },\n}\n";
        let uri = encode_base64_uri(src);
        assert!(
            uri.starts_with(BASE64_SCHEME),
            "encoded value must carry the base64:// scheme: {uri}"
        );
        // The raw source must NOT appear verbatim in the encoded URI.
        assert!(
            !uri.contains("function(ctx)"),
            "the encoded URI must not contain the plaintext source: {uri}"
        );
        let decoded = decode_base64_uri(&uri).expect("decode round-trips");
        assert_eq!(decoded, src, "encode -> decode must be the identity");
    }

    #[test]
    fn round_trip_uses_standard_alphabet() {
        // Bytes that produce `+`/`/` under the STANDARD alphabet (and `-`/`_`
        // under URL-safe) — assert the STANDARD form is emitted and decodes back.
        let src = "\u{00ff}\u{00fe}\u{00fd}\u{00fc}"; // multi-byte UTF-8 payload
        let uri = encode_base64_uri(src);
        let payload = uri.strip_prefix(BASE64_SCHEME).unwrap();
        // STANDARD base64 is padded; URL-safe-no-pad would not be.
        assert!(
            payload.ends_with('=') || !payload.contains('-') && !payload.contains('_'),
            "standard (padded, +// alphabet) base64 expected: {payload}"
        );
        assert_eq!(decode_base64_uri(&uri).unwrap(), src);
    }

    #[test]
    fn non_base64_uris_pass_through_unchanged_without_fetch() {
        for uri in [
            "file:///etc/config/kratos/oidc.jsonnet",
            "http://internal-service/mapper.jsonnet",
            "https://example.com/mapper.jsonnet",
            "", // empty string is not base64:// either
        ] {
            assert_eq!(
                decode_base64_uri(uri).expect("pass-through never errors"),
                uri,
                "a non-base64:// URI must pass through unchanged (no fetch)"
            );
        }
    }

    #[test]
    fn invalid_base64_payload_is_value_free_bad_request() {
        // `*` is not in the base64 alphabet -> decode error, value-free message.
        let err = decode_base64_uri("base64://not*valid*b64")
            .expect_err("invalid base64 must be rejected");
        assert!(matches!(err, AppError::BadRequest(_)));
        if let AppError::BadRequest(msg) = err {
            assert!(
                !msg.contains("not*valid*b64"),
                "error message must be value-free: {msg}"
            );
        }
    }

    #[test]
    fn empty_source_round_trips() {
        // An empty mapper body encodes to `base64://` (empty payload) and decodes
        // back to the empty string.
        let uri = encode_base64_uri("");
        assert_eq!(uri, BASE64_SCHEME);
        assert_eq!(decode_base64_uri(&uri).unwrap(), "");
    }
}
