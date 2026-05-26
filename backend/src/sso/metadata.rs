//! IdP metadata pre-flight + base64 encode (SSO-02 — the MANDATORY signing CA).
//!
//! The console is the enforcement point for the signing-certificate mandate
//! (RESEARCH Pitfall 1 / T-14-01): Polis itself will happily create a connection
//! from minimal metadata, and there is NO env var that disables Polis signature
//! validation — so the only place a CA-less connection can be REFUSED is here,
//! BEFORE the `POST /api/v1/sso`. A SAML connection with no signing cert means
//! Polis has nothing to validate the assertion signature against → a forged-
//! assertion auth bypass.
//!
//! [`require_signing_cert`] parses the IdP metadata XML and requires at least one
//! `<X509Certificate>` that is usable for SIGNING — i.e. it lives under a
//! `<KeyDescriptor use="signing">` OR a `<KeyDescriptor>` with NO `use` attribute
//! (per the SAML 2.0 metadata spec an absent `use` means the key is valid for both
//! signing and encryption). A cert that appears ONLY under `use="encryption"` does
//! NOT satisfy the mandate (A2): an encryption-only cert cannot validate an
//! assertion signature, so a metadata document whose sole cert is encryption-only
//! is REJECTED. The reject message is VALUE-FREE — it never echoes the XML.
//!
//! No XML/DSIG library is hand-rolled here (the assertion-signature validation
//! itself is Polis's job, `@boxyhq/saml20`); this is a conservative structural
//! pre-flight over the metadata's `KeyDescriptor` shape. There is NO operator
//! toggle to skip it.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use crate::config_edit::schema::FieldError;
use crate::error::AppError;

/// The value-free 422 message for CA-less / encryption-only metadata. Names the
/// missing CONTROL, never the offending XML (BACK-07).
const NO_SIGNING_CERT_MSG: &str =
    "SAML IdP metadata must include a signing certificate (an X509Certificate under a \
     KeyDescriptor usable for signing); connections without a signing certificate are rejected.";

/// Require that `idp_xml` carries at least one X509 certificate usable for
/// SIGNING (SSO-02). Returns `Ok(())` when a signing-usable cert is present;
/// `AppError::Validation` (422) with a value-free message otherwise.
///
/// A cert is "signing-usable" when it appears inside a `<KeyDescriptor>` whose
/// `use` is `"signing"` OR absent (absent `use` = both per the SAML metadata
/// spec). A cert that appears ONLY under `use="encryption"` does NOT qualify —
/// an encryption-only document is rejected (A2). The check is case-insensitive on
/// the `use` value and tolerant of XML namespace prefixes (`ds:X509Certificate`,
/// `md:KeyDescriptor`).
pub fn require_signing_cert(idp_xml: &str) -> Result<(), AppError> {
    if has_signing_cert(idp_xml) {
        Ok(())
    } else {
        // Value-free: the offending XML is never placed in the error.
        Err(AppError::Validation(vec![FieldError {
            path: "metadata".into(),
            message: NO_SIGNING_CERT_MSG.into(),
        }]))
    }
}

/// Conservative structural scan: is there an `<X509Certificate>` under a
/// signing-usable `<KeyDescriptor>`?
///
/// We walk the metadata one `KeyDescriptor` element at a time. For each, we read
/// its `use` attribute (if any) and whether its body contains an
/// `<X509Certificate>`. A KeyDescriptor with a non-empty cert qualifies iff its
/// `use` is `"signing"` or absent. We also handle the (non-spec but seen)
/// degenerate case of a bare `<X509Certificate>` not wrapped in any KeyDescriptor
/// by treating an unwrapped cert as signing-usable (absent `use` semantics).
fn has_signing_cert(xml: &str) -> bool {
    // Lowercase a COPY only for locating the tag boundaries; the original casing
    // is irrelevant to the structural decision (we never echo the content).
    let lower = xml.to_ascii_lowercase();

    // Track whether we ever saw ANY KeyDescriptor at all. If we never see one but
    // a bare cert exists, fall back to treating the unwrapped cert as signing-
    // usable (absent-use semantics) so a minimal but cert-bearing doc still works.
    let mut saw_key_descriptor = false;

    // Scan each <KeyDescriptor ...> ... </KeyDescriptor> region.
    let mut search_from = 0usize;
    while let Some(rel_open) = lower[search_from..].find("keydescriptor") {
        // Find the actual element-open `<` preceding this token so we can read the
        // attributes of the open tag. Move back to the `<`.
        let token_pos = search_from + rel_open;
        let open_lt = match lower[..token_pos].rfind('<') {
            Some(p) => p,
            None => {
                search_from = token_pos + "keydescriptor".len();
                continue;
            }
        };
        // The open tag ends at the next `>`.
        let open_gt = match lower[open_lt..].find('>') {
            Some(rel) => open_lt + rel,
            None => break, // malformed; stop scanning
        };
        saw_key_descriptor = true;
        let open_tag = &lower[open_lt..=open_gt];

        // Read the `use` attribute of THIS KeyDescriptor open tag (if present).
        let key_use = extract_use_attr(open_tag);

        // The element body runs from just after the open tag to the matching
        // closing `</...keydescriptor>` (or end of doc if self-closing/unterminated).
        let body_start = open_gt + 1;
        let body_end = lower[body_start..]
            .find("</")
            .and_then(|rel| {
                // Confirm the close tag is a keydescriptor close; otherwise scan onward.
                let close_pos = body_start + rel;
                if lower[close_pos..].starts_with("</")
                    && lower[close_pos..]
                        .find("keydescriptor")
                        .map(|d| d < 20)
                        .unwrap_or(false)
                {
                    Some(close_pos)
                } else {
                    // Nested or unrelated close: fall back to the rest of the doc.
                    Some(lower.len())
                }
            })
            .unwrap_or(lower.len());
        let body = &lower[body_start..body_end];

        let has_cert = body.contains("x509certificate") && body.contains("</")
            // require a non-empty cert payload between the open/close cert tags
            && cert_payload_nonempty(body);

        if has_cert {
            match key_use.as_deref() {
                // Signing-usable: explicit "signing" or absent `use`.
                Some("signing") | None => return true,
                // Anything else (notably "encryption") does NOT satisfy SSO-02.
                Some(_) => {}
            }
        }

        // Continue scanning after this KeyDescriptor open tag.
        search_from = open_gt + 1;
    }

    // No qualifying KeyDescriptor. If the document never declared a KeyDescriptor
    // at all but does carry a non-empty bare X509Certificate, treat it as
    // signing-usable (absent-use semantics for an unwrapped cert).
    if !saw_key_descriptor && lower.contains("x509certificate") && cert_payload_nonempty(&lower) {
        return true;
    }
    false
}

/// Extract the (lowercased) value of a `use="..."` attribute from a KeyDescriptor
/// open tag, if present. Returns `None` when the attribute is absent.
fn extract_use_attr(open_tag: &str) -> Option<String> {
    // Find `use` as a standalone attribute name (avoid matching inside another
    // token). Look for `use` followed by optional spaces then `=`.
    let bytes = open_tag.as_bytes();
    let mut i = 0usize;
    while let Some(rel) = open_tag[i..].find("use") {
        let pos = i + rel;
        // Preceding char must be a boundary (space, quote, or `<`), and the char
        // after must lead to `=` (allowing whitespace).
        let prev_ok = pos == 0
            || matches!(bytes.get(pos - 1), Some(b' ' | b'\t' | b'\n' | b'\r' | b'"' | b'\''));
        let after = &open_tag[pos + 3..];
        let after_trim = after.trim_start();
        if prev_ok && after_trim.starts_with('=') {
            // Parse the quoted value.
            let val_part = after_trim[1..].trim_start();
            let quote = val_part.chars().next();
            if let Some(q @ ('"' | '\'')) = quote {
                if let Some(end) = val_part[1..].find(q) {
                    return Some(val_part[1..=end].to_string());
                }
            }
        }
        i = pos + 3;
    }
    None
}

/// True iff there is at least one non-whitespace character between an
/// `<...x509certificate>` open and its `</...x509certificate>` close in `body`.
/// Guards against an empty `<X509Certificate></X509Certificate>` passing the
/// presence check.
fn cert_payload_nonempty(body: &str) -> bool {
    let mut from = 0usize;
    while let Some(rel) = body[from..].find("x509certificate") {
        let tag_pos = from + rel;
        // Move to the `>` that ends this open tag.
        if let Some(gt_rel) = body[tag_pos..].find('>') {
            let payload_start = tag_pos + gt_rel + 1;
            // The payload ends at the next `<` (the close tag).
            if let Some(lt_rel) = body[payload_start..].find('<') {
                let payload = &body[payload_start..payload_start + lt_rel];
                if payload.trim().chars().any(|c| !c.is_whitespace()) {
                    return true;
                }
            }
            from = payload_start;
        } else {
            break;
        }
    }
    false
}

/// Base64-encode operator-uploaded IdP metadata XML for the Polis
/// `encodedRawMetadata` field (the PREFERRED, fetch-free metadata source — no
/// SSRF surface). Uses the STANDARD (padded) base64 alphabet, which is what Polis
/// decodes.
pub fn encode_metadata(idp_xml: &str) -> String {
    STANDARD.encode(idp_xml.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal IdP metadata fragment with a SIGNING KeyDescriptor cert.
    const SIGNING_METADATA: &str = r#"
        <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example/meta">
          <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <md:KeyDescriptor use="signing">
              <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data><ds:X509Certificate>MIIDsigningCERTbase64==</ds:X509Certificate></ds:X509Data>
              </ds:KeyInfo>
            </md:KeyDescriptor>
          </md:IDPSSODescriptor>
        </md:EntityDescriptor>"#;

    #[test]
    fn signing_cert_is_accepted() {
        require_signing_cert(SIGNING_METADATA).expect("metadata with a signing cert must pass");
    }

    #[test]
    fn metadata_without_any_cert_is_rejected_422() {
        // SSO-02 negative: no X509Certificate anywhere → 422, value-free message.
        let no_cert = r#"
            <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp/meta">
              <md:IDPSSODescriptor>
                <md:SingleSignOnService Location="https://idp/sso"/>
              </md:IDPSSODescriptor>
            </md:EntityDescriptor>"#;
        let err = require_signing_cert(no_cert).expect_err("no-cert metadata must be rejected");
        assert!(matches!(err, AppError::Validation(_)), "got {err:?}");
        assert_eq!(err.status_code(), salvo::http::StatusCode::UNPROCESSABLE_ENTITY);
        // The error must NOT echo the metadata content.
        assert!(
            !err.to_string().contains("idp/sso"),
            "the reject message must be value-free: {err}"
        );
    }

    #[test]
    fn encryption_only_cert_is_rejected_422() {
        // A2 / SSO-02 negative: the ONLY cert is under use="encryption" → it cannot
        // validate an assertion signature, so the connection MUST be rejected even
        // though an X509Certificate string is technically present (a naive
        // `contains("X509Certificate")` check would WRONGLY accept this).
        let encryption_only = r#"
            <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp/meta">
              <md:IDPSSODescriptor>
                <md:KeyDescriptor use="encryption">
                  <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                    <ds:X509Data><ds:X509Certificate>MIIDencryptionONLY==</ds:X509Certificate></ds:X509Data>
                  </ds:KeyInfo>
                </md:KeyDescriptor>
              </md:IDPSSODescriptor>
            </md:EntityDescriptor>"#;
        let err =
            require_signing_cert(encryption_only).expect_err("encryption-only cert must be rejected");
        assert!(matches!(err, AppError::Validation(_)), "got {err:?}");
    }

    #[test]
    fn keydescriptor_without_use_is_signing_usable() {
        // SAML metadata spec: an absent `use` means the key is valid for BOTH
        // signing and encryption — so it satisfies the signing mandate.
        let no_use = r#"
            <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
              <md:IDPSSODescriptor>
                <md:KeyDescriptor>
                  <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                    <ds:X509Data><ds:X509Certificate>MIIDboth==</ds:X509Certificate></ds:X509Data>
                  </ds:KeyInfo>
                </md:KeyDescriptor>
              </md:IDPSSODescriptor>
            </md:EntityDescriptor>"#;
        require_signing_cert(no_use).expect("a KeyDescriptor with no `use` is signing-usable");
    }

    #[test]
    fn both_signing_and_encryption_present_is_accepted() {
        // A realistic doc with an encryption KeyDescriptor AND a signing one: the
        // signing one must let it through (the encryption one alone never would).
        let both = r#"
            <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
              <md:IDPSSODescriptor>
                <md:KeyDescriptor use="encryption">
                  <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                    <ds:X509Data><ds:X509Certificate>ENCcert==</ds:X509Certificate></ds:X509Data>
                  </ds:KeyInfo>
                </md:KeyDescriptor>
                <md:KeyDescriptor use="signing">
                  <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                    <ds:X509Data><ds:X509Certificate>SIGNcert==</ds:X509Certificate></ds:X509Data>
                  </ds:KeyInfo>
                </md:KeyDescriptor>
              </md:IDPSSODescriptor>
            </md:EntityDescriptor>"#;
        require_signing_cert(both).expect("a doc with both certs must pass on the signing one");
    }

    #[test]
    fn empty_signing_cert_payload_is_rejected() {
        // An empty <X509Certificate></X509Certificate> under a signing descriptor
        // is not a real cert → reject.
        let empty = r#"
            <md:KeyDescriptor use="signing">
              <ds:X509Certificate></ds:X509Certificate>
            </md:KeyDescriptor>"#;
        let err = require_signing_cert(empty).expect_err("empty cert payload must be rejected");
        assert!(matches!(err, AppError::Validation(_)), "got {err:?}");
    }

    #[test]
    fn encode_metadata_round_trips_via_standard_base64() {
        let xml = "<EntityDescriptor>测试</EntityDescriptor>";
        let encoded = encode_metadata(xml);
        // The raw XML must not appear verbatim in the base64 form.
        assert!(!encoded.contains("EntityDescriptor"), "raw xml leaked: {encoded}");
        let decoded = STANDARD.decode(&encoded).expect("valid standard base64");
        assert_eq!(String::from_utf8(decoded).unwrap(), xml);
    }
}
