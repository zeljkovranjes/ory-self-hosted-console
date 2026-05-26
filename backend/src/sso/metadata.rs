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
//! pre-flight over the metadata's `KeyDescriptor` shape, evaluated with a real
//! namespace-aware XML pull-parser (`quick-xml`, WR-01) that ignores comments
//! and CDATA — NOT a string scan. There is NO operator toggle to skip it.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use quick_xml::events::Event;
use quick_xml::name::QName;
use quick_xml::reader::Reader;

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

/// Strip an `{namespace}` Clark-notation prefix and lowercase a local element
/// name so the structural check is namespace-prefix agnostic (`md:KeyDescriptor`,
/// `KeyDescriptor`, `ds:X509Certificate` all match). quick-xml already resolves
/// the bytes to the LOCAL name for us via `QName::local_name`; this just folds
/// case for the comparison.
fn local_name_lower(qname: QName<'_>) -> String {
    String::from_utf8_lossy(qname.local_name().as_ref()).to_ascii_lowercase()
}

/// Real (namespace-aware) structural pre-flight: is there a non-empty
/// `<X509Certificate>` under a signing-usable `<KeyDescriptor>`?
///
/// Implemented with a `quick-xml` pull-parser (WR-01) so that — unlike the prior
/// string scan — comments and CDATA are NEVER honored as markup, the
/// `KeyDescriptor/@use` attribute is read from the actual element (not a substring
/// match that could see `keyUse` or a `use=` inside a comment), and an
/// encryption-only `KeyDescriptor` can never be credited with a cert that lives
/// in a sibling element.
///
/// Decision rule (unchanged from the SSO-02 contract):
///   - A `<KeyDescriptor>` qualifies iff its `use` is `"signing"` (case-insensitive)
///     OR absent (absent `use` = valid for both per the SAML metadata spec), AND it
///     contains a descendant `<X509Certificate>` with a non-whitespace payload.
///   - A cert that appears ONLY under `use="encryption"` does NOT qualify.
///   - A bare `<X509Certificate>` with NO enclosing `<KeyDescriptor>` anywhere in
///     the document is treated as signing-usable (absent-use semantics) so a
///     minimal but cert-bearing doc still works.
///
/// Any XML parse error is fail-CLOSED (returns `false` → the connection is
/// rejected): malformed metadata can never validate an assertion signature.
fn has_signing_cert(xml: &str) -> bool {
    let mut reader = Reader::from_str(xml);
    let config = reader.config_mut();
    // Tolerate the loose, real-world IdP metadata we see (unquoted edge cases,
    // mismatched-but-harmless end tags) without crediting comments/CDATA as
    // markup — quick-xml never surfaces comment/CDATA bytes as Start/Text we act on.
    config.check_end_names = false;

    // Depth at which a signing-usable KeyDescriptor opened (None = not inside one).
    // We only credit an X509Certificate that is a DESCENDANT of such a descriptor.
    let mut signing_descriptor_depth: Option<usize> = None;
    let mut depth: usize = 0;
    let mut saw_key_descriptor = false;
    // Did we see any KeyDescriptor at all? If not, a bare cert is signing-usable.
    let mut bare_cert_present = false;
    // Are we currently inside an <X509Certificate> element (any nesting)? Track the
    // depth at which it opened plus whether its text payload was non-empty, and
    // whether that cert is signing-usable (inside a qualifying KeyDescriptor OR,
    // for the bare-cert fallback, anywhere when no KeyDescriptor exists).
    let mut cert_open_depth: Option<usize> = None;
    let mut cert_is_signing_context = false;
    let mut cert_text_nonempty = false;

    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                depth += 1;
                let name = local_name_lower(e.name());
                if name == "keydescriptor" {
                    saw_key_descriptor = true;
                    if key_use_is_signing(&e) {
                        signing_descriptor_depth = Some(depth);
                    }
                } else if name == "x509certificate" {
                    cert_open_depth = Some(depth);
                    cert_text_nonempty = false;
                    // Signing context: inside a qualifying KeyDescriptor.
                    cert_is_signing_context = signing_descriptor_depth.is_some();
                }
            }
            Ok(Event::End(_)) => {
                // A qualifying KeyDescriptor closes when we pop back above its depth.
                if let Some(d) = signing_descriptor_depth {
                    if depth <= d {
                        signing_descriptor_depth = None;
                    }
                }
                if let Some(d) = cert_open_depth {
                    if depth <= d {
                        // The cert element just closed: evaluate it.
                        if cert_text_nonempty {
                            bare_cert_present = true;
                            if cert_is_signing_context {
                                return true;
                            }
                        }
                        cert_open_depth = None;
                        cert_is_signing_context = false;
                        cert_text_nonempty = false;
                    }
                }
                depth = depth.saturating_sub(1);
            }
            // CDATA is delivered as a separate `CData` event (NOT Text), so a cert
            // payload smuggled in CDATA is intentionally ignored here.
            Ok(Event::Text(t)) if cert_open_depth.is_some() => {
                if let Ok(text) = t.decode() {
                    if text.chars().any(|c| !c.is_whitespace()) {
                        cert_text_nonempty = true;
                    }
                }
            }
            Ok(Event::Eof) => break,
            // Parse error: fail closed (reject). Malformed metadata cannot prove a
            // signing cert.
            Err(_) => return false,
            _ => {}
        }
        buf.clear();
    }

    // Fallback: a non-empty bare X509Certificate with NO KeyDescriptor anywhere in
    // the document is signing-usable (absent-use semantics for an unwrapped cert).
    if !saw_key_descriptor && bare_cert_present {
        return true;
    }
    false
}

/// Read a `<KeyDescriptor>`'s `use` attribute and report whether it is
/// signing-usable: `use="signing"` (case-insensitive) OR `use` ABSENT (absent =
/// both signing and encryption per the SAML metadata spec). Any other value
/// (notably `encryption`) is NOT signing-usable. The attribute is read from the
/// real element via quick-xml, so it can never match a comment or another token.
fn key_use_is_signing(e: &quick_xml::events::BytesStart<'_>) -> bool {
    for attr in e.attributes().flatten() {
        // Compare on the LOCAL attribute name so a namespaced `md:use` (rare) and a
        // bare `use` both match; ignore unrelated attrs like `keyUse`.
        if local_name_lower(attr.key) == "use" {
            // The `use` value is a plain token (`signing`/`encryption`) with no
            // XML entities to unescape, so the raw attribute bytes are sufficient
            // and avoid the version-coupled normalized_value API.
            let val = String::from_utf8_lossy(attr.value.as_ref())
                .trim()
                .to_ascii_lowercase();
            return val == "signing";
        }
    }
    // No `use` attribute → signing-usable (absent-use semantics).
    true
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
    fn use_signing_inside_an_xml_comment_does_not_count() {
        // WR-01 crafted-metadata bypass: the ONLY real KeyDescriptor is
        // use="encryption"; a `use="signing"` token is smuggled into an XML COMMENT.
        // The old string scan honored the comment and WRONGLY accepted this. A real
        // parser never sees the comment as markup → reject.
        let crafted = r#"
            <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
              <md:IDPSSODescriptor>
                <!-- <md:KeyDescriptor use="signing"> a decoy in a comment -->
                <md:KeyDescriptor use="encryption">
                  <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                    <ds:X509Data><ds:X509Certificate>MIIDencONLY==</ds:X509Certificate></ds:X509Data>
                  </ds:KeyInfo>
                </md:KeyDescriptor>
              </md:IDPSSODescriptor>
            </md:EntityDescriptor>"#;
        let err = require_signing_cert(crafted)
            .expect_err("a use=signing token hidden in a comment must NOT satisfy SSO-02");
        assert!(matches!(err, AppError::Validation(_)), "got {err:?}");
    }

    #[test]
    fn cert_in_cdata_under_encryption_descriptor_does_not_count() {
        // WR-01: a bare-looking <X509Certificate> smuggled in CDATA must not be
        // credited to the encryption-only descriptor (CDATA is not markup, and the
        // only KeyDescriptor is encryption-use).
        let crafted = r#"
            <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
              <md:IDPSSODescriptor>
                <md:KeyDescriptor use="encryption">
                  <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                    <ds:X509Data><ds:X509Certificate><![CDATA[MIIDsmuggled==]]></ds:X509Certificate></ds:X509Data>
                  </ds:KeyInfo>
                </md:KeyDescriptor>
              </md:IDPSSODescriptor>
            </md:EntityDescriptor>"#;
        let err = require_signing_cert(crafted)
            .expect_err("an encryption-only descriptor (even with a CDATA cert) must be rejected");
        assert!(matches!(err, AppError::Validation(_)), "got {err:?}");
    }

    #[test]
    fn malformed_xml_is_fail_closed() {
        // Unparseable junk must be rejected (fail-closed), never accepted.
        let err = require_signing_cert("<md:KeyDescriptor use=\"signing\"><not closed")
            .expect_err("malformed metadata must fail closed");
        assert!(matches!(err, AppError::Validation(_)), "got {err:?}");
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
