//! The `email_verified`-default-false Kratos Jsonnet mapper generator (SSO-03 —
//! the account-takeover defense, the #1 pitfall of this phase).
//!
//! Polis's OIDC id_token is VERIFIED to carry NO `email_verified` claim (RESEARCH:
//! `ory/polis@v26.2.0 npm/src/typings.ts` `Profile` has no such field, and
//! `oauth.ts` never injects one). A naive Kratos mapper that maps `email`
//! unconditionally is therefore a direct account-takeover vector: an attacker who
//! controls a SAML IdP asserts `victim@corp.com` and Kratos auto-links them to the
//! victim's existing identity (Pitfall 2 / T-14-02).
//!
//! [`generate_gated_mapper`] emits Ory's documented default-false defense
//! (`local claims = { email_verified: false } + std.extVar('claims')`), so an
//! ABSENT `email_verified` (which for a Polis SAML bridge is ALWAYS) drops the
//! `email` trait entirely. There is NO unconditional `email: claims.email`, and
//! NO operator toggle to remove the guard. The trust anchor that makes a SAML
//! email usable is the Organization domain binding (SSO-05) + an explicit operator
//! linking action (mirroring `auth/github.rs` link-or-deny) — never the assertion.
//!
//! Source: `[CITED: ory.com/docs/kratos/social-signin/data-mapping]` (the
//! default-false pattern verbatim) + `[VERIFIED: ory/polis emits no email_verified]`.

/// The default-false guard line that MUST begin every generated mapper. Pinned as
/// a constant so the negative test asserts the exact substring (account-takeover
/// regression). The `+ std.extVar('claims')` overlay means a PRESENT
/// `email_verified` from the provider wins, but an ABSENT one defaults to `false`.
pub const GUARD_PRELUDE: &str =
    "local claims = { email_verified: false } + std.extVar('claims');";

/// The conditional-key guard that gates the `email` trait on BOTH presence AND
/// verification. Pinned so the test can assert it is present and that there is no
/// unconditional `email: claims.email`.
pub const EMAIL_GATE: &str =
    "[if 'email' in claims && claims.email_verified then 'email' else null]: claims.email,";

/// Generate the `email_verified`-default-false Kratos Jsonnet mapper source.
///
/// The returned source:
///   1. begins with the [`GUARD_PRELUDE`] default-false overlay;
///   2. emits the `email` trait ONLY under the [`EMAIL_GATE`] conditional key —
///      there is NO unconditional `email: claims.email` anywhere;
///   3. maps the non-identifying `name` traits conditionally (only when present),
///      which is safe to do without a verification gate (a display name is not an
///      account-linking key).
///
/// The mapper is the SAME for every connection (no per-connection / per-operator
/// parameter that could weaken the guard). The caller base64-encodes it into the
/// Kratos `providers[].mapper_url` via `config_edit::jsonnet::encode_base64_uri`.
pub fn generate_gated_mapper() -> String {
    format!(
        "{GUARD_PRELUDE}\n\
\n\
{{\n\
  identity: {{\n\
    traits: {{\n\
      // SSO-03: email is emitted ONLY when present AND the provider asserts\n\
      // email_verified. Polis (SAML bridge) asserts NO email_verified, so this\n\
      // key is dropped and Kratos cannot auto-link by email (takeover defense).\n\
      {EMAIL_GATE}\n\
      // name is non-identifying — safe to map unconditionally when present.\n\
      [if 'firstName' in claims then 'name' else null]: {{\n\
        first: claims.firstName,\n\
        last: if 'lastName' in claims then claims.lastName else null,\n\
      }},\n\
    }},\n\
  }},\n\
}}\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapper_begins_with_the_default_false_guard() {
        let src = generate_gated_mapper();
        assert!(
            src.starts_with(GUARD_PRELUDE),
            "the mapper MUST begin with the default-false guard; got:\n{src}"
        );
    }

    /// SSO-03 NEGATIVE (account-takeover regression): feed/inspect a generated
    /// mapper and assert the email trait is CONDITIONAL on email_verified — there
    /// is NO unconditional `email: claims.email`, and the gate substring IS
    /// present. This is the load-bearing proof that an unverified email is dropped.
    #[test]
    fn unverified_email_is_dropped() {
        let src = generate_gated_mapper();

        // The verification gate must be present verbatim.
        assert!(
            src.contains(EMAIL_GATE),
            "the email trait must be gated on `email_verified`; got:\n{src}"
        );
        // The default-false overlay must be present (absent claim ⇒ false ⇒ dropped).
        assert!(
            src.contains("email_verified: false"),
            "the default-false overlay must be present; got:\n{src}"
        );

        // There must be NO unconditional `email: claims.email` outside the gate.
        // Strip the single gated occurrence, then assert the dangerous pattern is
        // gone from the remainder (it would indicate an ungated email mapping).
        let without_gate = src.replace(EMAIL_GATE, "");
        assert!(
            !without_gate.contains("email: claims.email")
                && !without_gate.contains("'email': claims.email")
                && !without_gate.contains("\"email\": claims.email"),
            "found an UNCONDITIONAL email mapping (account-takeover vector); got:\n{src}"
        );

        // There is no operator toggle / escape hatch wording.
        let lower = src.to_ascii_lowercase();
        assert!(
            !lower.contains("trust") && !lower.contains("skip") && !lower.contains("disable"),
            "the mapper must expose no guard-disabling toggle; got:\n{src}"
        );
    }

    #[test]
    fn name_is_mapped_conditionally_and_unconditionally_safe() {
        let src = generate_gated_mapper();
        // name is gated on PRESENCE only (no verification gate — it is not an
        // account-linking key), but still conditional so an absent firstName does
        // not write a null-keyed trait.
        assert!(
            src.contains("[if 'firstName' in claims then 'name' else null]"),
            "name must be mapped conditionally on presence; got:\n{src}"
        );
    }
}
