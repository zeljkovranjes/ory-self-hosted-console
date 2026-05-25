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

/// Code-defined registry of every shipped section allowlist. The lookup is the
/// ONLY way to obtain an allowlist — it is never assembled from client input.
const REGISTRY: &[&SectionAllowlist] = &[&KRATOS_SESSION];

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
}
