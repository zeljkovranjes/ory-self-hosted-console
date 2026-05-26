//! Spoofing-resistant domain normalization (SSO-05 / threat T-14-07).
//!
//! [`normalize_domain`] is applied IDENTICALLY at two call sites — when an
//! operator writes an organization's verified domain, AND when the login-time
//! domain->SSO lookup resolves an email's domain (SSO-06). If the two paths ever
//! normalized differently, domain spoofing would reappear at lookup, so both go
//! through this ONE function and the unique index is on its output.
//!
//! The normalization pipeline (in order — RESEARCH Pattern 5):
//!   1. trim surrounding whitespace.
//!   2. strip a single trailing dot (the FQDN root: `corp.com.` == `corp.com`).
//!   3. lowercase (ASCII-case-fold; IDNA below folds the Unicode cases).
//!   4. IDNA / punycode -> ASCII via `url::Host::parse` (TR-46). This collapses a
//!      Cyrillic-homoglyph `cорp.com` and an already-`xn--` form to the SAME
//!      deterministic ASCII key — defeating homoglyph spoofing.
//!   5. registered-domain (eTLD+1) boundary via the `psl` crate (compile-time
//!      embedded Public Suffix List, no runtime fetch -> no SSRF/freshness
//!      surface). `sub.corp.com` and `corp.com` both reduce to `corp.com`, while
//!      `corp.com.attacker.com` reduces to `attacker.com` — so it does NOT
//!      collide with `corp.com`. The public suffix MUST be known (in the PSL):
//!      a bare TLD or an unknown suffix is rejected.
//!   6. empty / structurally-invalid input -> [`AppError::BadRequest`] (value-free).
//!
//! The stored value is the normalized ASCII registered domain; the unique index
//! is on that value so a case/IDNA/trailing-dot duplicate collides on insert.

use crate::error::AppError;

/// Normalize a domain (or the host part of an email) to its canonical, spoofing-
/// resistant registered-domain key. Used on BOTH write and lookup so the two can
/// never drift. Returns a value-free `BadRequest` for empty/invalid input.
pub fn normalize_domain(input: &str) -> Result<String, AppError> {
    // 1-2. trim + strip a single trailing FQDN-root dot.
    let trimmed = input.trim().trim_end_matches('.').trim();
    if trimmed.is_empty() {
        return Err(AppError::BadRequest("domain is required".into()));
    }
    // A domain never contains a path, scheme, userinfo, port, or whitespace. Reject
    // those structurally before IDNA so we never accept (and silently strip) an
    // attacker-supplied URL-ish value.
    if trimmed.contains('/')
        || trimmed.contains('@')
        || trimmed.contains(':')
        || trimmed.contains(char::is_whitespace)
    {
        return Err(AppError::BadRequest("invalid domain".into()));
    }
    // 3. ASCII lowercase (IDNA folds the Unicode cases; this handles the ASCII ones
    //    cheaply and deterministically first).
    let lowered = trimmed.to_lowercase();

    // 4. IDNA -> ASCII. `url::Host::parse` applies TR-46 internally and yields
    //    `Host::Domain(ascii)` (the xn-- punycode form) for a valid domain. An IP
    //    literal or a structurally invalid host is rejected (not a domain).
    let ascii = match url::Host::parse(&lowered) {
        Ok(url::Host::Domain(d)) if !d.is_empty() => d,
        _ => return Err(AppError::BadRequest("invalid domain".into())),
    };
    // A registrable domain has at least two labels (label + public suffix). A bare
    // single label (e.g. `localhost`, `com`) is not a registrable domain.
    if !ascii.contains('.') {
        return Err(AppError::BadRequest("invalid domain".into()));
    }

    // 5. Registered-domain (eTLD+1) boundary via the embedded PSL. `domain_str`
    //    returns the registrable domain (one label above the public suffix):
    //      sub.corp.com          -> corp.com
    //      corp.com              -> corp.com
    //      corp.com.attacker.com -> attacker.com   (so it does NOT collide)
    //      foo.co.uk             -> foo.co.uk       (multi-label TLD respected)
    //    The public suffix MUST be known (explicitly in the PSL) — an unknown TLD
    //    (the PSL `*` wildcard default rule) would let an attacker fabricate a
    //    boundary, so we reject it.
    let registered = psl::domain_str(&ascii).ok_or_else(|| AppError::BadRequest("invalid domain".into()))?;
    if !psl::suffix(ascii.as_bytes())
        .map(|s| s.is_known())
        .unwrap_or(false)
    {
        return Err(AppError::BadRequest("invalid domain".into()));
    }
    Ok(registered.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Assert two inputs normalize to the SAME stored key (a collision — the
    /// unique index would reject the second as a duplicate).
    fn assert_collides(a: &str, b: &str) {
        let na = normalize_domain(a).unwrap_or_else(|_| panic!("{a:?} should normalize"));
        let nb = normalize_domain(b).unwrap_or_else(|_| panic!("{b:?} should normalize"));
        assert_eq!(na, nb, "{a:?} and {b:?} must collide to the same key");
    }

    /// Assert two inputs normalize to DIFFERENT keys (no collision).
    fn assert_distinct(a: &str, b: &str) {
        let na = normalize_domain(a).unwrap_or_else(|_| panic!("{a:?} should normalize"));
        let nb = normalize_domain(b).unwrap_or_else(|_| panic!("{b:?} should normalize"));
        assert_ne!(na, nb, "{a:?} and {b:?} must NOT collide");
    }

    /// SSO-05 core table: case, trailing-dot, and Cyrillic-homoglyph variants all
    /// collapse to the SAME stored key as the plain ASCII `corp.com`.
    #[test]
    fn case_trailing_dot_and_homoglyph_collide() {
        // Case variants.
        assert_collides("corp.com", "CORP.com");
        assert_collides("corp.com", "Corp.Com");
        // Trailing FQDN-root dot.
        assert_collides("corp.com", "corp.com.");
        assert_collides("CORP.COM.", "corp.com");
        // Cyrillic-homoglyph: the 'о' here is U+043E (Cyrillic small o), which
        // punycodes to an xn-- form. Whichever canonical key it produces, the two
        // confusable spellings MUST collide so an attacker cannot register a
        // visually-identical "corp.com".
        let a = normalize_domain("c\u{43e}rp.com").expect("homoglyph normalizes");
        let b = normalize_domain("c\u{43e}rp.COM.").expect("homoglyph normalizes");
        assert_eq!(a, b, "homoglyph case/dot variants collide");
        // And the homoglyph is DISTINCT from the genuine ASCII corp.com (it is a
        // different registrable name — the defense is that they don't silently
        // merge, AND the operator can't be tricked by the rendering).
        let ascii = normalize_domain("corp.com").unwrap();
        assert_ne!(a, ascii, "the Cyrillic homoglyph is a distinct name from ASCII corp.com");
    }

    /// SSO-05 boundary: a sub-domain reduces to its registered domain, but a
    /// look-alike that appends the victim domain as a sub-label of an attacker
    /// domain does NOT collide.
    #[test]
    fn registered_domain_boundary() {
        // sub-domains reduce to the registered domain (collide with it).
        assert_collides("sub.corp.com", "corp.com");
        assert_collides("a.b.c.corp.com", "corp.com");
        // the classic spoof: corp.com.attacker.com is attacker.com's territory.
        assert_distinct("corp.com.attacker.com", "corp.com");
        let spoof = normalize_domain("corp.com.attacker.com").unwrap();
        assert_eq!(spoof, "attacker.com", "the spoof reduces to attacker.com");
    }

    /// Multi-label public suffixes (co.uk) are respected — the registered domain
    /// is `foo.co.uk`, not `co.uk`. This is the capability the zero-dep fallback
    /// would have lost (RESEARCH A3); `psl` gets it right.
    #[test]
    fn multi_label_tld_boundary() {
        assert_eq!(normalize_domain("foo.co.uk").unwrap(), "foo.co.uk");
        assert_eq!(normalize_domain("mail.foo.co.uk").unwrap(), "foo.co.uk");
        assert_collides("mail.foo.co.uk", "foo.co.uk");
        // a DIFFERENT registrable name under the same multi-label suffix is distinct.
        assert_distinct("foo.co.uk", "bar.co.uk");
    }

    /// Empty / structurally-invalid input is a value-free 400 (never a stored key).
    #[test]
    fn invalid_input_is_rejected() {
        for bad in [
            "",
            "   ",
            ".",
            "..",
            "com",              // bare public suffix (no registrable label)
            "localhost",        // single label, not registrable
            "corp.com/evil",    // path component
            "user@corp.com",    // userinfo / email, not a bare domain
            "corp.com:8080",    // port
            "http://corp.com",  // scheme
            "corp .com",        // embedded whitespace
            "192.168.0.1",      // IP literal, not a domain
        ] {
            assert!(
                normalize_domain(bad).is_err(),
                "{bad:?} must be rejected as invalid"
            );
        }
    }

    /// The normalized output never carries case, a trailing dot, or surrounding
    /// whitespace — it is the canonical key the unique index stores.
    #[test]
    fn output_is_canonical() {
        let n = normalize_domain("  Sub.CORP.Com.  ").unwrap();
        assert_eq!(n, "corp.com");
        assert!(!n.ends_with('.'));
        assert_eq!(n, n.to_lowercase());
        assert_eq!(n.trim(), n);
    }
}
