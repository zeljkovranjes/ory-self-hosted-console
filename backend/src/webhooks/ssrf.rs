//! SSRF guard for outbound webhook delivery (HOOK-02) — the security headline.
//!
//! Webhook URLs are OPERATOR INPUT crossing the highest-risk trust boundary
//! (backend → operator receiver). An attacker who controls a webhook config can
//! try to steer a delivery at an internal service (Ory admin ports, the docker
//! bridge, cloud metadata at 169.254.169.254). This module:
//!
//!   1. [`is_blocked_ip`] — classifies a RESOLVED IP as private/loopback/
//!      link-local/ULA/CGNAT/benchmarking/metadata/IPv4-mapped and rejects it.
//!   2. [`validate_url`] — at webhook CREATE: parse, require http(s), resolve the
//!      host, and reject (422) if ANY resolved IP is blocked (fast feedback).
//!   3. [`build_pinned_client`] — at DELIVERY time (authoritative, DNS-rebind
//!      defense): re-resolve, re-validate EVERY resolved IP, then PIN the request
//!      to the just-validated addresses (`resolve_to_addrs`) with redirects OFF
//!      (`Policy::none()`) and a bounded timeout, so resolution cannot change
//!      between the check and the connect (TOCTOU).
//!
//! CORRECTNESS (load-bearing): on STABLE Rust 1.95 `IpAddr::is_global()`,
//! `Ipv4Addr::is_shared()`, and `Ipv4Addr::is_benchmarking()` are NIGHTLY-ONLY
//! (feature `ip`, #27709) and WILL NOT COMPILE. This module uses ONLY stable
//! classifiers + a couple of manual octet ranges for the gaps (CGNAT 100.64/10,
//! benchmarking 198.18/15) and unwraps IPv4-mapped-IPv6 before re-checking.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use crate::error::AppError;

/// Operator-safe reject message — names the CATEGORY, never the resolved internal
/// IP/host (BACK-07: no internal-topology leak). Mirrors the UI-SPEC copy.
const SSRF_REJECT_MSG: &str =
    "This URL resolves to a private, loopback, link-local, or cloud-metadata address and is not allowed.";

/// Per-delivery outbound timeout (also caps a slow/huge receiver — T-11-08).
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(10);

/// Reject any IP that is not a routable PUBLIC address. Built ONLY from stable
/// std classifiers + explicit ranges for the gaps std doesn't cover on stable.
pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_v4(v4),
        IpAddr::V6(v6) => {
            // IPv4-mapped IPv6 (::ffff:a.b.c.d) MUST be unwrapped and re-checked,
            // or an attacker tunnels a private v4 through a v6 literal.
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_blocked_v4(mapped);
            }
            is_blocked_v6(v6)
        }
    }
}

fn is_blocked_v4(ip: Ipv4Addr) -> bool {
    ip.is_loopback()            // 127.0.0.0/8
        || ip.is_private()      // 10/8, 172.16/12, 192.168/16 (covers the docker bridge)
        || ip.is_link_local()   // 169.254.0.0/16 — INCLUDES 169.254.169.254 cloud metadata
        || ip.is_unspecified()  // 0.0.0.0
        || ip.is_broadcast()    // 255.255.255.255
        || ip.is_multicast()    // 224/4
        || ip.is_documentation()// 192.0.2/24, 198.51.100/24, 203.0.113/24
        // --- gaps std doesn't classify on STABLE 1.95 ---
        || is_shared_cgnat(ip)  // 100.64.0.0/10 (RFC 6598) — is_shared() is nightly-only
        || is_benchmarking_v4(ip) // 198.18.0.0/15 (RFC 2544) — is_benchmarking() nightly-only
}

/// 100.64.0.0/10 (RFC 6598 carrier-grade NAT). Manual because `is_shared()` is
/// nightly-only on stable 1.95.
fn is_shared_cgnat(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (o[1] & 0xC0) == 64
}

/// 198.18.0.0/15 (RFC 2544 benchmarking). Manual because `is_benchmarking()` is
/// nightly-only on stable 1.95.
fn is_benchmarking_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 198 && (o[1] == 18 || o[1] == 19)
}

fn is_blocked_v6(ip: Ipv6Addr) -> bool {
    ip.is_loopback()                  // ::1
        || ip.is_unspecified()        // ::
        || ip.is_unique_local()       // fc00::/7 (ULA)
        || ip.is_unicast_link_local() // fe80::/10
        || ip.is_multicast() // ff00::/8
}

/// Parse + resolve a webhook URL and reject if any resolved IP is blocked.
///
/// Used at webhook CREATE for fast 422 feedback. The delivery-time worker MUST
/// re-validate via [`build_pinned_client`] regardless — create-time validation is
/// NOT authoritative against DNS rebinding.
pub async fn validate_url(url: &str) -> Result<(), AppError> {
    let (host, port) = parse_host_port(url)?;
    let addrs = resolve(&host, port).await?;
    for sa in &addrs {
        if is_blocked_ip(sa.ip()) {
            return Err(AppError::BadRequest(SSRF_REJECT_MSG.to_string()));
        }
    }
    Ok(())
}

/// DELIVERY-TIME guard: resolve, validate EVERY resolved IP, then build a reqwest
/// client PINNED to those addresses with redirects OFF. Returns the client and
/// the validated socket addrs (for diagnostics). A blocked IP is an explicit
/// reject — never a silent no-op.
///
/// `allow_private` is the TEST/CI escape hatch: production callers (the worker
/// spawned from `main.rs`) pass `false`, fully enforcing the classifier. ONLY the
/// integration-test harness and the live phase-11 acceptance gate — whose
/// receivers run on loopback (`mockito`) or the internal docker network — pass
/// `true`. It relaxes ONLY the public/private classification; the DNS-resolve +
/// `resolve_to_addrs` PIN (TOCTOU defense) and redirects-off Policy STILL apply,
/// so even in the relaxed mode the connection cannot be rebound or bounced.
pub async fn build_pinned_client(
    url: &str,
    allow_private: bool,
) -> Result<(reqwest::Client, Vec<SocketAddr>), AppError> {
    let (host, port) = parse_host_port(url)?;
    let addrs = resolve(&host, port).await?;
    for sa in &addrs {
        if !allow_private && is_blocked_ip(sa.ip()) {
            return Err(AppError::BadRequest(SSRF_REJECT_MSG.to_string()));
        }
    }
    // Pin: resolve THIS host to ONLY the just-validated addresses so DNS cannot
    // rebind between the check above and the connect (TOCTOU). Redirects OFF so a
    // 3xx Location to an internal target is never followed (recorded as non-2xx).
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(&host, &addrs)
        .timeout(DELIVERY_TIMEOUT)
        .build()
        .map_err(|e| AppError::Internal(format!("build pinned webhook client: {e}")))?;
    Ok((client, addrs))
}

/// Parse the URL, require an http/https scheme, and extract (host, port).
fn parse_host_port(url: &str) -> Result<(String, u16), AppError> {
    let parsed = url::Url::parse(url)
        .map_err(|_| AppError::BadRequest("Webhook URL is not a valid URL.".to_string()))?;
    match parsed.scheme() {
        "http" | "https" => {}
        _ => {
            return Err(AppError::BadRequest(
                "Webhook URL must use http or https.".to_string(),
            ))
        }
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| AppError::BadRequest("Webhook URL has no host.".to_string()))?
        .to_string();
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| AppError::BadRequest("Webhook URL has no port.".to_string()))?;
    Ok((host, port))
}

/// Resolve all A/AAAA records for (host, port). An unresolvable or empty result
/// is a reject (operator-safe message), never a silent pass.
async fn resolve(host: &str, port: u16) -> Result<Vec<SocketAddr>, AppError> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| AppError::BadRequest("Webhook host could not be resolved.".to_string()))?
        .collect();
    if addrs.is_empty() {
        return Err(AppError::BadRequest(
            "Webhook host could not be resolved.".to_string(),
        ));
    }
    Ok(addrs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Table-driven: every forbidden range MUST be rejected; public IPs allowed.
    #[test]
    fn is_blocked_ip_rejects_every_forbidden_range() {
        // (label, ip, expected_blocked)
        let cases: &[(&str, IpAddr, bool)] = &[
            ("loopback v4", IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), true),
            ("private 10/8", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), true),
            ("private 172.16/12", IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), true),
            ("private 192.168/16", IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), true),
            ("cloud metadata", IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)), true),
            ("link-local v4", IpAddr::V4(Ipv4Addr::new(169, 254, 0, 1)), true),
            ("unspecified v4", IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), true),
            ("broadcast", IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)), true),
            ("multicast v4", IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)), true),
            ("documentation", IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), true),
            ("CGNAT 100.64/10", IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)), true),
            ("CGNAT 100.127", IpAddr::V4(Ipv4Addr::new(100, 127, 255, 254)), true),
            ("benchmarking 198.18", IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)), true),
            ("benchmarking 198.19", IpAddr::V4(Ipv4Addr::new(198, 19, 0, 1)), true),
            ("loopback v6", IpAddr::V6(Ipv6Addr::LOCALHOST), true),
            ("unspecified v6", IpAddr::V6(Ipv6Addr::UNSPECIFIED), true),
            ("ULA fc00::/7", IpAddr::V6("fc00::1".parse().unwrap()), true),
            ("link-local fe80::/10", IpAddr::V6("fe80::1".parse().unwrap()), true),
            ("multicast v6", IpAddr::V6("ff00::1".parse().unwrap()), true),
            (
                "ipv4-mapped loopback",
                IpAddr::V6("::ffff:127.0.0.1".parse().unwrap()),
                true,
            ),
            (
                "ipv4-mapped metadata",
                IpAddr::V6("::ffff:169.254.169.254".parse().unwrap()),
                true,
            ),
            // --- allowed (public) ---
            ("public v4 8.8.8.8", IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), false),
            ("public v4 1.1.1.1", IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), false),
            (
                "public v6 google",
                IpAddr::V6("2001:4860:4860::8888".parse().unwrap()),
                false,
            ),
            (
                "ipv4-mapped public",
                IpAddr::V6("::ffff:8.8.8.8".parse().unwrap()),
                false,
            ),
        ];

        for (label, ip, expected) in cases {
            assert_eq!(
                is_blocked_ip(*ip),
                *expected,
                "is_blocked_ip mismatch for {label} ({ip})"
            );
        }
    }

    #[tokio::test]
    async fn validate_url_rejects_loopback_literal() {
        let err = validate_url("http://127.0.0.1/hook").await.unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)));
    }

    #[tokio::test]
    async fn validate_url_rejects_metadata_literal() {
        let err = validate_url("http://169.254.169.254/latest/meta-data")
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)));
    }

    #[tokio::test]
    async fn validate_url_rejects_non_http_scheme() {
        let err = validate_url("ftp://example.com/hook").await.unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)));
    }

    #[tokio::test]
    async fn validate_url_rejects_garbage() {
        let err = validate_url("not a url").await.unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)));
    }
}
