//! ISOLATED reqwest-0.13 fallback for Ory Admin endpoints NO typed crate covers.
//!
//! # Why this module exists (and why it is deliberately separated)
//!
//! The four per-service Ory crates (`ory-{kratos,hydra,keto,oathkeeper}-client`)
//! are the PRIMARY Admin clients and cover almost everything. A small set of
//! self-hosted concerns has no typed-crate surface — e.g. Keto namespace/OPL
//! definitions and Oathkeeper rule AUTHORING are file-based, and an occasional
//! Admin route can lag the generated crate. For those gaps (wired in later
//! phases as they arise) the backend falls back to raw HTTP with hand-mirrored
//! serde structs.
//!
//! ## Isolation invariant (auditability + the reqwest 0.12/0.13 split)
//!
//! The Ory crates depend on **reqwest ^0.12**; the backend pins **reqwest 0.13**
//! (a DISTINCT, non-interchangeable major — RESEARCH Pitfall 1). This module
//! uses the backend's **reqwest 0.13** transport and is kept STRICTLY isolated:
//!
//! - It MUST NOT import any Ory crate's generated client module (typed clients
//!   live elsewhere). It may read fixed base URLs from `Config`, but it never
//!   touches the generated `Configuration`/client types — that contains the
//!   0.12/0.13 split to one side of the codebase.
//! - The typed handlers (`kratos`/`hydra`/`keto`/`oathkeeper`) MUST NOT import
//!   this module — the two paths never mix.
//!
//! ## Uniform error envelope
//!
//! A fallback failure maps to the SAME [`AppError::Upstream`] (HTTP 502,
//! detail-free body) the typed path uses via [`map_fallback_err`], so the
//! frontend sees an identical error shape regardless of which transport served
//! the request (BACK-07 — the raw upstream body / admin URL is never returned).
//!
//! Hand-mirrored serde structs are acceptable ONLY here and ONLY for uncovered
//! endpoints (RESEARCH "Don't Hand-Roll"): everything a crate covers MUST go
//! through that crate's generated `models`/client modules.

use serde::Deserialize;

use crate::error::AppError;

/// Map any backend-reqwest (0.13) failure from a fallback call into the shared
/// [`AppError::Upstream`] (502) envelope. The cause is logged server-side at
/// `warn`; the client receives only the generic `upstream_error` machine code —
/// the upstream body, admin URL, and any credential never leave the process
/// (BACK-07). This mirrors what `ory::error::map_*_err` does for the typed path,
/// WITHOUT importing the Ory crates' generated `Error<T>` type.
pub fn map_fallback_err(err: reqwest::Error) -> AppError {
    tracing::warn!(error = %err, "ory fallback transport error");
    AppError::Upstream("ory upstream unreachable".into())
}

/// Map a non-2xx fallback response to the shared [`AppError::Upstream`] (502).
/// Only the status is logged server-side; the raw body is never read into the
/// returned error (BACK-07).
pub fn map_fallback_status(status: reqwest::StatusCode) -> AppError {
    tracing::warn!(status = %status, "ory fallback returned error status");
    AppError::Upstream(format!("ory upstream status {status}"))
}

/// Build the backend's reqwest **0.13** client used by every fallback call.
///
/// Distinct from the reqwest 0.12 client each Ory `Configuration` owns
/// (RESEARCH Pitfall 1) — the two majors never share an instance. A short
/// connect/request timeout keeps a stuck upstream from hanging a handler.
pub fn fallback_client() -> Result<reqwest::Client, AppError> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| AppError::Internal(format!("build fallback http client: {e}")))
}

/// Example hand-mirrored response struct for a gap endpoint.
///
/// This is the ONE documented example of the fallback pattern: a minimal,
/// hand-written serde mirror of an upstream JSON shape (here, a service version
/// probe — `{"version":"..."}`). Real gap endpoints (Keto OPL/namespace config,
/// Oathkeeper rule authoring, any lagging Admin route) add their own mirrors
/// here as they are wired in later phases. We hand-mirror ONLY because no typed
/// crate covers the endpoint — anything a crate covers goes through the crate.
#[derive(Debug, Deserialize)]
pub struct FallbackVersion {
    /// The upstream-reported service version string.
    pub version: String,
}

/// Documented EXAMPLE fallback call demonstrating the full pattern end-to-end:
/// backend reqwest 0.13 -> hand-mirrored struct -> shared `AppError::Upstream`
/// envelope. It is NOT mounted on any route yet (no gap endpoint needs wiring in
/// this phase) — it exists to establish and exercise the pattern, and is covered
/// by the unit test below.
///
/// `base_url` is a FIXED internal Admin URL from `Config` (never user input — no
/// SSRF surface; RESEARCH Security Domain V10). The path is appended by the
/// caller; here we probe `{base_url}/version`.
pub async fn fetch_version(
    client: &reqwest::Client,
    base_url: &str,
) -> Result<FallbackVersion, AppError> {
    let url = format!("{}/version", base_url.trim_end_matches('/'));
    let resp = client.get(url).send().await.map_err(map_fallback_err)?;

    let status = resp.status();
    if !status.is_success() {
        return Err(map_fallback_status(status));
    }

    // Decode into the hand-mirrored struct; a decode failure is still an
    // upstream problem -> 502, never a body leak.
    resp.json::<FallbackVersion>().await.map_err(map_fallback_err)
}

/// Parse the `page_token` query value of the `rel="next"` entry from a Kratos
/// `Link` response header (RFC 8288 web-linking), returning `None` when there is
/// no next page.
///
/// Kratos paginates the Admin identity list with KEYSET cursors (RESEARCH
/// Pitfall 3): the typed `identity_api::list_identities` returns only the body
/// `Vec<Identity>` and DROPS the response headers, so the forward cursor is
/// unreachable through the crate. This isolated reqwest-0.13 wrapper exists to
/// read that header for the list endpoint ONLY (RESEARCH Open Q1 / the one
/// justified fallback use). The header looks like:
///
/// ```text
/// Link: </admin/identities?page_size=50&page_token=abc>; rel="next",
///       </admin/identities?page_size=50&page_token=def>; rel="first"
/// ```
///
/// We extract the `page_token` query param of the `rel="next"` URL. A token-free
/// or absent `next` link yields `None` (the operator is on the last page —
/// "fewer items than the page size" is the other last-page signal).
pub fn parse_next_page_token(link_header: &str) -> Option<String> {
    // Each comma-separated section is `<url>; rel="name"` (params may carry their
    // own commas inside the URL query, but Kratos uses `&` there, so a simple
    // split on `,` between sections is safe for this upstream).
    for section in link_header.split(',') {
        let section = section.trim();
        // Must be the forward cursor.
        if !section.contains("rel=\"next\"") && !section.contains("rel=next") {
            continue;
        }
        // Pull the `<...>` URL-reference and read its `page_token` query value.
        let start = section.find('<')?;
        let end = section[start + 1..].find('>')? + start + 1;
        let url_ref = &section[start + 1..end];
        // The URL-reference is relative (`/admin/identities?...`); a query parse
        // only needs the part after `?`.
        let query = url_ref.split_once('?').map(|(_, q)| q).unwrap_or("");
        for pair in query.split('&') {
            if let Some(tok) = pair.strip_prefix("page_token=") {
                if !tok.is_empty() {
                    return Some(tok.to_string());
                }
            }
        }
    }
    None
}

/// List Kratos identities for ONE keyset page, returning the raw identity JSON
/// objects plus the `page_token` cursor for the NEXT page (`None` on the last
/// page).
///
/// This is the single justified reqwest-0.13 fallback (RESEARCH Open Q1): the
/// typed `list_identities` drops the `Link` header that carries the keyset
/// cursor. We GET `{base_url}/admin/identities?page_size=&page_token=` and parse
/// the header. The identities are returned as `serde_json::Value` (NOT the Ory
/// `Identity` type) to preserve this module's isolation invariant — the typed
/// handler in `kratos.rs` shapes them (stripping credential secrets) before they
/// reach the client.
///
/// `base_url` is the FIXED internal Kratos Admin URL from `Config` (never user
/// input — no SSRF surface, RESEARCH Security Domain). `credentials_identifier`
/// is the OPTIONAL Users-list search term (an exact-match credential-identifier
/// filter Kratos supports); it is user input, so it is percent-encoded into the
/// query (never trusted verbatim) and an empty value is treated as no filter. On
/// any non-2xx or transport/decode failure the shared [`AppError::Upstream`]
/// (502) envelope is returned with NO upstream body/host leaked (BACK-07).
///
/// The query string is assembled by the pure [`build_list_url`] helper so the
/// param-threading (page_size / page_token / `credentials_identifier`) is unit-
/// testable WITHOUT a live Kratos (WR-01).
pub async fn list_identities_paged(
    client: &reqwest::Client,
    base_url: &str,
    page_size: i64,
    page_token: Option<&str>,
    credentials_identifier: Option<&str>,
) -> Result<(Vec<serde_json::Value>, Option<String>), AppError> {
    let url = build_list_url(base_url, page_size, page_token, credentials_identifier);

    let resp = client.get(url).send().await.map_err(map_fallback_err)?;
    let status = resp.status();
    if !status.is_success() {
        return Err(map_fallback_status(status));
    }

    // Read the next-page cursor from the Link header BEFORE consuming the body.
    let next_token = resp
        .headers()
        .get(reqwest::header::LINK)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_next_page_token);

    // Decode the body as a generic JSON array of identity objects. A decode
    // failure is still an upstream problem -> 502, never a body leak.
    let body: serde_json::Value = resp.json().await.map_err(map_fallback_err)?;
    let rows = body
        .as_array()
        .cloned()
        .ok_or_else(|| AppError::Upstream("ory upstream returned a non-array list".into()))?;

    Ok((rows, next_token))
}

/// Build the Kratos `GET /admin/identities` URL with the page_size, an optional
/// opaque keyset `page_token` cursor, and an optional `credentials_identifier`
/// search filter (WR-01). Both optional values are percent-encoded; an empty
/// `credentials_identifier` is omitted entirely (no filter). Pure — no IO — so
/// the param threading is unit-testable without a live Kratos.
fn build_list_url(
    base_url: &str,
    page_size: i64,
    page_token: Option<&str>,
    credentials_identifier: Option<&str>,
) -> String {
    let mut url = format!(
        "{}/admin/identities?page_size={}",
        base_url.trim_end_matches('/'),
        page_size
    );
    if let Some(tok) = page_token {
        // page_token is an opaque Kratos cursor; percent-encode to be safe.
        url.push_str("&page_token=");
        url.push_str(&urlencode(tok));
    }
    // IDENT-01 / WR-01: the Kratos Admin `GET /admin/identities` endpoint
    // supports a `credentials_identifier` filter (exact-match on a credential
    // identifier, e.g. an email/username). When the operator types in the
    // Users-list search box the frontend forwards the term here; thread it to
    // Kratos (percent-encoded — it is user input, never trusted into the URL
    // verbatim). An empty term is treated as no filter.
    if let Some(ident) = credentials_identifier {
        if !ident.is_empty() {
            url.push_str("&credentials_identifier=");
            url.push_str(&urlencode(ident));
        }
    }
    url
}

/// Minimal percent-encoding for an opaque page-token cursor placed in a query
/// string. Encodes the characters that are unsafe in a query value; the Kratos
/// token alphabet is URL-safe in practice, this is belt-and-suspenders.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AppError;
    use salvo::http::StatusCode as SalvoStatus;

    /// The `rel="next"` `page_token` is extracted from a realistic Link header.
    #[test]
    fn next_token_extracted_from_link_header() {
        let header = "</admin/identities?page_token=abc&page_size=50>; rel=\"next\"";
        assert_eq!(parse_next_page_token(header), Some("abc".to_string()));
    }

    /// A multi-rel header still picks the `next` token (not first/prev).
    #[test]
    fn next_token_picks_next_among_many_rels() {
        let header = "</admin/identities?page_token=first0&page_size=50>; rel=\"first\", \
                      </admin/identities?page_token=nexttok&page_size=50>; rel=\"next\", \
                      </admin/identities?page_token=prev0&page_size=50>; rel=\"prev\"";
        assert_eq!(parse_next_page_token(header), Some("nexttok".to_string()));
    }

    /// No `rel="next"` => no further page => None (last-page signal).
    #[test]
    fn no_next_rel_is_none() {
        let header = "</admin/identities?page_size=50>; rel=\"first\"";
        assert_eq!(parse_next_page_token(header), None);
    }

    /// An empty header string yields None (absent cursor).
    #[test]
    fn empty_header_is_none() {
        assert_eq!(parse_next_page_token(""), None);
    }

    /// A transport-level reqwest error maps to the SAME `Upstream` (502) envelope
    /// the typed path produces, with no body/URL leak — proving the fallback
    /// shares the error contract (Criterion 3).
    #[tokio::test]
    async fn unreachable_host_maps_to_upstream() {
        let client = fallback_client().expect("build fallback client");
        // RFC 5737 TEST-NET-1, no listener — guaranteed connect failure fast.
        let err = fetch_version(&client, "http://192.0.2.1:9").await.unwrap_err();
        assert!(matches!(err, AppError::Upstream(_)), "got {err:?}");
        assert_eq!(err.status_code(), SalvoStatus::BAD_GATEWAY);
        assert_eq!(err.machine_code(), "upstream_error");
    }

    /// WR-01: the search filter is threaded into the Kratos list URL,
    /// percent-encoded, and an empty filter is omitted entirely.
    #[test]
    fn build_list_url_threads_credentials_identifier() {
        let base = "http://kratos:4434";

        // No filter, no token: just page_size.
        let url = build_list_url(base, 20, None, None);
        assert_eq!(url, "http://kratos:4434/admin/identities?page_size=20");

        // A search term is appended, percent-encoded (the `@` becomes %40).
        let url = build_list_url(base, 20, None, Some("a@example.com"));
        assert!(
            url.contains("&credentials_identifier=a%40example.com"),
            "search term must reach Kratos percent-encoded; got {url}"
        );

        // An empty term is treated as NO filter (does not advertise an inert box).
        let url = build_list_url(base, 20, None, Some(""));
        assert!(
            !url.contains("credentials_identifier"),
            "an empty filter must be omitted; got {url}"
        );

        // Token AND filter coexist.
        let url = build_list_url(base, 50, Some("tok123"), Some("bob"));
        assert!(url.contains("&page_token=tok123"), "token present; got {url}");
        assert!(
            url.contains("&credentials_identifier=bob"),
            "filter present alongside token; got {url}"
        );
    }

    /// A non-2xx status maps to `Upstream` carrying ONLY the status (log detail),
    /// never the upstream body (BACK-07).
    #[test]
    fn status_mapper_carries_status_not_body() {
        let err = map_fallback_status(reqwest::StatusCode::BAD_GATEWAY);
        assert!(matches!(err, AppError::Upstream(_)), "got {err:?}");
        assert!(err.to_string().contains("502"), "status in log detail: {err}");
    }
}
