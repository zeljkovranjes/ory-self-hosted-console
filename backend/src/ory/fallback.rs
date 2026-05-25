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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AppError;
    use salvo::http::StatusCode as SalvoStatus;

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

    /// A non-2xx status maps to `Upstream` carrying ONLY the status (log detail),
    /// never the upstream body (BACK-07).
    #[test]
    fn status_mapper_carries_status_not_body() {
        let err = map_fallback_status(reqwest::StatusCode::BAD_GATEWAY);
        assert!(matches!(err, AppError::Upstream(_)), "got {err:?}");
        assert!(err.to_string().contains("502"), "status in log detail: {err}");
    }
}
