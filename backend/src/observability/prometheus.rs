//! Parameterized PromQL query passthrough for the Activity dashboard (OBS-03).
//!
//! THE injection-defense (T-16-09 / Security V5): the frontend NEVER sends a raw
//! PromQL string. It selects a CLOSED dashboard INTENT (`login-rate`,
//! `signup-rate`, `login-latency`) plus a bounded time range; the backend builds
//! the actual PromQL `query`/`query_range` from that intent. An unknown intent is
//! rejected `422` BEFORE any upstream call — there is no path by which operator
//! text reaches Prometheus's query parser.
//!
//! This replaces the ACT-03 derived stub as the LIVE Activity surface (OBS-03):
//! `get_metrics_activity` probe-FIRST (FLAG-04) — flag-ON + profile-running →
//! Prometheus-derived series; flag-ON + profile-DOWN → the structured
//! `profile_not_running` 200 payload, NEVER a raw 502.
//!
//! Uses the backend reqwest-0.13 transport against the FIXED `Config`
//! `prometheus_url` (never client input — no SSRF surface), mirroring the
//! `ory::fallback` isolation invariant.

use salvo::prelude::*;
use serde::Serialize;

use crate::config::Config;
use crate::error::AppError;
use crate::observability::probe::{probe_profile, ProfileState};

/// The short query timeout for an Activity range query (kept tight so a slow
/// Prometheus does not hang the console request behind it).
const QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);

/// Default look-back window (seconds) for a range query when the client does not
/// pin one — one hour of the Activity series.
const DEFAULT_RANGE_SECS: i64 = 3600;
/// The hard CAP on the look-back window (seconds) — 7 days. A client-supplied
/// range beyond this is clamped (bounds the query cost; no unbounded scans).
const MAX_RANGE_SECS: i64 = 604_800;
/// Default step (seconds) between range-query data points.
const DEFAULT_STEP_SECS: i64 = 60;
/// Minimum step (seconds) — clamps a tiny step that would explode the point count.
const MIN_STEP_SECS: i64 = 15;

/// The closed set of Activity dashboard intents → the server-built PromQL.
///
/// Each arm returns a FIXED PromQL expression built ENTIRELY from constants —
/// there is NO interpolation of any client value into the query string (the only
/// client-influenced values are the numeric time range/step, threaded as
/// separate, integer-validated query params). An unknown intent returns `None`
/// (the handler maps that to 422).
fn promql_for_intent(intent: &str) -> Option<&'static str> {
    match intent {
        // Console login attempts per second, split by result (success/failure),
        // averaged over 5m — the primary Activity signal from the backend's own
        // `console_login_attempts_total{result}` counter (Phase-16 metrics/mod.rs).
        "login-rate" => Some("sum by (result) (rate(console_login_attempts_total[5m]))"),
        // Console setup completions per second (the `console_setup_completions_total`
        // counter) — a low-frequency but meaningful onboarding signal.
        "signup-rate" => Some("sum(rate(console_setup_completions_total[5m]))"),
        // Backend HTTP request latency: the 95th percentile over the Salvo request
        // histogram exposed on /metrics (counts/buckets only). Aggregated across
        // all routes (no per-identity label — T-16-04).
        "login-latency" => Some(
            "histogram_quantile(0.95, sum by (le) (rate(http_request_duration_seconds_bucket[5m])))",
        ),
        _ => None,
    }
}

/// The Activity response envelope. `source` is `"prometheus"` (distinguishing it
/// from the retired ACT-03 `"derived"` stub) so the frontend knows the series is
/// metric-backed (OBS-03). When the profile is down, `state` carries the tolerant
/// `profile_not_running` and `result` is `None`.
#[derive(Debug, Clone, Serialize)]
pub struct MetricsActivity {
    /// Always `"prometheus"` for this route (vs the retired `"derived"` stub).
    pub source: &'static str,
    /// The profile health state (`running` | `profile_not_running`) — FLAG-04.
    pub state: &'static str,
    /// The selected intent (echoed back for the frontend).
    pub intent: String,
    /// The raw Prometheus `data` object on success, `None` when the profile is
    /// down. Passed through as generic JSON — the backend never reshapes the
    /// metric body, and it carries counts/buckets only (no per-identity label).
    pub result: Option<serde_json::Value>,
}

/// Validate + clamp an optional integer query param to `[min, max]`, falling
/// back to `default` when absent. A non-integer value is a client error (`422`).
fn clamp_param(
    raw: Option<String>,
    default: i64,
    min: i64,
    max: i64,
) -> Result<i64, AppError> {
    match raw.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(default),
        Some(s) => {
            let v: i64 = s
                .parse()
                .map_err(|_| AppError::BadRequest("range/step must be an integer".into()))?;
            Ok(v.clamp(min, max))
        }
    }
}

/// `GET /api/console/metrics/activity?intent=&range=&step=` — the Prometheus-
/// backed Activity series (OBS-03).
///
/// Mounted behind `FeatureFlagHoop::new("observability")` (404 when OFF). Inside
/// the handler it is probe-FIRST (FLAG-04): if the profile is DOWN it returns the
/// structured `profile_not_running` 200 payload, NEVER a raw 502. An unknown
/// `intent` is rejected 422 (no raw PromQL passthrough — T-16-09).
#[handler]
pub async fn get_metrics_activity(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<MetricsActivity>, AppError> {
    let cfg = obtain_cfg(depot)?;

    // CLOSED-intent validation FIRST — reject an unknown intent before any
    // upstream call (default to login-rate when omitted).
    let intent = req
        .query::<String>("intent")
        .unwrap_or_else(|| "login-rate".to_string());
    let promql = promql_for_intent(&intent)
        .ok_or_else(|| AppError::BadRequest(format!("unknown activity intent: {intent}")))?;

    // Numeric range/step — integer-validated + clamped. These are the ONLY
    // client-influenced values, and they never touch the PromQL string itself.
    let range_secs = clamp_param(req.query::<String>("range"), DEFAULT_RANGE_SECS, MIN_STEP_SECS, MAX_RANGE_SECS)?;
    let step_secs = clamp_param(req.query::<String>("step"), DEFAULT_STEP_SECS, MIN_STEP_SECS, MAX_RANGE_SECS)?;

    // Probe FIRST (FLAG-04): a down profile is a CLEAN state, never a 502.
    let state = probe_profile(&cfg).await;
    if !state.is_running() {
        return Ok(Json(not_running(&intent, &state)));
    }

    // Profile is up — run the server-built range query.
    let result = query_range(&cfg, promql, range_secs, step_secs).await;
    match result {
        Ok(data) => Ok(Json(MetricsActivity {
            source: "prometheus",
            state: "running",
            intent,
            result: Some(data),
        })),
        // A query failure AFTER a healthy probe is a transient upstream blip; keep
        // the tolerant contract (FLAG-04) — surface profile_not_running rather than
        // a raw 502 so the Activity page degrades cleanly.
        Err(_) => Ok(Json(not_running(&intent, &state))),
    }
}

/// Build the tolerant `profile_not_running` envelope (no upstream detail leaked).
fn not_running(intent: &str, _state: &ProfileState) -> MetricsActivity {
    MetricsActivity {
        source: "prometheus",
        state: "profile_not_running",
        intent: intent.to_string(),
        result: None,
    }
}

/// Issue a PromQL `query_range` against `{prometheus_url}/api/v1/query_range`.
///
/// The `query` is the SERVER-BUILT constant PromQL; `start`/`end`/`step` are the
/// integer-validated range. Returns the raw Prometheus `data` object as generic
/// JSON on success; any transport/non-2xx/decode failure is `Err` (the caller
/// folds it into `profile_not_running`, never leaking the upstream body/URL).
async fn query_range(
    cfg: &Config,
    promql: &str,
    range_secs: i64,
    step_secs: i64,
) -> Result<serde_json::Value, AppError> {
    let client = reqwest::Client::builder()
        .timeout(QUERY_TIMEOUT)
        .build()
        .map_err(|e| AppError::Internal(format!("build prometheus client: {e}")))?;

    let now = unix_now();
    let start = now - range_secs;

    // Build the query string with percent-encoded values (the reqwest 0.13
    // `query` feature is not enabled — we encode manually). `promql` is a
    // server-built constant; the numerics are validated i64s.
    let url = format!(
        "{}/api/v1/query_range?query={}&start={}&end={}&step={}",
        cfg.prometheus_url.trim_end_matches('/'),
        urlencode(promql),
        start,
        now,
        step_secs
    );

    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "prometheus query transport error");
            AppError::Upstream("prometheus unreachable".into())
        })?;

    let status = resp.status();
    if !status.is_success() {
        tracing::warn!(status = %status, "prometheus query returned error status");
        return Err(AppError::Upstream(format!("prometheus status {status}")));
    }

    // Prometheus responds `{"status":"success","data":{...}}`. Pull out `data`
    // (counts/buckets only); a decode failure is an upstream problem, never a leak.
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "prometheus query decode error");
            AppError::Upstream("prometheus decode error".into())
        })?;
    Ok(body.get("data").cloned().unwrap_or(body))
}

/// Percent-encode a query-string VALUE (RFC 3986 unreserved chars pass through;
/// everything else is `%XX`). Used for the server-built PromQL — belt-and-
/// suspenders since the value is a known constant, but it keeps the URL valid
/// regardless of the PromQL's special characters.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
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

/// Current UNIX time in whole seconds.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Obtain the injected [`Config`] from the Depot (cloned).
fn obtain_cfg(depot: &mut Depot) -> Result<Config, AppError> {
    Ok(depot
        .obtain::<Config>()
        .map_err(|_| AppError::Internal("config missing from depot".into()))?
        .clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The closed intent set maps known intents to a FIXED PromQL and rejects
    /// anything else (the 422 path) — proving no raw operator query can pass.
    #[test]
    fn intent_allowlist_is_closed() {
        assert!(promql_for_intent("login-rate").is_some());
        assert!(promql_for_intent("signup-rate").is_some());
        assert!(promql_for_intent("login-latency").is_some());
        // A raw PromQL string is NOT a known intent → None → 422.
        assert!(promql_for_intent("up{job=\"kratos\"}").is_none());
        assert!(promql_for_intent("__proto__").is_none());
        assert!(promql_for_intent("").is_none());
    }

    /// The built PromQL contains NO client-controlled substring — it is a
    /// constant. (Sanity: the known intents reference only fixed metric names.)
    #[test]
    fn promql_is_constant_not_interpolated() {
        let q = promql_for_intent("login-rate").unwrap();
        assert!(q.contains("console_login_attempts_total"));
        assert!(!q.contains("{intent}") && !q.contains("{{"));
    }

    /// range/step params: absent → default; integer → clamped to bounds;
    /// non-integer → 422 (BadRequest). This guards the only client-influenced
    /// values from becoming an unbounded/garbage query.
    #[test]
    fn clamp_param_validates_and_bounds() {
        // Absent → default.
        assert_eq!(
            clamp_param(None, DEFAULT_RANGE_SECS, MIN_STEP_SECS, MAX_RANGE_SECS).unwrap(),
            DEFAULT_RANGE_SECS
        );
        // In-range integer → passed through.
        assert_eq!(
            clamp_param(Some("3600".into()), DEFAULT_RANGE_SECS, MIN_STEP_SECS, MAX_RANGE_SECS)
                .unwrap(),
            3600
        );
        // Above max → clamped to max.
        assert_eq!(
            clamp_param(Some("99999999".into()), DEFAULT_RANGE_SECS, MIN_STEP_SECS, MAX_RANGE_SECS)
                .unwrap(),
            MAX_RANGE_SECS
        );
        // Below min → clamped to min.
        assert_eq!(
            clamp_param(Some("1".into()), DEFAULT_RANGE_SECS, MIN_STEP_SECS, MAX_RANGE_SECS).unwrap(),
            MIN_STEP_SECS
        );
        // Non-integer → 422.
        let err = clamp_param(Some("abc".into()), DEFAULT_RANGE_SECS, MIN_STEP_SECS, MAX_RANGE_SECS)
            .unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)), "got {err:?}");
    }
}
