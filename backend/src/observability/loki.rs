//! Parameterized LogQL query passthrough for the Logs & events search (OBS-04).
//!
//! Same injection-defense as the PromQL route (T-16-09 / Security V5): the
//! frontend selects a CLOSED LogQL INTENT (`all`, `errors`, by `service`) plus a
//! bounded time window + line limit — NEVER a raw LogQL string. The backend
//! builds the `{...}`-stream selector + filter from that intent; an unknown
//! intent is rejected `422` before any upstream call.
//!
//! The lines Loki returns were ALREADY PII-masked at ingestion by Alloy
//! (`loki.process` stage.replace — emails/tokens redacted) and carry only
//! low-cardinality labels (no identity/session IDs). The route still never echoes
//! a raw operator query string into the LogQL.
//!
//! Probe-FIRST (FLAG-04): flag-ON + profile-DOWN → the structured
//! `profile_not_running` 200 payload, NEVER a raw 502. Uses the backend
//! reqwest-0.13 transport against the FIXED `Config` `loki_url`.

use salvo::prelude::*;
use serde::Serialize;

use crate::config::Config;
use crate::error::AppError;
use crate::observability::probe::probe_profile;

/// Short query timeout (a slow Loki must not hang the console request).
const QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);

/// Default look-back window (seconds) for the log search — one hour.
const DEFAULT_RANGE_SECS: i64 = 3600;
/// Hard cap on the look-back window (seconds) — 7 days.
const MAX_RANGE_SECS: i64 = 604_800;
/// Default + max number of log lines returned (Loki `limit`). Bounded so a
/// search cannot pull an unbounded result set.
const DEFAULT_LIMIT: i64 = 100;
const MAX_LIMIT: i64 = 1000;

/// The closed set of log-search intents → the server-built LogQL stream selector.
///
/// The LogQL is built ENTIRELY from constants (a fixed stream selector + an
/// optional fixed line filter). For a per-`service` intent the service token is
/// validated against a CLOSED allowlist of known stack services — it is NEVER a
/// free-form client substring spliced into the query. An unknown intent/service
/// returns `None` (→ 422).
fn logql_for_intent(intent: &str, service: Option<&str>) -> Option<String> {
    match intent {
        // All ingested console-stack logs in the window.
        "all" => Some(r#"{job="docker"}"#.to_string()),
        // Error-level lines only (a fixed case-insensitive line filter).
        "errors" => Some(r#"{job="docker"} |~ "(?i)level=error|\"level\":\"error\"""#.to_string()),
        // Logs for ONE known service. WR-01: Alloy ships container logs by
        // FILE-TAILING the Docker json-file dir (BACK-05 forbids a second
        // docker-socket holder), and a json-file line carries ONLY
        // `{log,stream,time}` — there is NO container name in the line and only the
        // opaque container ID in the path, so Alloy CANNOT emit a per-service
        // STREAM label without the socket. A `{service="<svc>"}` selector therefore
        // matched zero streams (a permanently-dead "By service" tab). Instead we
        // keep the working `{job="docker"}` stream selector and add a LINE FILTER on
        // the service-name token. The `svc` value MUST be in the closed allowlist,
        // so the interpolated value is one of a FIXED set of `[a-z]+`-shaped
        // literals (never a free-form client substring) — no LogQL operator, quote,
        // or pipe can appear, preserving the injection-safety the closed allowlist
        // guarantees. The match is case-insensitive + word-boundary-anchored so a
        // line that names the service (the common case for the stack's structured
        // logs) is returned. The acceptance gate drives this path end-to-end
        // (phase16-acceptance.sh OBS-04 service assertion) so a regression FAILS.
        "service" => {
            let svc = service?;
            if !is_allowed_service(svc) {
                return None;
            }
            // NB: LogQL double-quoted string literals process Go escape sequences
            // BEFORE the RE2 engine sees the pattern, so a single `\b` would be
            // unescaped to a backspace (0x08) and match nothing. Emit `\\b` so the
            // literal yields `\b` for RE2 (a word boundary). Mirrors how the
            // `errors` intent escapes its embedded quotes.
            Some(format!(r#"{{job="docker"}} |~ "(?i)\\b{svc}\\b""#))
        }
        _ => None,
    }
}

/// CLOSED allowlist of known stack service label values. The `service` intent
/// interpolates the value into a LINE FILTER on `{job="docker"}` (WR-01: Alloy's
/// file-tail emits no per-service stream label), so only these fixed `[a-z]+`
/// literals can ever appear in the LogQL — any other value is rejected, which is
/// what makes the line filter injection-safe.
fn is_allowed_service(svc: &str) -> bool {
    matches!(
        svc,
        "kratos" | "hydra" | "keto" | "oathkeeper" | "backend" | "frontend" | "polis"
    )
}

/// The Logs response envelope (OBS-04). `state` carries the FLAG-04 health state;
/// `result` is the raw Loki `data` on success, `None` when the profile is down.
#[derive(Debug, Clone, Serialize)]
pub struct LogsResult {
    pub source: &'static str,
    pub state: &'static str,
    pub intent: String,
    pub result: Option<serde_json::Value>,
}

/// `GET /api/console/logs?intent=&service=&range=&limit=` — the Loki-backed log
/// search (OBS-04).
///
/// Mounted behind `FeatureFlagHoop::new("observability")` (404 when OFF). Inside:
/// closed-intent validation FIRST (unknown → 422, T-16-09), then probe-FIRST
/// (FLAG-04: down → `profile_not_running` 200, never a 502).
#[handler]
pub async fn get_logs(req: &mut Request, depot: &mut Depot) -> Result<Json<LogsResult>, AppError> {
    let cfg = obtain_cfg(depot)?;

    let intent = req
        .query::<String>("intent")
        .unwrap_or_else(|| "all".to_string());
    let service = req.query::<String>("service");
    let logql = logql_for_intent(&intent, service.as_deref())
        .ok_or_else(|| AppError::BadRequest(format!("unknown log intent: {intent}")))?;

    let range_secs = clamp_param(req.query::<String>("range"), DEFAULT_RANGE_SECS, 60, MAX_RANGE_SECS)?;
    let limit = clamp_param(req.query::<String>("limit"), DEFAULT_LIMIT, 1, MAX_LIMIT)?;

    let state = probe_profile(&cfg).await;
    if !state.is_running() {
        return Ok(Json(not_running(&intent)));
    }

    match query_range(&cfg, &logql, range_secs, limit).await {
        Ok(data) => Ok(Json(LogsResult {
            source: "loki",
            state: "running",
            intent,
            result: Some(data),
        })),
        Err(_) => Ok(Json(not_running(&intent))),
    }
}

/// The tolerant `profile_not_running` envelope.
fn not_running(intent: &str) -> LogsResult {
    LogsResult {
        source: "loki",
        state: "profile_not_running",
        intent: intent.to_string(),
        result: None,
    }
}

/// Validate + clamp an optional integer query param to `[min, max]`, falling back
/// to `default` when absent. A non-integer value is `422`.
fn clamp_param(raw: Option<String>, default: i64, min: i64, max: i64) -> Result<i64, AppError> {
    match raw.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(default),
        Some(s) => {
            let v: i64 = s
                .parse()
                .map_err(|_| AppError::BadRequest("range/limit must be an integer".into()))?;
            Ok(v.clamp(min, max))
        }
    }
}

/// Issue a LogQL `query_range` against `{loki_url}/loki/api/v1/query_range`.
///
/// The `query` is the SERVER-BUILT LogQL (constant selector / allowlisted
/// service); `start`/`end` are nanosecond UNIX timestamps (Loki's range unit) and
/// `limit` is the bounded line count. Returns the raw Loki `data` object on
/// success; any failure is `Err` (folded into `profile_not_running`, no leak).
async fn query_range(
    cfg: &Config,
    logql: &str,
    range_secs: i64,
    limit: i64,
) -> Result<serde_json::Value, AppError> {
    let client = reqwest::Client::builder()
        .timeout(QUERY_TIMEOUT)
        .build()
        .map_err(|e| AppError::Internal(format!("build loki client: {e}")))?;

    // Loki's query_range start/end are UNIX NANOSECONDS.
    let now_ns = unix_now_nanos();
    let start_ns = now_ns - (range_secs as i128 * 1_000_000_000);

    // Build the query string with percent-encoded values (the reqwest 0.13
    // `query` feature is not enabled — encode manually). `logql` is server-built.
    let url = format!(
        "{}/loki/api/v1/query_range?query={}&start={}&end={}&limit={}&direction=backward",
        cfg.loki_url.trim_end_matches('/'),
        urlencode(logql),
        start_ns,
        now_ns,
        limit
    );

    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "loki query transport error");
            AppError::Upstream("loki unreachable".into())
        })?;

    let status = resp.status();
    if !status.is_success() {
        tracing::warn!(status = %status, "loki query returned error status");
        return Err(AppError::Upstream(format!("loki status {status}")));
    }

    let body: serde_json::Value = resp.json().await.map_err(|e| {
        tracing::warn!(error = %e, "loki query decode error");
        AppError::Upstream("loki decode error".into())
    })?;
    Ok(body.get("data").cloned().unwrap_or(body))
}

/// Percent-encode a query-string VALUE (RFC 3986 unreserved chars pass through;
/// everything else `%XX`). Used for the server-built LogQL.
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

/// Current UNIX time in nanoseconds (Loki's range-query timestamp unit).
fn unix_now_nanos() -> i128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i128)
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

    /// Known intents map to a fixed LogQL; an unknown intent / non-allowlisted
    /// service is rejected (None → 422). No raw operator LogQL can pass through.
    #[test]
    fn logql_intent_allowlist_is_closed() {
        assert!(logql_for_intent("all", None).is_some());
        assert!(logql_for_intent("errors", None).is_some());
        assert!(logql_for_intent("service", Some("kratos")).is_some());

        // An unknown intent → None.
        assert!(logql_for_intent(r#"{job="x"} |= "secret""#, None).is_none());
        // A `service` intent with a non-allowlisted (injection) value → None.
        assert!(logql_for_intent("service", Some(r#"x"} |= "")"#)).is_none());
        assert!(logql_for_intent("service", Some("etc-passwd")).is_none());
        // A `service` intent with no service → None.
        assert!(logql_for_intent("service", None).is_none());
    }

    /// WR-01: the allowlisted-service query keeps the WORKING `{job="docker"}`
    /// stream selector (Alloy emits no per-service stream label under file-tail)
    /// and adds a word-boundary line filter on the allowlisted literal — the only
    /// client-influenced text is one of the closed `[a-z]+` allowlist values, so no
    /// LogQL operator/quote/pipe can be injected.
    #[test]
    fn service_selector_is_exact_template() {
        assert_eq!(
            logql_for_intent("service", Some("backend")).unwrap(),
            // The LogQL carries the LITERAL two-char `\b` sequence (a backslash +
            // 'b') so Loki's string-unescape yields a RE2 word boundary — written
            // here as `\\b` in a normal Rust string (each is one backslash + 'b').
            "{job=\"docker\"} |~ \"(?i)\\\\bbackend\\\\b\""
        );
    }

    /// WR-01: a `service` value that is NOT in the closed allowlist (e.g. a LogQL
    /// injection attempt) is rejected before it can reach the line filter, so the
    /// `{svc}` interpolation can only ever be one of the fixed `[a-z]+` literals.
    #[test]
    fn service_line_filter_only_admits_allowlisted_literals() {
        // Allowlisted -> a `{job="docker"}` stream selector + a line filter (never
        // a `{service=...}` stream label, which Alloy cannot emit under file-tail).
        let q = logql_for_intent("service", Some("kratos")).unwrap();
        assert!(q.starts_with(r#"{job="docker"}"#), "got {q}");
        assert!(q.contains("|~"), "got {q}");
        assert!(q.contains("kratos"), "got {q}");
        // Injection / non-allowlisted values are rejected (None) before interpolation.
        assert!(logql_for_intent("service", Some(r#"x" |= "secret"#)).is_none());
        assert!(logql_for_intent("service", Some("backend\" }")).is_none());
    }

    #[test]
    fn clamp_param_validates_and_bounds() {
        assert_eq!(clamp_param(None, DEFAULT_LIMIT, 1, MAX_LIMIT).unwrap(), DEFAULT_LIMIT);
        assert_eq!(clamp_param(Some("50".into()), DEFAULT_LIMIT, 1, MAX_LIMIT).unwrap(), 50);
        assert_eq!(
            clamp_param(Some("99999".into()), DEFAULT_LIMIT, 1, MAX_LIMIT).unwrap(),
            MAX_LIMIT
        );
        let err = clamp_param(Some("nope".into()), DEFAULT_LIMIT, 1, MAX_LIMIT).unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)), "got {err:?}");
    }
}
