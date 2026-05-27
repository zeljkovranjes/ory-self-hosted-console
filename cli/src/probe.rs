//! Connection-validation readiness probes (CLI-builder Wave 2 / CONN-CHECK).
//!
//! Before bringing a stack up (or re-applying a `console.config.toml`), the
//! builder probes the readiness endpoint of every `in-stack` and `byo` service so
//! a misconfigured BYO URL or a not-yet-ready container is caught with a clear
//! diagnostic instead of a confusing downstream 502. `off` services are skipped
//! (there is nothing to reach).
//!
//! POLICY (CONTEXT.md — "BLOCK with explicit override"): any failing probe stops
//! the flow ([`should_block`] returns the failures) UNLESS the operator passed
//! `--skip-checks`.
//!
//! The probe is NON-DESTRUCTIVE: a single GET, redirects OFF, a short timeout. It
//! NEVER writes to the running stack and NEVER carries the Polis API key — every
//! readiness endpoint here is UNAUTHENTICATED (incl. Polis `/api/health`), so the
//! probe builds no secret-bearing request and the diagnostics are secret-free.
//!
//! Readiness endpoints (VERIFIED against docker-compose.yml healthchecks +
//! backend.environment defaults + the Ory REST reference, 2026-05-27):
//!   * Kratos     {admin}/admin/health/ready   (admin :4434)  — in-stack http://kratos:4434
//!   * Hydra      {admin}/health/ready          (admin :4445)  — in-stack http://hydra:4445
//!   * Keto       {read}/health/ready AND {write}/health/ready (:4466 / :4467)
//!                in-stack http://keto:4466 / http://keto:4467
//!   * Oathkeeper {api}/health/alive            (:4456)        — in-stack http://oathkeeper:4456
//!                (/health/ready 503s for the stateless from-file config; the
//!                 compose healthcheck uses /health/alive — Phase-9 decision)
//!   * Polis      {admin}/api/health            (:5225)        — in-stack http://polis:5225

use std::time::Duration;

use crate::config_model::{ConsoleConfig, ServiceMode, SERVICES};

/// The default per-endpoint probe timeout. Short — a readiness endpoint that does
/// not answer promptly is treated as not-ready.
pub const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// The in-stack default base URLs (mirrors docker-compose.yml backend.environment).
/// Used when a service is `in-stack` and the operator gave no override. Returned
/// as `(admin/api, public/read, write)` slots; unused slots are empty.
fn in_stack_bases(service: &str) -> (&'static str, &'static str, &'static str) {
    match service {
        "kratos" => ("http://kratos:4434", "", ""),
        "hydra" => ("http://hydra:4445", "http://hydra:4444", ""),
        "keto" => ("", "http://keto:4466", "http://keto:4467"),
        "oathkeeper" => ("http://oathkeeper:4456", "", ""),
        "polis" => ("http://polis:5225", "", ""),
        _ => ("", "", ""),
    }
}

/// The outcome of probing ONE logical service. For Keto, `url` may be a
/// `read; write` pair and `ok` is false if EITHER endpoint fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeResult {
    /// Canonical service name (`kratos` / `hydra` / `keto` / `oathkeeper` / `polis`).
    pub service: String,
    /// The readiness URL(s) probed (Keto: `read; write`). Secret-free.
    pub url: String,
    /// True iff every probed endpoint for this service answered 2xx.
    pub ok: bool,
    /// On success the HTTP status; on failure the status or transport error +
    /// the URL that failed. Always secret-free.
    pub status_or_error: String,
    /// An operator-facing fix hint (empty on success).
    pub hint: String,
}

/// The readiness URL(s) for a service given its mode. Returns:
///   * `None` for an `off` service (skipped — nothing to probe);
///   * a `Vec` of one URL for kratos/hydra/oathkeeper/polis, or TWO (read, write)
///     for keto.
/// In `byo` mode the operator-supplied URL(s) are used; in `in-stack` mode the
/// compose default base. A trailing slash on a base is tolerated.
pub fn readiness_url(service: &str, config: &ConsoleConfig) -> Option<Vec<String>> {
    let mode = config.to_service_seed().get(service).copied()?;
    if mode == ServiceMode::Off {
        return None;
    }
    let cfg = service_config(config, service);
    let (admin_d, public_or_read_d, write_d) = in_stack_bases(service);

    // Resolve a base: byo → the operator override (falling back to the in-stack
    // default if absent, so a half-specified byo still probes a sane endpoint);
    // in-stack → always the compose default.
    let pick = |byo_val: Option<String>, default: &str| -> String {
        match mode {
            ServiceMode::Byo => byo_val.unwrap_or_else(|| default.to_string()),
            _ => default.to_string(),
        }
    };

    let urls = match service {
        "kratos" => vec![join(
            &pick(cfg.and_then(|c| c.admin_url.clone()), admin_d),
            "/admin/health/ready",
        )],
        "hydra" => vec![join(
            &pick(cfg.and_then(|c| c.admin_url.clone()), admin_d),
            "/health/ready",
        )],
        "keto" => vec![
            join(
                &pick(cfg.and_then(|c| c.read_url.clone()), public_or_read_d),
                "/health/ready",
            ),
            join(
                &pick(cfg.and_then(|c| c.write_url.clone()), write_d),
                "/health/ready",
            ),
        ],
        "oathkeeper" => vec![join(
            &pick(cfg.and_then(|c| c.admin_url.clone()), admin_d),
            "/health/alive",
        )],
        // Polis /api/health is UNAUTHENTICATED — probed WITHOUT the API key.
        "polis" => vec![join(
            &pick(cfg.and_then(|c| c.admin_url.clone()), admin_d),
            "/api/health",
        )],
        _ => return None,
    };
    Some(urls)
}

/// Probe ONE service's readiness endpoint(s) with a single GET each (redirects
/// off, short timeout). Returns `None` only when the service is `off` (skipped).
/// A transport error is `ok=false` (never a panic).
pub async fn probe_service(
    service: &str,
    config: &ConsoleConfig,
    timeout: Duration,
) -> Option<ProbeResult> {
    let urls = readiness_url(service, config)?;
    let client = match reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return Some(ProbeResult {
                service: service.to_string(),
                url: urls.join("; "),
                ok: false,
                status_or_error: format!("could not build HTTP client: {e}"),
                hint: build_hint(service, config),
            });
        }
    };

    let mut statuses: Vec<String> = Vec::new();
    let mut all_ok = true;
    for url in &urls {
        match client.get(url).send().await {
            Ok(resp) => {
                let st = resp.status();
                statuses.push(format!("{url} -> {}", st.as_u16()));
                if !st.is_success() {
                    all_ok = false;
                }
            }
            Err(e) => {
                all_ok = false;
                // reqwest's Display is secret-free (URL + transport reason).
                statuses.push(format!("{url} -> transport error: {e}"));
            }
        }
    }

    Some(ProbeResult {
        service: service.to_string(),
        url: urls.join("; "),
        ok: all_ok,
        status_or_error: statuses.join(" | "),
        hint: if all_ok { String::new() } else { build_hint(service, config) },
    })
}

/// Probe EVERY non-`off` service in the config, in the stable SERVICES order.
pub async fn probe_all(config: &ConsoleConfig, timeout: Duration) -> Vec<ProbeResult> {
    let mut out = Vec::new();
    for svc in SERVICES {
        if let Some(r) = probe_service(svc, config, timeout).await {
            out.push(r);
        }
    }
    out
}

/// The BLOCK-on-failure policy (pure). Returns the failing probes when ANY failed
/// AND `skip_checks` is false; returns `None` (proceed) when all passed OR
/// `skip_checks` is true.
pub fn should_block(results: &[ProbeResult], skip_checks: bool) -> Option<Vec<ProbeResult>> {
    if skip_checks {
        return None;
    }
    let failures: Vec<ProbeResult> = results.iter().filter(|r| !r.ok).cloned().collect();
    if failures.is_empty() {
        None
    } else {
        Some(failures)
    }
}

/// A mode-aware fix hint (secret-free).
fn build_hint(service: &str, config: &ConsoleConfig) -> String {
    let mode = config.to_service_seed().get(service).copied();
    match mode {
        Some(ServiceMode::Byo) => format!(
            "{service} is `byo` — is the external URL correct and reachable from the backend's network? \
             (pass --skip-checks to proceed anyway)"
        ),
        _ => format!(
            "{service} is `in-stack` — is the container running and healthy yet? \
             (it may still be starting; pass --skip-checks to proceed anyway)"
        ),
    }
}

/// Join a base URL and a path, tolerating a trailing slash on the base.
fn join(base: &str, path: &str) -> String {
    format!("{}{}", base.trim_end_matches('/'), path)
}

/// The `ServiceConfig` for a service by name, if present.
fn service_config<'a>(
    config: &'a ConsoleConfig,
    service: &str,
) -> Option<&'a crate::config_model::ServiceConfig> {
    match service {
        "kratos" => config.services.kratos.as_ref(),
        "hydra" => config.services.hydra.as_ref(),
        "keto" => config.services.keto.as_ref(),
        "oathkeeper" => config.services.oathkeeper.as_ref(),
        "polis" => config.services.polis.as_ref(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_model::parse_config;

    fn cfg(toml: &str) -> ConsoleConfig {
        parse_config(toml).expect("test config must parse")
    }

    #[test]
    fn probe_readiness_url_in_stack_defaults_per_service() {
        let c = cfg(r#"
[services.kratos]
mode = "in-stack"
[services.hydra]
mode = "in-stack"
[services.keto]
mode = "in-stack"
[services.oathkeeper]
mode = "in-stack"
[services.polis]
mode = "in-stack"
"#);
        assert_eq!(
            readiness_url("kratos", &c).unwrap(),
            vec!["http://kratos:4434/admin/health/ready"]
        );
        assert_eq!(
            readiness_url("hydra", &c).unwrap(),
            vec!["http://hydra:4445/health/ready"]
        );
        assert_eq!(
            readiness_url("keto", &c).unwrap(),
            vec![
                "http://keto:4466/health/ready",
                "http://keto:4467/health/ready"
            ]
        );
        assert_eq!(
            readiness_url("oathkeeper", &c).unwrap(),
            vec!["http://oathkeeper:4456/health/alive"]
        );
        assert_eq!(
            readiness_url("polis", &c).unwrap(),
            vec!["http://polis:5225/api/health"]
        );
    }

    #[test]
    fn probe_readiness_url_byo_uses_operator_urls() {
        let c = cfg(r#"
[services.kratos]
mode = "byo"
admin_url = "https://kratos.ext.example"
[services.keto]
mode = "byo"
read_url = "https://keto.ext/read"
write_url = "https://keto.ext/write"
"#);
        assert_eq!(
            readiness_url("kratos", &c).unwrap(),
            vec!["https://kratos.ext.example/admin/health/ready"]
        );
        assert_eq!(
            readiness_url("keto", &c).unwrap(),
            vec![
                "https://keto.ext/read/health/ready",
                "https://keto.ext/write/health/ready"
            ]
        );
    }

    #[test]
    fn probe_readiness_url_off_service_is_skipped() {
        let c = cfg(r#"
[services.keto]
mode = "off"
"#);
        assert!(readiness_url("keto", &c).is_none(), "off → no probe");
        // And probe_service returns None for an off service.
        let none = tokio_test_block(probe_service("keto", &c, DEFAULT_PROBE_TIMEOUT));
        assert!(none.is_none(), "off service must not be probed");
    }

    #[tokio::test]
    async fn probe_service_200_is_ok() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("GET", "/health/ready")
            .with_status(200)
            .with_body("{}")
            .create_async()
            .await;

        let c = cfg(&format!(
            r#"
[services.hydra]
mode = "byo"
admin_url = "{}"
"#,
            server.url()
        ));
        let r = probe_service("hydra", &c, DEFAULT_PROBE_TIMEOUT)
            .await
            .expect("hydra should be probed");
        assert!(r.ok, "200 → ok: {r:?}");
        assert!(r.hint.is_empty(), "no hint on success");
        m.assert_async().await;
    }

    #[tokio::test]
    async fn probe_service_503_is_not_ok_with_hint() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/health/ready")
            .with_status(503)
            .with_body("not ready")
            .create_async()
            .await;

        let c = cfg(&format!(
            r#"
[services.hydra]
mode = "byo"
admin_url = "{}"
"#,
            server.url()
        ));
        let r = probe_service("hydra", &c, DEFAULT_PROBE_TIMEOUT)
            .await
            .unwrap();
        assert!(!r.ok, "503 → not ok");
        assert!(r.status_or_error.contains("503"), "status: {r:?}");
        assert!(r.hint.contains("byo"), "byo hint: {r:?}");
    }

    #[tokio::test]
    async fn probe_service_connection_refused_is_not_ok_no_panic() {
        // An unroutable URL (reserved TEST-NET-1, port 1) → transport error.
        let c = cfg(r#"
[services.kratos]
mode = "byo"
admin_url = "http://192.0.2.1:1"
"#);
        let r = probe_service("kratos", &c, Duration::from_millis(800))
            .await
            .unwrap();
        assert!(!r.ok, "unreachable → not ok");
        assert!(!r.hint.is_empty(), "a failure carries a hint");
    }

    #[tokio::test]
    async fn probe_keto_fails_if_either_endpoint_fails() {
        let mut server = mockito::Server::new_async().await;
        // read OK, write 503 → the logical keto probe fails.
        let _read = server
            .mock("GET", "/read/health/ready")
            .with_status(200)
            .create_async()
            .await;
        let _write = server
            .mock("GET", "/write/health/ready")
            .with_status(503)
            .create_async()
            .await;

        let c = cfg(&format!(
            r#"
[services.keto]
mode = "byo"
read_url = "{base}/read"
write_url = "{base}/write"
"#,
            base = server.url()
        ));
        let r = probe_service("keto", &c, DEFAULT_PROBE_TIMEOUT)
            .await
            .unwrap();
        assert!(!r.ok, "keto fails if EITHER endpoint fails: {r:?}");
        assert!(r.status_or_error.contains("503"), "write 503 surfaced: {r:?}");
    }

    #[test]
    fn probe_should_block_honors_skip_checks_and_failures() {
        let ok = ProbeResult {
            service: "kratos".into(),
            url: "u".into(),
            ok: true,
            status_or_error: "200".into(),
            hint: String::new(),
        };
        let bad = ProbeResult {
            service: "hydra".into(),
            url: "u".into(),
            ok: false,
            status_or_error: "503".into(),
            hint: "fix it".into(),
        };
        // all pass → proceed (None).
        assert!(should_block(&[ok.clone()], false).is_none());
        // a failure + not skipping → block (Some, listing the failure).
        let blocked = should_block(&[ok.clone(), bad.clone()], false).unwrap();
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].service, "hydra");
        // a failure BUT skip_checks → proceed (None).
        assert!(should_block(&[ok, bad], true).is_none());
    }

    /// Minimal block_on for the two sync tests that call an async fn (avoids a new
    /// dev-dep; tokio is already present).
    fn tokio_test_block<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    }
}
