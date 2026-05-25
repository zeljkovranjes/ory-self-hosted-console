//! Scoped container restart + post-restart health poll (BACK-05 — the backend
//! holds NO docker socket).
//!
//! After a validated atomic write the engine restarts ONLY the affected
//! container by POSTing to the Phase-1 `wollomatic` socket-proxy broker, then
//! polls the service's `/health/ready` until it comes back. Both the restart URL
//! and the health URL are built ENTIRELY server-side from a fixed broker base
//! plus a closed [`Service`] enum — NO part of either URL is ever derived from
//! client input (SSRF guard, T-04-12 / BACK-05). An unknown service name cannot
//! even produce a [`Service`]; [`Service::parse`] returns `AppError::NotFound`.
//!
//! ## Restart (RESEARCH Pattern 4)
//!
//! `POST {broker}/v1.<NN>/containers/ory-<svc>/restart` -> the Phase-1 broker
//! allowlist (`/v1\..{1,2}/containers/(ory-kratos|ory-hydra|ory-keto|ory-oathkeeper)/restart(\?.*)?`)
//! forwards it to the engine, which returns **204 No Content**. Anything other
//! than 204 maps to [`AppError::Upstream`] (502) — and the broker response body
//! and the URL are NEVER placed in the error (BACK-07 / T-04-15).
//!
//! ## Health poll (RESEARCH Pattern 4 + Pitfall 6)
//!
//! A freshly-restarted Ory service briefly returns **503** (`{"status":"not
//! ready"}`) or refuses the connection while it boots. [`wait_healthy`] polls
//! `GET http://<svc>:<adminport>/health/ready` in a `tokio::time::timeout` loop
//! (~1 s interval), treating connection errors and 503 as "not yet" and a 200 as
//! healthy. It returns `false` on timeout (which drives the caller's rollback) —
//! never a needless rollback on the first transient 503.

use std::time::Duration;

use crate::error::AppError;

/// The four config-editable Ory services. A closed enum so the restart/health
/// TARGET can never be client-derived — the only constructor that accepts a
/// string is [`Service::parse`], which rejects anything unknown (SSRF guard,
/// T-04-12). The route layer parses the `<service>` path segment through here
/// BEFORE any URL is built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    Kratos,
    Hydra,
    Keto,
    Oathkeeper,
}

/// Docker Engine API version segment used in the restart path. The Phase-1 broker
/// allowlist regex is version-tolerant (`/v1\..{1,2}/…`, RESEARCH A4), so a
/// current constant is accepted; we do not hardcode a fragile exact engine match.
const DOCKER_API_SEGMENT: &str = "v1.43";

/// How often to re-poll `/health/ready` while waiting for a restarted service.
const HEALTH_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// WR-05: per-PROBE timeout for the `/health/ready` poll, independent of the
/// shared 10s Ory-fallback client timeout. A hanging connect during the boot
/// window is bounded to this (well under the 1s cadence + interval) so the loop
/// keeps probing at the intended ~1s cadence instead of being coarsened to ~5
/// probes across the 60s budget by a 10s per-attempt stall.
const HEALTH_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Build the reqwest client used for BOTH the broker restart POST and the
/// `/health/ready` poll.
///
/// WR-04: redirects are DISABLED (`Policy::none()`), consistent with the SSRF
/// guard posture used elsewhere — the targets are fixed internal URLs, and a 3xx
/// `Location` from a compromised/misbehaving internal service (or a broker
/// mis-config) must never steer a follow-up request, nor be read as "healthy" by
/// following it to a 200 elsewhere. WR-05: a short connect/request timeout keeps
/// the health probe cadence tight; the per-request `.timeout()` in
/// [`wait_healthy`] bounds each individual probe further.
pub fn restart_client() -> Result<reqwest::Client, AppError> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(HEALTH_PROBE_TIMEOUT)
        .build()
        .map_err(|e| AppError::Internal(format!("build restart/health http client: {e}")))
}

impl Service {
    /// Parse a `<service>` path segment into a [`Service`]. An unrecognised name
    /// is `AppError::NotFound` — no URL is ever built for an unknown service, so
    /// a client cannot steer the restart/health target (SSRF guard).
    pub fn parse(service: &str) -> Result<Service, AppError> {
        match service {
            "kratos" => Ok(Service::Kratos),
            "hydra" => Ok(Service::Hydra),
            "keto" => Ok(Service::Keto),
            "oathkeeper" => Ok(Service::Oathkeeper),
            _ => Err(AppError::NotFound),
        }
    }

    /// Canonical service key (`"kratos"` …) — the lowercase name used in the
    /// `ory-<svc>` container name and the schema/allowlist registries.
    pub fn key(self) -> &'static str {
        match self {
            Service::Kratos => "kratos",
            Service::Hydra => "hydra",
            Service::Keto => "keto",
            Service::Oathkeeper => "oathkeeper",
        }
    }

    /// The scoped container name the broker allowlist permits (`ory-kratos` …).
    fn container(self) -> &'static str {
        match self {
            Service::Kratos => "ory-kratos",
            Service::Hydra => "ory-hydra",
            Service::Keto => "ory-keto",
            Service::Oathkeeper => "ory-oathkeeper",
        }
    }

    /// The service's INTERNAL `/health/ready` base authority (`http://<svc>:<port>`).
    /// Fixed per RESEARCH Pattern 4 table: kratos:4434 (admin), hydra:4445
    /// (admin), keto:4469 (metadata), oathkeeper:4456 (api). Server-defined, never
    /// client input.
    fn health_base(self) -> &'static str {
        match self {
            Service::Kratos => "http://kratos:4434",
            Service::Hydra => "http://hydra:4445",
            Service::Keto => "http://keto:4469",
            Service::Oathkeeper => "http://oathkeeper:4456",
        }
    }
}

/// Build the broker restart URL ENTIRELY from the fixed broker base + the closed
/// [`Service`] — no client-supplied host or path segment can enter it. The base
/// is trimmed of a trailing slash so a configured `…:2375/` does not double up.
fn restart_url(broker_base: &str, svc: Service) -> String {
    format!(
        "{base}/{api}/containers/{container}/restart",
        base = broker_base.trim_end_matches('/'),
        api = DOCKER_API_SEGMENT,
        container = svc.container(),
    )
}

/// POST a single-container restart to the scoped broker, expecting **204**.
///
/// `broker_base` is the fixed `Config::restart_broker_url`; `svc` is a closed
/// [`Service`] — together they yield a fully server-built URL (SSRF guard). Any
/// status other than 204 maps to [`AppError::Upstream`] (502) and the broker
/// response body / URL are NEVER echoed into the error (BACK-07). A transport
/// error is likewise a generic 502.
pub async fn restart(
    http: &reqwest::Client,
    broker_base: &str,
    svc: Service,
) -> Result<(), AppError> {
    let url = restart_url(broker_base, svc);
    let resp = http.post(url).send().await.map_err(|e| {
        // Log the transport cause server-side; the client sees only the code.
        tracing::warn!(error = %e, service = svc.key(), "restart broker transport error");
        AppError::Upstream("restart broker unreachable".to_string())
    })?;

    let status = resp.status();
    if status == reqwest::StatusCode::NO_CONTENT {
        Ok(())
    } else {
        // Log ONLY the status (never the body) — T-04-15 / BACK-07.
        tracing::warn!(status = %status, service = svc.key(), "restart broker returned non-204");
        Err(AppError::Upstream(format!(
            "restart broker status {status}"
        )))
    }
}

/// Poll `<health_base>/health/ready` until 200 or `timeout` elapses.
///
/// `health_base_override` lets a unit test point the poll at a mock; production
/// passes `None` and the fixed per-service internal base is used. Connection
/// errors and any non-200 (notably the boot-time 503, Pitfall 6) are treated as
/// "not yet" — we keep polling on `HEALTH_POLL_INTERVAL` until a 200 (-> `true`)
/// or the overall `timeout` is exhausted (-> `false`, which drives rollback).
pub async fn wait_healthy(
    http: &reqwest::Client,
    svc: Service,
    timeout: Duration,
    health_base_override: Option<&str>,
) -> bool {
    let base = health_base_override.unwrap_or_else(|| svc.health_base());
    let url = format!("{}/health/ready", base.trim_end_matches('/'));

    let poll = async {
        loop {
            // WR-05: bound each individual probe with an explicit per-request
            // timeout so a hanging connect during boot cannot consume the shared
            // 10s client timeout and coarsen the ~1s poll cadence. WR-04: the
            // client disables redirects, so a 3xx arrives here as a non-200 and
            // is treated as "not yet" — never followed to a 200 elsewhere.
            match http.get(&url).timeout(HEALTH_PROBE_TIMEOUT).send().await {
                Ok(resp) if resp.status() == reqwest::StatusCode::OK => return true,
                // Non-200 (e.g. boot-time 503 or a 3xx redirect) or a
                // transport/connection/timeout error: treat as "not yet" and
                // keep polling (Pitfall 6).
                Ok(_) | Err(_) => {
                    tokio::time::sleep(HEALTH_POLL_INTERVAL).await;
                }
            }
        }
    };

    // `timeout` resolving to Err means we never saw a 200 in the window -> not
    // healthy; the caller then rolls back.
    matches!(tokio::time::timeout(timeout, poll).await, Ok(true))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_url_is_built_server_side() {
        // The URL is composed from the fixed broker base + a CLOSED Service — no
        // client host/path can enter it. A trailing slash on the base is trimmed.
        let url = restart_url("http://restart-broker:2375", Service::Kratos);
        assert_eq!(
            url,
            "http://restart-broker:2375/v1.43/containers/ory-kratos/restart"
        );
        let url2 = restart_url("http://restart-broker:2375/", Service::Hydra);
        assert_eq!(
            url2,
            "http://restart-broker:2375/v1.43/containers/ory-hydra/restart"
        );

        // An unknown service name cannot produce a Service at all (NotFound), so
        // it can NEVER reach restart_url — the SSRF target is closed.
        assert!(matches!(Service::parse("evil"), Err(AppError::NotFound)));
        assert!(matches!(
            Service::parse("kratos/../hydra"),
            Err(AppError::NotFound)
        ));
        // Every valid service maps to exactly its scoped container name.
        for (name, container) in [
            ("kratos", "ory-kratos"),
            ("hydra", "ory-hydra"),
            ("keto", "ory-keto"),
            ("oathkeeper", "ory-oathkeeper"),
        ] {
            let svc = Service::parse(name).expect("known service parses");
            assert!(
                restart_url("http://b", svc).ends_with(&format!("/{container}/restart")),
                "{name} must target {container}"
            );
        }
    }

    #[tokio::test]
    async fn non_204_restart_is_upstream_error() {
        // A mocked broker returning anything other than 204 must map to
        // AppError::Upstream (502) with NO broker body in the message.
        let mut server = mockito::Server::new_async().await;
        let body = "INTERNAL BROKER PANIC: socket /var/run/docker.sock denied";
        let m = server
            .mock("POST", "/v1.43/containers/ory-kratos/restart")
            .with_status(500)
            .with_body(body)
            .create_async()
            .await;

        let http = reqwest::Client::new();
        let err = restart(&http, &server.url(), Service::Kratos)
            .await
            .expect_err("non-204 must be an error");
        m.assert_async().await;

        assert!(matches!(err, AppError::Upstream(_)), "got {err:?}");
        assert_eq!(err.status_code(), salvo::http::StatusCode::BAD_GATEWAY);
        // The broker BODY must never appear in the error detail (BACK-07).
        assert!(
            !err.to_string().contains("socket") && !err.to_string().contains("PANIC"),
            "broker body must not leak into the error: {err}"
        );

        // A 204 is the success path.
        let mut ok_server = mockito::Server::new_async().await;
        let ok = ok_server
            .mock("POST", "/v1.43/containers/ory-hydra/restart")
            .with_status(204)
            .create_async()
            .await;
        restart(&http, &ok_server.url(), Service::Hydra)
            .await
            .expect("204 is success");
        ok.assert_async().await;
    }

    #[tokio::test]
    async fn health_poll_tolerates_503_then_succeeds() {
        // A poll that sees 503 then 200 returns healthy: mockito serves 503 once,
        // then 200. The ~1s interval + a generous timeout lets the second poll win.
        let mut server = mockito::Server::new_async().await;
        let _first = server
            .mock("GET", "/health/ready")
            .with_status(503)
            .with_body(r#"{"status":"not ready"}"#)
            .expect(1)
            .create_async()
            .await;
        let _ready = server
            .mock("GET", "/health/ready")
            .with_status(200)
            .with_body(r#"{"status":"ok"}"#)
            .create_async()
            .await;

        let http = reqwest::Client::new();
        let healthy = wait_healthy(
            &http,
            Service::Kratos,
            Duration::from_secs(5),
            Some(&server.url()),
        )
        .await;
        assert!(healthy, "503-then-200 must report healthy");
    }

    #[tokio::test]
    async fn health_poll_times_out_on_persistent_503() {
        // A poll that only ever sees 503 within the (short) timeout returns NOT
        // healthy -> drives the caller's rollback.
        let mut server = mockito::Server::new_async().await;
        let _always_503 = server
            .mock("GET", "/health/ready")
            .with_status(503)
            .create_async()
            .await;

        let http = reqwest::Client::new();
        let healthy = wait_healthy(
            &http,
            Service::Keto,
            // Short timeout so the test is fast; the 1s interval guarantees we
            // exhaust the window without a 200.
            Duration::from_millis(300),
            Some(&server.url()),
        )
        .await;
        assert!(!healthy, "persistent 503 within the timeout must be NOT healthy");
    }
}
