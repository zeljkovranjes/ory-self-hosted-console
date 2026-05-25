//! Ory Self-Hosted Console — backend skeleton (Phase 1).
//!
//! This is intentionally minimal: it stands up the empty Salvo server slot in
//! the compose graph (Plan 04) and exposes `GET /health` so the container has a
//! healthcheck target and can serve as the curl source for the Plan 03 internal
//! network probes. It contains NO real application logic — no Ory clients, no
//! auth, no persistence, no config subsystem. Those land in Phase 2.
//!
//! Bind address is read from the `BACKEND_BIND_ADDR` env var (default
//! `0.0.0.0:8080`) so Plan 04 / the operator can override it without rebuilding.

use salvo::prelude::*;

/// Default bind address. Listens on all interfaces so the container is reachable
/// from both the edge network (host-published) and the internal network (where
/// the Plan 03 harness probes `backend:8080/health`).
const DEFAULT_BIND_ADDR: &str = "0.0.0.0:8080";

/// Liveness/readiness probe.
///
/// Returns HTTP 200 with a small JSON body. The body content is not part of any
/// contract this phase — only the 200 status matters for the healthcheck. Real
/// readiness semantics (DB reachable, Ory reachable) are a Phase 2 concern.
#[handler]
async fn health(res: &mut Response) {
    res.status_code(StatusCode::OK);
    res.render(Json(serde_json::json!({ "status": "ok" })));
}

/// Root placeholder so a manual `GET /` does not 404 during smoke checks.
#[handler]
async fn index() -> &'static str {
    "ory-console-backend: ok"
}

fn build_router() -> Router {
    Router::new()
        .get(index)
        .push(Router::with_path("health").get(health))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let bind_addr =
        std::env::var("BACKEND_BIND_ADDR").unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_string());

    let router = build_router();

    tracing::info!(%bind_addr, "starting ory-console-backend skeleton");

    let acceptor = TcpListener::new(bind_addr).bind().await;
    Server::new(acceptor).serve(router).await;
}
