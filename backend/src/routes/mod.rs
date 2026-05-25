//! Router assembly (BACK-01).
//!
//! This phase (Plan 02-01) wires only the public skeleton: the `affix_state`
//! hoop injecting the `PgPool` + `Config` into every `Depot`, plus the
//! preserved `GET /health` and `GET /` index. The auth subsystem (setup/login/
//! logout/middleware/CSRF/rate-limit/github) and the protected subtree are
//! added by Plans 02-02..04, which extend `build` — keep it forward-compatible.

use salvo::affix_state;
use salvo::prelude::*;
use sqlx::PgPool;

use crate::config::Config;

/// Liveness/readiness probe. Preserved from the Phase-1 skeleton: returns 200
/// with a small JSON body. Public — no auth hoop (CAUTH-06 public set).
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

/// Build the application router.
///
/// The `affix_state` hoop injects the shared `PgPool` and `Config` into every
/// request's `Depot`; downstream handlers (later plans) read them via
/// `depot.obtain::<PgPool>()` / `depot.obtain::<Config>()`.
pub fn build(pool: PgPool, cfg: Config) -> Router {
    Router::new()
        .hoop(affix_state::inject(pool).inject(cfg))
        .get(index)
        .push(Router::with_path("health").get(health))
}
