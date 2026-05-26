//! Ory Self-Hosted Console — backend (Phase 2).
//!
//! Structured Salvo application that is the single authenticated API layer
//! (BACK-01) with its own `console` Postgres database (BACK-03) and secret-safe
//! error handling (BACK-07). Bootstrap order (RESEARCH "Bootstrap order"):
//!
//!   init tracing -> Config::from_env -> build PgPool -> sqlx::migrate!() -> serve
//!
//! Migrations run BEFORE the listener binds, so the schema is always present by
//! the time `/health` answers. The auth subsystem (setup/login/session/
//! middleware/CSRF/github) lands in Plans 02-02..04 under `mod auth`.

use salvo::prelude::*;

use std::time::Duration;

use ory_console_backend::auth::setup::ensure_bootstrap_token;
use ory_console_backend::config::Config;
use ory_console_backend::db::queries;
use ory_console_backend::error::AppError;
use ory_console_backend::webhooks;
use ory_console_backend::{db, routes};

/// WR-07: how often the background reaper deletes absolutely-expired sessions.
/// Hourly is ample for a low-concurrency console — it bounds `sessions` growth
/// from abandoned (never-logged-out) sessions without adding meaningful load.
const SESSION_REAP_INTERVAL: Duration = Duration::from_secs(3600);

/// HOOK-01: how often the webhook worker claims + delivers due rows. A tight 2s
/// cadence keeps delivery latency low for a low-volume single-tenant console.
const WEBHOOK_TICK_INTERVAL: Duration = Duration::from_secs(2);

/// HOOK-03: how often the webhook maintenance task prunes terminal deliveries
/// and recovers stale 'delivering' rows. Hourly is ample.
const WEBHOOK_MAINT_INTERVAL: Duration = Duration::from_secs(3600);

/// Initialize structured logging. Keeps the Phase-1 default filter ("info").
fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    init_tracing();

    // Config first — never logs the DSN or any secret (redacting Debug).
    let cfg = Config::from_env()?;

    // Console-DB pool. The DSN is a secret; build_pool maps failures to the
    // generic AppError::Db (no DSN in the message).
    let pool = db::build_pool(&cfg.console_database_url).await?;

    // Run migrations BEFORE binding; idempotent. AppError::Migrate -> 500-class
    // exit with a generic message (no connection string leaked).
    sqlx::migrate!("./migrations").run(&pool).await?;
    tracing::info!("console DB migrations applied");

    // First-run bootstrap token (CAUTH-02): on an uninitialized console, this
    // regenerates + persists (hash only) a one-time setup token and prints the
    // raw value to stdout exactly once. No-op on an initialized console. Runs
    // AFTER migrate, BEFORE serve (RESEARCH "Bootstrap order").
    ensure_bootstrap_token(&pool).await?;

    // WR-07: background session reaper. A detached tokio task periodically
    // deletes sessions past their absolute `expires_at` so the table cannot grow
    // without bound from abandoned (never-logged-out) sessions. Runs one sweep
    // immediately at boot, then on a fixed interval. A failed sweep is logged and
    // retried next tick — it never blocks request serving.
    {
        let reap_pool = pool.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(SESSION_REAP_INTERVAL);
            loop {
                ticker.tick().await;
                match queries::delete_expired_sessions(&reap_pool).await {
                    Ok(n) if n > 0 => tracing::info!(reaped = n, "expired sessions reaped"),
                    Ok(_) => {}
                    Err(e) => tracing::warn!(error = %e, "session reaper sweep failed"),
                }
            }
        });
    }

    // HOOK-01: background webhook delivery worker. Mirrors the session reaper —
    // a detached tokio task that, every tick, claims due deliveries
    // (FOR UPDATE SKIP LOCKED), SSRF-guards the target, HMAC-signs the body, and
    // POSTs it, recording delivered | backoff retry | dead. State is durable in
    // Postgres so the queue survives a restart. A failed tick is logged and
    // retried next tick — it never panics the loop or blocks request serving.
    {
        let worker_pool = pool.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(WEBHOOK_TICK_INTERVAL);
            loop {
                ticker.tick().await;
                if let Err(e) = webhooks::worker::tick(&worker_pool).await {
                    tracing::warn!(error = %e, "webhook worker tick failed");
                }
            }
        });
    }

    // HOOK-03: background webhook maintenance — prune terminal deliveries past
    // the retention window and recover stale 'delivering' rows (a worker that
    // crashed mid-flight). Hourly; failures logged, never fatal.
    {
        let maint_pool = pool.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(WEBHOOK_MAINT_INTERVAL);
            loop {
                ticker.tick().await;
                if let Err(e) = webhooks::worker::prune_tick(&maint_pool).await {
                    tracing::warn!(error = %e, "webhook pruning tick failed");
                }
                if let Err(e) = webhooks::worker::reap_stale_tick(&maint_pool).await {
                    tracing::warn!(error = %e, "webhook stale-reap tick failed");
                }
            }
        });
    }

    // Owned bind address: TcpListener::new requires a 'static address, and `cfg`
    // is moved into the router below.
    let bind_addr = cfg.bind_addr.clone();

    // Build the router (affix_state injects pool + cfg into every Depot).
    // WR-03: `build` validates the five Ory admin URLs and fails fast at boot
    // (before binding the listener) if any is malformed, rather than degrading
    // to opaque per-request 502s.
    let router = routes::build(pool.clone(), cfg)?;

    tracing::info!(%bind_addr, "starting ory-console-backend");

    let acceptor = TcpListener::new(bind_addr).bind().await;
    Server::new(acceptor).serve(router).await;

    Ok(())
}
