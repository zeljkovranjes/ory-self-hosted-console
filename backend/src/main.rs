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
use ory_console_backend::events;
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

/// EVT-01: how often the event-stream fan-out task reads new audit rows past each
/// sink's cursor and enqueues deliveries. A short cadence keeps the stream fresh
/// without scanning the audit log too aggressively on a low-volume console.
const EVENT_FANOUT_INTERVAL: Duration = Duration::from_secs(5);

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

    // Phase 12 (FLAG-01, Pitfall 5): load the feature-flag cache AFTER migrate (so
    // `0007` is applied and the table exists) and BEFORE serve (so no gated route
    // is ever reachable with an empty cache — fail-closed boot). The cache is
    // injected into every Depot via affix_state inside `routes::build`.
    let flags = ory_console_backend::features::FeatureFlags::load(&pool).await?;
    tracing::info!("feature-flag cache loaded");

    // Phase 16 (OBS-02): install the process-global Prometheus recorder ONCE,
    // AFTER the flag cache load and BEFORE serve, so the `GET /metrics` handler
    // (mounted internal-only in `routes::build`) has a live render handle the
    // moment the listener binds. Idempotent/re-entrant (tolerates an already-set
    // recorder). The endpoint is scraped container-to-container by the opt-in
    // `observability` Prometheus on the INTERNAL network — never host-published.
    ory_console_backend::metrics::install_recorder();
    tracing::info!("prometheus metrics recorder installed");

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
        // EFFECTIVE SSRF posture (fail-closed double-gate, T-11-01/02). In the
        // production posture this is ALWAYS false (the worker fully enforces the
        // SSRF classifier); it can only be true under the dev insecure-cookie
        // escape hatch AND an explicit WEBHOOK_ALLOW_PRIVATE_TARGETS — the live
        // acceptance gate's posture, where the echo receiver lives on the internal
        // docker network. The resolve + pin + redirects-off hardening applies
        // regardless, so even when relaxed the connection cannot be rebound.
        let allow_private = cfg.webhook_allow_private_targets();
        if allow_private {
            tracing::warn!(
                "WEBHOOK_ALLOW_PRIVATE_TARGETS is active (dev/acceptance posture): the \
                 webhook worker may deliver to private/loopback targets — NEVER use this in \
                 production"
            );
        }
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(WEBHOOK_TICK_INTERVAL);
            loop {
                ticker.tick().await;
                if let Err(e) = webhooks::worker::tick_with(&worker_pool, allow_private).await {
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

    // EVT-01/02/03: the event-stream workers (Phase 17). Three detached tokio
    // tasks mirroring the HOOK worker pattern, reusing the SAME OFF-by-default
    // `WEBHOOK_ALLOW_PRIVATE_TARGETS` escape hatch (production = false) so they
    // share one outbound-SSRF posture with the webhook worker — no second env var.
    //
    //   (1) fan-out: read new console_audit_log rows past each enabled sink's
    //       cursor, redact, and enqueue one event_deliveries row per (sink, event).
    //   (2) delivery: claim due deliveries (SKIP LOCKED) and dispatch through the
    //       Sink registry (webhook re-validates SSRF at delivery time), recording
    //       delivered | backoff retry | dead.
    //   (3) maintenance: prune terminal deliveries past retention + recover stale
    //       'delivering' rows.
    {
        // (1) fan-out — audit → event_deliveries.
        let fanout_pool = pool.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(EVENT_FANOUT_INTERVAL);
            loop {
                ticker.tick().await;
                if let Err(e) =
                    events::worker::fan_out_tick(&fanout_pool, events::worker::FANOUT_BATCH).await
                {
                    tracing::warn!(error = %e, "event fan-out tick failed");
                }
            }
        });

        // (2) delivery — claim → dispatch via Sink::deliver. Reuses the SAME
        // allow_private posture as the webhook worker (production false).
        let delivery_pool = pool.clone();
        let event_allow_private = cfg.webhook_allow_private_targets();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(WEBHOOK_TICK_INTERVAL);
            loop {
                ticker.tick().await;
                if let Err(e) =
                    events::worker::delivery_tick_with(&delivery_pool, event_allow_private).await
                {
                    tracing::warn!(error = %e, "event delivery tick failed");
                }
            }
        });

        // (3) maintenance — prune + reap, hourly.
        let event_maint_pool = pool.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(WEBHOOK_MAINT_INTERVAL);
            loop {
                ticker.tick().await;
                if let Err(e) = events::worker::prune_tick(&event_maint_pool).await {
                    tracing::warn!(error = %e, "event pruning tick failed");
                }
                if let Err(e) = events::worker::reap_stale_tick(&event_maint_pool).await {
                    tracing::warn!(error = %e, "event stale-reap tick failed");
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
    let router = routes::build(pool.clone(), cfg, flags)?;

    tracing::info!(%bind_addr, "starting ory-console-backend");

    let acceptor = TcpListener::new(bind_addr).bind().await;
    Server::new(acceptor).serve(router).await;

    Ok(())
}
