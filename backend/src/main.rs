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

use ory_console_backend::auth::setup::ensure_bootstrap_token;
use ory_console_backend::config::Config;
use ory_console_backend::error::AppError;
use ory_console_backend::{db, routes};

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

    // Owned bind address: TcpListener::new requires a 'static address, and `cfg`
    // is moved into the router below.
    let bind_addr = cfg.bind_addr.clone();

    // Build the router (affix_state injects pool + cfg into every Depot).
    let router = routes::build(pool.clone(), cfg);

    tracing::info!(%bind_addr, "starting ory-console-backend");

    let acceptor = TcpListener::new(bind_addr).bind().await;
    Server::new(acceptor).serve(router).await;

    Ok(())
}
