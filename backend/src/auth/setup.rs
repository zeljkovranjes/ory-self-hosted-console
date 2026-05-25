//! First-run bootstrap token + token-gated single-use `/setup` (CAUTH-01..03).
//!
//! - `ensure_bootstrap_token` runs once at boot (after migrate, before serve).
//!   On an UNINITIALIZED console it regenerates a fresh 256-bit token every
//!   boot (LOCKED Open Question 1: regenerate-each-uninitialized-boot — a
//!   missed/stale token is invalidated, residual T-02-14 accepted), persists
//!   ONLY its SHA-256 hash, and prints the raw token on exactly one stdout line
//!   plus one `tracing::warn` line. This is the ONLY place the raw token ever
//!   surfaces (Anti-Pattern: never return it via the API).
//! - `require_uninitialized` is a hoop that returns 404 + `skip_rest` once the
//!   console is initialized (CAUTH-01), reading server-side state (fail-closed).
//! - `setup` is the `POST /setup` handler: constant-time token verify (403 on
//!   mismatch), Argon2id admin creation, `initialized=true`, regenerate-on-auth
//!   session, secret-free 201 DTO.

use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::auth::{password, session};
use crate::config::Config;
use crate::db::queries;
use crate::error::AppError;

/// Setup request body. The bootstrap `token` may instead be supplied via the
/// `X-Setup-Token` header (the body field takes precedence when both present).
#[derive(Debug, Deserialize)]
pub struct SetupRequest {
    pub name: String,
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub token: Option<String>,
}

/// Secret-free response DTO (BACK-07 / Pattern 6): no hash, no token, no secret.
#[derive(Debug, Serialize)]
pub struct AdminDto {
    pub id: String,
    pub email: String,
    pub name: String,
}

/// One-time bootstrap-token first-run hook. Called from `main.rs` after
/// migrations and before the listener binds. No-op (prints nothing) on an
/// already-initialized console.
pub async fn ensure_bootstrap_token(pool: &PgPool) -> Result<(), AppError> {
    // Fail-closed: if the state read errors, treat as initialized (do nothing,
    // never reopen setup on a DB blip).
    if queries::is_initialized(pool).await.unwrap_or(true) {
        return Ok(());
    }

    // Regenerate on every uninitialized boot (LOCKED Open Question 1): any
    // previously-printed token is invalidated by overwriting the stored hash.
    let raw = session::generate_token();
    let hash = password::sha256_hex(&raw);
    queries::insert_console_settings(pool, &hash).await?;

    // The ONE deliberate disclosure of the raw token: stdout (for
    // `docker compose logs backend`) + a single warn line. Nothing else logs it.
    println!("FIRST-RUN SETUP TOKEN: {raw}");
    tracing::warn!(
        "FIRST-RUN SETUP TOKEN generated — POST it once to /setup to create the admin. \
         Copy it from this log line; it is regenerated on every restart until setup completes."
    );

    Ok(())
}

/// Hoop guarding `/setup`: once the console is initialized, respond 404 and
/// stop the chain so the handler never runs (CAUTH-01 single-use). Fail-closed:
/// a state-read error is treated as initialized (404), never as "open".
#[handler]
pub async fn require_uninitialized(depot: &mut Depot, res: &mut Response, ctrl: &mut FlowCtrl) {
    let pool = match depot.obtain::<PgPool>() {
        Ok(p) => p,
        Err(_) => {
            res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
            ctrl.skip_rest();
            return;
        }
    };

    let initialized = queries::is_initialized(pool).await.unwrap_or(true);
    if initialized {
        res.status_code(StatusCode::NOT_FOUND);
        res.render(Json(serde_json::json!({ "error": "not_found" })));
        ctrl.skip_rest();
    }
}

/// `POST /setup` — token-gated first-run admin creation (CAUTH-01..03, CAUTH-05).
#[handler]
pub async fn setup(req: &mut Request, depot: &mut Depot, res: &mut Response) -> Result<(), AppError> {
    let pool = depot
        .obtain::<PgPool>()
        .map_err(|_| AppError::Internal("pool missing from depot".into()))?
        .clone();
    let cfg = depot
        .obtain::<Config>()
        .map_err(|_| AppError::Internal("config missing from depot".into()))?
        .clone();

    // Token from the X-Setup-Token header, overridden by the body field if set.
    let header_token = req
        .header::<String>("X-Setup-Token")
        .filter(|t| !t.is_empty());

    let body: SetupRequest = req
        .parse_json()
        .await
        .map_err(|_| AppError::BadRequest("invalid JSON body".into()))?;

    let submitted = body
        .token
        .clone()
        .filter(|t| !t.is_empty())
        .or(header_token)
        .ok_or(AppError::Forbidden)?;

    // Password policy BEFORE touching secrets/DB.
    password::enforce_password_policy(&body.password)?;

    // Load the stored bootstrap hash. No row / no hash => not in a setup state.
    let settings = queries::get_console_settings(&pool)
        .await?
        .ok_or(AppError::Forbidden)?;
    let stored_hash = settings.bootstrap_token_hash.ok_or(AppError::Forbidden)?;

    // Constant-time verify; generic 403 on mismatch (no field disclosure).
    if !password::verify_token_ct(&submitted, &stored_hash) {
        return Err(AppError::Forbidden);
    }

    // Create the local admin with an Argon2id hash, flip initialized, mint a
    // fresh session (regenerate-on-auth), set the hardened cookie.
    let pw_hash = password::hash_password(&body.password)?;
    let admin_id = queries::insert_admin(&pool, &body.email, &body.name, &pw_hash).await?;
    queries::mark_initialized(&pool).await?;

    let ip = req.remote_addr().to_string();
    let user_agent = req.header::<String>("user-agent");
    let minted = session::mint_session(
        &pool,
        admin_id,
        Some(ip.as_str()),
        user_agent.as_deref(),
        &cfg,
    )
    .await?;
    session::set_session_cookie(res, &minted.raw_token, cfg.session_absolute_secs, &cfg);

    res.status_code(StatusCode::CREATED);
    res.render(Json(AdminDto {
        id: admin_id.to_string(),
        email: body.email,
        name: body.name,
    }));
    Ok(())
}
