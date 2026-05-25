//! Console state + identity endpoints.
//!
//! - `console_state` — `GET /api/console/state` (PUBLIC, secret-free). Reports
//!   `{initialized, github_oauth_enabled}` so the frontend (Phase 5) can decide
//!   between the `/setup` and `/login` flows and whether to render the GitHub
//!   button. Carries NO secret (threat T-02-24).
//! - `me` — `GET /api/console/me` (PROTECTED, behind the auth chokepoint).
//!   Returns the secret-free `AdminDto` for the session's admin (no hash, no
//!   token), sourced from the `Session` injected by `auth_guard`.

use salvo::prelude::*;
use serde::Serialize;
use sqlx::PgPool;

use crate::config::Config;
use crate::db::models::Session;
use crate::db::queries;
use crate::error::AppError;

/// Secret-free identity DTO (BACK-07 / Pattern 6): id/email/name + a derived
/// `github_linked` flag — never a hash or token.
#[derive(Debug, Serialize)]
pub struct MeDto {
    pub id: String,
    pub email: String,
    pub name: String,
    pub github_linked: bool,
}

/// `GET /api/console/state` — PUBLIC first-run signal. No auth, no secret.
#[handler]
pub async fn console_state(depot: &mut Depot, res: &mut Response) -> Result<(), AppError> {
    let pool = depot
        .obtain::<PgPool>()
        .map_err(|_| AppError::Internal("pool missing from depot".into()))?
        .clone();
    let cfg = depot
        .obtain::<Config>()
        .map_err(|_| AppError::Internal("config missing from depot".into()))?
        .clone();

    // is_initialized fails CLOSED to "initialized" on a DB blip, but here we want
    // the true value for the redirect signal; a DB error surfaces as 500.
    let initialized = queries::is_initialized(&pool).await?;

    res.render(Json(serde_json::json!({
        "initialized": initialized,
        "github_oauth_enabled": cfg.github_oauth_enabled(),
    })));
    Ok(())
}

/// `GET /api/console/me` — PROTECTED. Returns the authenticated admin's
/// secret-free profile. The `Session` is injected by `auth_guard`.
#[handler]
pub async fn me(depot: &mut Depot, res: &mut Response) -> Result<(), AppError> {
    let pool = depot
        .obtain::<PgPool>()
        .map_err(|_| AppError::Internal("pool missing from depot".into()))?
        .clone();

    // auth_guard guarantees a Session in the Depot on the protected subtree.
    let admin_id = depot
        .obtain::<Session>()
        .map_err(|_| AppError::Unauthorized)?
        .admin_id;

    let admin = queries::get_admin_by_id(&pool, admin_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    res.render(Json(MeDto {
        id: admin.id.to_string(),
        email: admin.email,
        name: admin.name,
        github_linked: admin.github_user_id.is_some(),
    }));
    Ok(())
}
