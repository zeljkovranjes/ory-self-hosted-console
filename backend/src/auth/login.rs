//! `POST /login` + `POST /logout` (CAUTH-05 session half).
//!
//! - `login`: verify credentials with Argon2id (constant-time), regenerate the
//!   session on success (OWASP: delete any prior session for the admin, mint a
//!   fresh one), set the hardened cookie, return a secret-free 200 DTO. On any
//!   failure return a GENERIC 401 — never disclose whether the email existed or
//!   the password was wrong (T-02-11).
//! - `logout`: delete the session row keyed by the cookie token and clear the
//!   cookie (always 200; idempotent).

use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::auth::{password, session};
use crate::config::Config;
use crate::db::queries;
use crate::error::AppError;

/// Login request body.
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

/// Secret-free response DTO (BACK-07): no hash, no token.
#[derive(Debug, Serialize)]
pub struct AdminDto {
    pub id: String,
    pub email: String,
    pub name: String,
}

/// `POST /login` — credential check + regenerate-on-auth session (CAUTH-05).
#[handler]
pub async fn login(req: &mut Request, depot: &mut Depot, res: &mut Response) -> Result<(), AppError> {
    let pool = depot
        .obtain::<PgPool>()
        .map_err(|_| AppError::Internal("pool missing from depot".into()))?
        .clone();
    let cfg = depot
        .obtain::<Config>()
        .map_err(|_| AppError::Internal("config missing from depot".into()))?
        .clone();

    let body: LoginRequest = req
        .parse_json()
        .await
        .map_err(|_| AppError::BadRequest("invalid JSON body".into()))?;

    // Look up the admin. A missing admin and a wrong password both collapse to
    // the SAME generic 401 (no field disclosure, T-02-11).
    let admin = queries::get_admin_by_email(&pool, &body.email).await?;
    let admin = match admin {
        Some(a) => a,
        None => return Err(AppError::Unauthorized),
    };

    // OAuth-only admins have no password_hash; password login then fails 401.
    let ok = match &admin.password_hash {
        Some(phc) => password::verify_password(&body.password, phc),
        None => false,
    };
    if !ok {
        return Err(AppError::Unauthorized);
    }

    // Regenerate-on-auth: clear any pre-auth/stale sessions, mint fresh (OWASP).
    queries::delete_sessions_for_admin(&pool, admin.id).await?;
    queries::update_last_login(&pool, admin.id).await?;

    let ip = req.remote_addr().to_string();
    let user_agent = req.header::<String>("user-agent");
    let minted = session::mint_session(
        &pool,
        admin.id,
        Some(ip.as_str()),
        user_agent.as_deref(),
        &cfg,
    )
    .await?;
    session::set_session_cookie(res, &minted.raw_token, cfg.session_absolute_secs, &cfg);

    res.status_code(StatusCode::OK);
    res.render(Json(AdminDto {
        id: admin.id.to_string(),
        email: admin.email,
        name: admin.name,
    }));
    Ok(())
}

/// `POST /logout` — delete the session row + clear the cookie. Idempotent: a
/// missing/invalid cookie still returns 200 (Plan 03 puts this behind the
/// auth + CSRF hoops; the handler itself is safe to call unauthenticated).
#[handler]
pub async fn logout(req: &mut Request, depot: &mut Depot, res: &mut Response) -> Result<(), AppError> {
    let pool = depot
        .obtain::<PgPool>()
        .map_err(|_| AppError::Internal("pool missing from depot".into()))?
        .clone();
    let cfg = depot
        .obtain::<Config>()
        .map_err(|_| AppError::Internal("config missing from depot".into()))?
        .clone();

    let name = session::cookie_name(&cfg);
    if let Some(raw) = req.cookie(name).map(|c| c.value().to_owned()) {
        // Best-effort delete; a missing row is fine.
        let _ = session::delete_session(&pool, &raw).await;
    }
    session::clear_session_cookie(res, &cfg);

    res.status_code(StatusCode::OK);
    res.render(Json(serde_json::json!({ "status": "logged_out" })));
    Ok(())
}
