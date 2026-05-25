//! Typed application errors that render as generic JSON and NEVER leak secrets.
//!
//! BACK-07 / Pitfall 4: the DSN, password/token hashes, and any sqlx source
//! string must never reach a response body. Each variant maps to a stable
//! machine code (`{"error":"<code>"}`) and an HTTP status. Internal detail for
//! `Db`/`Internal`/`Config` is logged server-side (at error level) and is
//! deliberately omitted from the client-facing body — the body is a fixed,
//! detail-free string per variant.

use salvo::http::StatusCode;
use salvo::prelude::*;
use salvo::writing::Json;

/// Application error. The `Display`/source detail is for logs only; the JSON
/// body rendered to clients is the fixed `machine_code()` string.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// Database / sqlx failure. Detail logged, never returned. -> 500
    #[error("database error")]
    Db(#[from] sqlx::Error),

    /// Migration failure at boot (separate sqlx error family). -> 500
    #[error("migration error")]
    Migrate(#[from] sqlx::migrate::MigrateError),

    /// Configuration/env error (e.g. missing DSN). Detail logged. -> 500
    #[error("configuration error: {0}")]
    Config(String),

    /// No / invalid session. -> 401
    #[error("unauthorized")]
    Unauthorized,

    /// Authenticated but not permitted (e.g. failed CSRF). -> 403
    #[error("forbidden")]
    Forbidden,

    /// Resource (or guarded route, e.g. /setup after init) absent. -> 404
    #[error("not found")]
    NotFound,

    /// Client input rejected (validation). The message is operator-safe
    /// (e.g. "password too short") — never echo secrets into it. -> 400
    #[error("bad request: {0}")]
    BadRequest(String),

    /// Catch-all internal failure. Detail logged, never returned. -> 500
    #[error("internal error: {0}")]
    Internal(String),
}

impl AppError {
    /// HTTP status for this error.
    pub fn status_code(&self) -> StatusCode {
        match self {
            AppError::Unauthorized => StatusCode::UNAUTHORIZED,
            AppError::Forbidden => StatusCode::FORBIDDEN,
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Db(_)
            | AppError::Migrate(_)
            | AppError::Config(_)
            | AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Stable machine code for the client-facing JSON body. Carries NO secret
    /// or source detail — 500-class variants collapse to generic codes.
    pub fn machine_code(&self) -> &'static str {
        match self {
            AppError::Db(_) | AppError::Migrate(_) => "internal_error",
            AppError::Config(_) => "internal_error",
            AppError::Internal(_) => "internal_error",
            AppError::Unauthorized => "unauthenticated",
            AppError::Forbidden => "forbidden",
            AppError::NotFound => "not_found",
            AppError::BadRequest(_) => "bad_request",
        }
    }
}

/// Render `AppError` to a Salvo response: log full detail server-side (5xx),
/// then emit ONLY the generic machine code as JSON. The 4xx `BadRequest`
/// message is operator-safe and forwarded; 5xx detail is logged, not sent.
#[async_trait]
impl Writer for AppError {
    async fn write(self, _req: &mut Request, _depot: &mut Depot, res: &mut Response) {
        let status = self.status_code();

        // Server-side detail (NEVER to the client). 5xx is an error-level event.
        if status == StatusCode::INTERNAL_SERVER_ERROR {
            tracing::error!(error = %self, "request failed with internal error");
        } else {
            tracing::debug!(error = %self, status = %status, "request rejected");
        }

        let body = match &self {
            // 4xx BadRequest: the message is validation feedback, safe to send.
            AppError::BadRequest(msg) => {
                serde_json::json!({ "error": self.machine_code(), "message": msg })
            }
            // Everything else: machine code only — no detail, no secrets.
            _ => serde_json::json!({ "error": self.machine_code() }),
        };

        res.status_code(status);
        res.render(Json(body));
    }
}
