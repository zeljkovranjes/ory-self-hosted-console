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

    /// Resource is locked / busy — e.g. a config write is already in progress
    /// for the affected service (the per-service write lock is held). CONTEXT/
    /// RESEARCH Open Question 3: a save-in-progress returns busy as 409 Conflict
    /// (the semantically correct status for a locked resource), NOT 400. The
    /// String carries a stable machine reason (e.g. `config_busy`) for the log;
    /// the client receives only the generic `{"error":"conflict"}` body. -> 409
    #[error("conflict: {0}")]
    Conflict(String),

    /// Config-edit schema validation failed. Carries the per-field errors
    /// (JSON-Pointer path + value-free message) collected by
    /// `config_edit::schema::validate_full`. Renders as 422 with
    /// `{"error":"validation_failed","fields":[{path,message}…]}` — the field
    /// errors are schema-derived and value-free (BACK-07 / T-04-15), so they are
    /// safe to return. -> 422
    #[error("validation failed ({} field error(s))", .0.len())]
    Validation(Vec<crate::config_edit::schema::FieldError>),

    /// A restarted service did not pass `/health/ready` within the timeout, so the
    /// config-edit flow rolled back to the last-known-good. Renders as 502
    /// `{"error":"health_failed","status":"failed"}` — no service name, file path,
    /// or value is leaked. -> 502
    #[error("health check failed (rolled back)")]
    HealthFailed,

    /// Upstream Ory service failure (transport, decode, or non-2xx response).
    /// CONTEXT/BACK-02 require 502 (NOT 500) for upstream failures. The detail
    /// string is for SERVER-SIDE LOGS ONLY — it carries a sanitised summary
    /// (e.g. "ory upstream status 404") and NEVER the raw upstream body, the
    /// admin base URL, or any credential (BACK-07). The client receives only the
    /// generic `{"error":"upstream_error"}` machine code. -> 502
    #[error("upstream error: {0}")]
    Upstream(String),
}

impl AppError {
    /// HTTP status for this error.
    pub fn status_code(&self) -> StatusCode {
        match self {
            AppError::Unauthorized => StatusCode::UNAUTHORIZED,
            AppError::Forbidden => StatusCode::FORBIDDEN,
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::Validation(_) => StatusCode::UNPROCESSABLE_ENTITY,
            AppError::Upstream(_) | AppError::HealthFailed => StatusCode::BAD_GATEWAY,
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
            AppError::Conflict(_) => "conflict",
            AppError::Validation(_) => "validation_failed",
            AppError::HealthFailed => "health_failed",
            AppError::Upstream(_) => "upstream_error",
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

        // Server-side detail (NEVER to the client). 500 is an error-level event;
        // 502 (upstream Ory failure) is logged at warn — the sanitised detail
        // string lands in the LOGS only, never the body (BACK-07).
        if status == StatusCode::INTERNAL_SERVER_ERROR {
            tracing::error!(error = %self, "request failed with internal error");
        } else if status == StatusCode::BAD_GATEWAY {
            tracing::warn!(error = %self, "request failed with upstream error");
        } else {
            tracing::debug!(error = %self, status = %status, "request rejected");
        }

        let body = match &self {
            // 4xx BadRequest: the message is validation feedback, safe to send.
            AppError::BadRequest(msg) => {
                serde_json::json!({ "error": self.machine_code(), "message": msg })
            }
            // 422: the field errors are schema-derived + value-free (T-04-15),
            // so the array of {path, message} is safe to return to the client.
            AppError::Validation(fields) => {
                serde_json::json!({ "error": self.machine_code(), "fields": fields })
            }
            // 502 health rollback: report the failed status without any detail.
            AppError::HealthFailed => {
                serde_json::json!({ "error": self.machine_code(), "status": "failed" })
            }
            // Everything else: machine code only — no detail, no secrets.
            _ => serde_json::json!({ "error": self.machine_code() }),
        };

        res.status_code(status);
        res.render(Json(body));
    }
}
