//! Map each Ory crate's `apis::Error<T>` to a sanitised [`AppError::Upstream`]
//! (HTTP 502) — RESEARCH Pattern 4 + Pitfall 5.
//!
//! BACK-07: the returned `AppError` NEVER carries the raw upstream body
//! (`ResponseContent.content`), the admin base URL, or any credential. Only a
//! sanitised summary (e.g. `"ory upstream status 404"`) is placed in the error,
//! and even that is rendered to LOGS only — the `AppError` `Writer` collapses
//! `Upstream` to the generic `{"error":"upstream_error"}` body.
//!
//! The four Ory crates each export their OWN `apis::Error<T>` type (identical
//! shape, DISTINCT types — RESEARCH Pitfall 5), so a single generic mapper
//! cannot span them. The `map_ory_err!` macro generates one mapper per crate.

use crate::error::AppError;

/// Generate a per-crate `Error<T> -> AppError::Upstream` mapper.
///
/// `$name` is the mapper fn name; `$apis` is the crate's `apis` module path
/// (which exports `Error` and `ResponseContent`). The four enum variants are
/// identical in shape across all four crates, so the body is shared.
macro_rules! map_ory_err {
    ($name:ident, $krate:ident) => {
        /// Map this crate's `apis::Error<T>` to a sanitised `AppError::Upstream`
        /// (502). Logs the failure cause server-side at `warn`; NEVER returns the
        /// raw upstream body or the admin URL to the client (BACK-07).
        pub fn $name<T: std::fmt::Debug>(e: $krate::apis::Error<T>) -> AppError {
            use $krate::apis::Error;
            match e {
                // Non-2xx upstream response. Log ONLY the status server-side; the
                // raw upstream body field is deliberately never read/forwarded.
                Error::ResponseError(rc) => {
                    tracing::warn!(status = %rc.status, "ory upstream returned error status");
                    AppError::Upstream(format!("ory upstream status {}", rc.status))
                }
                Error::Reqwest(err) => {
                    tracing::warn!(error = %err, "ory upstream transport error");
                    AppError::Upstream("ory upstream unreachable".into())
                }
                Error::Serde(err) => {
                    tracing::warn!(error = %err, "ory upstream response decode error");
                    AppError::Upstream("ory upstream decode error".into())
                }
                Error::Io(err) => {
                    tracing::warn!(error = %err, "ory io error");
                    AppError::Upstream("ory io error".into())
                }
            }
        }
    };
}

map_ory_err!(map_kratos_err, ory_kratos_client);
map_ory_err!(map_hydra_err, ory_hydra_client);
map_ory_err!(map_keto_err, ory_keto_client);
map_ory_err!(map_oathkeeper_err, ory_oathkeeper_client);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AppError;
    use ory_kratos_client::apis::{Error, ResponseContent};
    use salvo::http::StatusCode as SalvoStatus;

    /// A `ResponseError` carrying a (secret-looking) raw upstream body maps to
    /// `AppError::Upstream` whose Display contains ONLY the status — never the
    /// body. This is the BACK-07 body-leak negative assertion.
    #[test]
    fn response_error_maps_to_upstream_without_body_leak() {
        let secret_body = "SUPER_SECRET_UPSTREAM_BODY_should_never_surface";
        let rc: ResponseContent<()> = ResponseContent {
            status: reqwest::StatusCode::NOT_FOUND,
            content: secret_body.to_string(),
            entity: None,
        };
        let err = map_kratos_err::<()>(Error::ResponseError(rc));

        // Must be the Upstream variant (-> 502), NOT Internal (500).
        assert!(matches!(err, AppError::Upstream(_)), "got {err:?}");
        assert_eq!(err.status_code(), SalvoStatus::BAD_GATEWAY);
        assert_eq!(err.machine_code(), "upstream_error");

        // The sanitised Display/detail must NOT contain the raw upstream body.
        let detail = err.to_string();
        assert!(
            !detail.contains(secret_body),
            "upstream body leaked into AppError detail: {detail}"
        );
        // The status IS allowed in the (log-only) detail.
        assert!(detail.contains("404"), "status should appear in log detail: {detail}");
    }

    /// A decode (`Serde`) failure maps to a generic Upstream error with a fixed,
    /// detail-free message — no upstream specifics leak.
    #[test]
    fn serde_error_maps_to_generic_upstream() {
        let serde_err = serde_json::from_str::<i32>("not a number").unwrap_err();
        let err = map_hydra_err::<()>(Error::Serde(serde_err).into_hydra());
        assert!(matches!(err, AppError::Upstream(_)), "got {err:?}");
        assert_eq!(err.to_string(), "upstream error: ory upstream decode error");
    }

    // Helper: the test constructs a kratos `Error::Serde`, but `map_hydra_err`
    // wants a hydra `Error`. Re-wrap the inner serde error into a hydra Error so
    // the cross-crate mapper is exercised with the right type.
    trait IntoHydraError {
        fn into_hydra(self) -> ory_hydra_client::apis::Error<()>;
    }
    impl IntoHydraError for Error<()> {
        fn into_hydra(self) -> ory_hydra_client::apis::Error<()> {
            match self {
                Error::Serde(e) => ory_hydra_client::apis::Error::Serde(e),
                _ => unreachable!("test only wraps Serde"),
            }
        }
    }
}
