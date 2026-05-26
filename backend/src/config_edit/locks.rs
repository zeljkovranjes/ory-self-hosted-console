//! Per-service write lock (RESEARCH Pattern 5 — no interleaving / lost updates).
//!
//! A config write is a non-atomic multi-step flow (load -> merge -> validate ->
//! backup -> write -> restart -> health-poll). Two concurrent writes to the SAME
//! service would interleave and risk a lost update or a torn restart, so each
//! service has its own `tokio::sync::Mutex`. A held lock surfaces as
//! `AppError::Conflict("config_busy")` (409) — CONTEXT/RESEARCH Open Question 3: a
//! save-in-progress is a Conflict, not a 400.
//!
//! Scope (RESEARCH A6): a single backend instance, so an in-process mutex is
//! sufficient. Horizontal scaling (multiple instances) would need a shared lock —
//! out of scope for v1, noted for future multi-instance work.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use tokio::sync::{Mutex, OwnedMutexGuard};

use crate::error::AppError;

/// The known config-editable services. A lock is created lazily per service on
/// first acquire; an unknown service yields `AppError::NotFound`.
const SERVICES: &[&str] = &["kratos", "hydra", "keto", "oathkeeper", "polis"];

/// One write lock per service, keyed by the canonical `'static` service name.
type LockRegistry = Mutex<HashMap<&'static str, Arc<Mutex<()>>>>;

/// Process-wide registry of one `Arc<Mutex<()>>` per service.
fn registry() -> &'static LockRegistry {
    static REG: OnceLock<LockRegistry> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Canonicalise a service name to its `'static` key (or `None` if unknown).
fn service_key(service: &str) -> Option<&'static str> {
    SERVICES.iter().copied().find(|s| *s == service)
}

/// Try to acquire the write lock for `service` WITHOUT waiting.
///
/// Returns an `OwnedMutexGuard` (released on drop) on success. If the lock is
/// already held, returns `AppError::Conflict("config_busy")` (409). An unknown
/// service returns `AppError::NotFound`.
pub async fn try_acquire(service: &str) -> Result<OwnedMutexGuard<()>, AppError> {
    let key = service_key(service).ok_or(AppError::NotFound)?;

    // Get (or lazily create) this service's lock Arc. The registry mutex is held
    // only briefly to clone the Arc out — never across the per-service try_lock.
    let svc_lock = {
        let mut reg = registry().lock().await;
        reg.entry(key)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    };

    svc_lock
        .try_lock_owned()
        .map_err(|_| AppError::Conflict("config_busy".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn lock_serialises_per_service() {
        // Acquire kratos -> held.
        let guard = try_acquire("kratos").await.expect("first acquire");

        // A second try on the SAME service is busy (409 Conflict).
        let busy = try_acquire("kratos").await;
        assert!(
            matches!(busy, Err(AppError::Conflict(ref r)) if r == "config_busy"),
            "second kratos acquire must be config_busy; got {busy:?}"
        );

        // A DIFFERENT service acquires concurrently.
        let other = try_acquire("hydra").await.expect("different service ok");
        drop(other);

        // Releasing the kratos guard frees it for re-acquire.
        drop(guard);
        let reacquire = try_acquire("kratos").await;
        assert!(reacquire.is_ok(), "kratos re-acquires after release");
    }

    #[tokio::test]
    async fn unknown_service_is_not_found() {
        assert!(matches!(
            try_acquire("nope").await,
            Err(AppError::NotFound)
        ));
    }
}
