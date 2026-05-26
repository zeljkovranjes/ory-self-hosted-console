//! Feature-flag management handlers (FLAG-02 / FLAG-04).
//!
//! Both routes sit on the PROTECTED subtree (inherit `auth_guard` 401 +
//! `csrf_guard` 403 on the PUT — T-12-05). They MANAGE flags and are therefore
//! NEVER themselves `FeatureFlagHoop`-gated.
//!
//!   - GET  /api/console/features      → the seeded set joined with the code-side
//!     `FEATURE_META` (enabled + label + requires_runtime). csrf-exempt (GET).
//!   - PUT  /api/console/features/{key} → toggle a flag, refresh the in-process
//!     cache, return the new state. The state-changing PUT is auto-audited by the
//!     existing response-phase `audit_hoop` (actor-from-session, T-12-04) — NO
//!     manual audit insert here (Don't-Hand-Roll). Unknown key → 404 (T-12-06).
//!
//! A `requires_runtime` flag turned ON does NOT 502 in this phase — it is
//! store-only; Phase 16 owns the health probe (Pitfall 7 / T-12-07).

use salvo::prelude::*;
use serde::{Deserialize, Serialize};

use crate::error::AppError;

use super::{meta_for, queries, FeatureFlags, FEATURE_META};

/// Obtain the console pool from the Depot, cloning BEFORE any await (mirrors
/// `apikeys::routes::pool`).
fn pool(depot: &mut Depot) -> Result<sqlx::PgPool, AppError> {
    Ok(depot
        .obtain::<sqlx::PgPool>()
        .map_err(|_| AppError::Internal("pool missing from depot".into()))?
        .clone())
}

/// One feature's state in the GET response: persisted `enabled` joined with the
/// code-side label + `requires_runtime` (omitted when false, per the contract).
#[derive(Debug, Serialize)]
pub struct FeatureState {
    pub enabled: bool,
    pub label: &'static str,
    #[serde(skip_serializing_if = "is_false")]
    pub requires_runtime: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// The GET response: `{ "features": { "<key>": { enabled, label, requires_runtime? } } }`.
#[derive(Debug, Serialize)]
pub struct FeaturesResponse {
    pub features: std::collections::BTreeMap<&'static str, FeatureState>,
}

/// GET /api/console/features — the seeded flag set joined with `FEATURE_META`.
///
/// Reads the persisted enabled state from the DB (the source of truth) and joins
/// each KNOWN key (from `FEATURE_META`) with its label + `requires_runtime`. A
/// key present in the DB but absent from `FEATURE_META` is ignored (the metadata
/// map is the authoritative surface); a known key absent from the DB defaults to
/// disabled (fail-closed).
#[handler]
pub async fn list_features(depot: &mut Depot) -> Result<Json<FeaturesResponse>, AppError> {
    let pool = pool(depot)?;
    let state = queries::load_all(&pool).await?;

    let mut features = std::collections::BTreeMap::new();
    for (key, meta) in FEATURE_META {
        let enabled = *state.get(*key).unwrap_or(&false);
        features.insert(
            *key,
            FeatureState {
                enabled,
                label: meta.label,
                requires_runtime: meta.requires_runtime,
            },
        );
    }
    Ok(Json(FeaturesResponse { features }))
}

/// The PUT body: `{ "enabled": bool }`.
#[derive(Debug, Deserialize)]
struct SetBody {
    enabled: bool,
}

/// The PUT response: the flag's key + its new enabled state.
#[derive(Debug, Serialize)]
pub struct ToggleResponse {
    pub key: String,
    pub enabled: bool,
}

/// PUT /api/console/features/{key} — toggle a flag (state change → CSRF-guarded).
///
/// Validates the `{key}` against the known set first, parses the strict
/// `{enabled}` body, UPDATEs the row (None → unknown key → 404, never INSERT from
/// input), then refreshes the in-process cache so the next gated request sees the
/// new state. The toggle is audited automatically by the response-phase
/// `audit_hoop` — no manual insert here. A `requires_runtime` flag turned ON
/// returns 2xx (store-only this phase; no 502 path — T-12-07).
#[handler]
pub async fn set_feature(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<ToggleResponse>, AppError> {
    let key = req.param::<String>("key").ok_or(AppError::NotFound)?;
    // Reject unknown keys up front (T-12-06): only known features are toggleable;
    // the DB UPDATE also returns None for an unknown key, so this is defence in
    // depth — never create arbitrary rows from caller input.
    if meta_for(&key).is_none() {
        return Err(AppError::NotFound);
    }

    let body: SetBody = req
        .parse_json()
        .await
        .map_err(|e| AppError::BadRequest(format!("invalid feature body: {e}")))?;

    let pool = pool(depot)?;
    let updated = queries::set_enabled(&pool, &key, body.enabled)
        .await?
        .ok_or(AppError::NotFound)?;

    // Refresh the in-process cache so the next gated request sees the new state
    // without a DB round-trip. Best-effort: a missing cache never fails the write.
    if let Ok(flags) = depot.obtain::<FeatureFlags>() {
        flags.set(&updated.key, updated.enabled);
    }

    Ok(Json(ToggleResponse {
        key: updated.key,
        enabled: updated.enabled,
    }))
}
