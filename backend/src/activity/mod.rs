//! Derived recent-activity stub (ACT-03, v1).
//!
//! `GET /api/activity` returns a SINGLE derived list composed from existing
//! Phase-10 primitives — the most recent Kratos sessions (recent
//! authentications) and the most recent courier messages (recent sends) — folded
//! into one newest-first feed. It introduces NO new persistence and NO new
//! table: it is a thin read-only projection over the typed admin crates that the
//! sessions/courier wrappers already use.
//!
//! Labeled `"v1"` (a derived approximation, not an event stream): self-hosted
//! Ory has no `events_api` (that lives only in the Network `ory-client`), so a
//! true activity feed would require backend event capture. v1 derives what it
//! can from sessions + courier without persisting anything.
//!
//! # OBS-03 supersession (Phase 16)
//!
//! When the `observability` profile + flag are ON, the LIVE Activity surface is
//! the Prometheus-backed series at `GET /api/console/metrics/activity`
//! (`observability::prometheus::get_metrics_activity`) — real login/sign-up rates
//! and latency from the scraped metrics, profile-health-probed (FLAG-04). This
//! derived `GET /api/activity` route is RETAINED UNFLAGGED as the documented v1
//! fallback so the existing Project→Activity page keeps working when the
//! observability profile is OFF (it is not silently broken). The two are distinct
//! routes: `/api/activity` (derived, always available) vs
//! `/api/console/metrics/activity` (Prometheus-backed, observability-gated).

use ory_kratos_client::apis::{courier_api, identity_api};
use salvo::prelude::*;
use serde::Serialize;

use crate::error::AppError;
use crate::ory::clients::OryClients;
use crate::ory::error::map_kratos_err;

/// How many of each source (sessions / courier) to pull into the derived feed.
const RECENT_PER_SOURCE: i64 = 25;

/// One derived activity entry. `kind` distinguishes the source
/// (`authentication` | `courier`); `detail` carries the raw upstream object so
/// the frontend can render specifics without a second round-trip.
#[derive(Debug, Clone, Serialize)]
pub struct ActivityEntry {
    pub kind: &'static str,
    pub detail: serde_json::Value,
}

/// The derived-activity envelope. `source` is fixed to `"derived"` and `version`
/// to `"v1"` so the frontend can clearly label this as an approximation, not a
/// persisted event log.
#[derive(Debug, Clone, Serialize)]
pub struct ActivityEnvelope {
    pub source: &'static str,
    pub version: &'static str,
    pub items: Vec<ActivityEntry>,
}

/// Obtain the injected [`OryClients`] from the Depot, cloning BEFORE any await.
fn ory_clients(depot: &mut Depot) -> Result<OryClients, AppError> {
    Ok(depot
        .obtain::<OryClients>()
        .map_err(|_| AppError::Internal("ory clients missing from depot".into()))?
        .clone())
}

/// `GET /api/activity` — derived recent-activity (v1).
///
/// Composes recent sessions + recent courier messages into one labeled feed. NO
/// new persistence. An upstream failure on either source maps to the shared
/// `AppError::Upstream` (502) — the same contract the sessions/courier wrappers
/// use.
#[handler]
pub async fn get_activity(depot: &mut Depot) -> Result<Json<ActivityEnvelope>, AppError> {
    let clients = ory_clients(depot)?;

    // Recent authentications: the most recent active sessions, identity expanded
    // (same typed call the Phase-10 list_sessions wrapper uses).
    let sessions = identity_api::list_sessions(
        &clients.kratos,
        Some(RECENT_PER_SOURCE),
        None,
        None,
        Some(vec!["identity".to_string()]),
    )
    .await
    .map_err(map_kratos_err)?;

    // Recent sends: the most recent courier messages (read-only delivery log).
    let messages = courier_api::list_courier_messages(
        &clients.kratos,
        Some(RECENT_PER_SOURCE),
        None,
        None,
        None,
    )
    .await
    .map_err(map_kratos_err)?;

    let mut items: Vec<ActivityEntry> = Vec::with_capacity(sessions.len() + messages.len());
    for s in sessions {
        let detail = serde_json::to_value(s)
            .map_err(|e| AppError::Internal(format!("serialize session: {e}")))?;
        items.push(ActivityEntry {
            kind: "authentication",
            detail,
        });
    }
    for m in messages {
        let detail = serde_json::to_value(m)
            .map_err(|e| AppError::Internal(format!("serialize courier message: {e}")))?;
        items.push(ActivityEntry {
            kind: "courier",
            detail,
        });
    }

    Ok(Json(ActivityEnvelope {
        source: "derived",
        version: "v1",
        items,
    }))
}
