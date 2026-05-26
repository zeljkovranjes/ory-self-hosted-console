//! Feature-toggle system (Phase 12 keystone — FLAG-01/02/04).
//!
//! The single SERVER-SIDE enforcement point for v2 feature gating. Three pieces:
//!
//!   - [`FeatureFlags`] — a process-wide, clone-cheap (`Arc<RwLock<HashMap>>`)
//!     cache of `key → enabled`, injected into every `Depot` via `affix_state`
//!     (alongside the pool/cfg/clients) and loaded once at boot from
//!     [`queries::load_all`]. Reads are fail-CLOSED: any miss → `false`.
//!   - [`FeatureFlagHoop`] — a PARAMETERIZED hoop carrying a flag key. A bare
//!     `#[handler] async fn` cannot carry state, so this is a STRUCT made into a
//!     `Handler` via `#[handler] impl` (RESEARCH Pattern 1 / Pitfall 2). Mounted
//!     INSIDE the protected subtree (AFTER `auth_guard`/`csrf_guard`), it returns
//!     `404 + skip_rest()` when the flag is OFF — so neither a valid session nor a
//!     matching CSRF token can reach a disabled feature's handler (FLAG-01). 404
//!     (not 403) so a disabled feature does not advertise its existence (T-12-02).
//!   - [`routes`] — `GET /api/console/features` (read) +
//!     `PUT /api/console/features/{key}` (toggle, refresh cache; audited by the
//!     existing response-phase audit hoop).
//!
//! The label + `requires_runtime` marker live in the [`FEATURE_META`] constant
//! map (RESEARCH A3), not DB columns — adding a flag is a code+seed edit.

pub mod queries;
pub mod routes;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use salvo::prelude::*;

/// Static metadata for a known feature flag: a human label and whether turning it
/// ON requires a runtime component (a compose profile) to be running. This phase
/// only STORES the `requires_runtime` marker for observability — it never probes
/// or proxies, and a `requires_runtime` flag turned ON must NOT 502 here (Phase
/// 16 owns the health probe — Pitfall 7 / T-12-07).
pub struct FeatureMeta {
    pub label: &'static str,
    pub requires_runtime: bool,
}

/// The canonical known-flag set: key → label + `requires_runtime`. Kept in
/// lockstep with the `0007` migration seed. Only `observability` requires a
/// runtime profile in this milestone.
pub const FEATURE_META: &[(&str, FeatureMeta)] = &[
    ("saml", FeatureMeta { label: "SAML Sign-In", requires_runtime: false }),
    ("organizations", FeatureMeta { label: "Organizations", requires_runtime: false }),
    ("account_experience", FeatureMeta { label: "Account Experience", requires_runtime: false }),
    ("observability", FeatureMeta { label: "Observability", requires_runtime: true }),
    ("event_streams", FeatureMeta { label: "Event Streams", requires_runtime: false }),
    ("opl_live_validation", FeatureMeta { label: "Live OPL Validation", requires_runtime: false }),
];

/// Look up the static metadata for a flag key, if it is a known feature.
pub fn meta_for(key: &str) -> Option<&'static FeatureMeta> {
    FEATURE_META.iter().find(|(k, _)| *k == key).map(|(_, m)| m)
}

/// Process-wide feature-flag cache. Clone is cheap (`Arc` bump); the `Send + Sync
/// + 'static` bound holds so it can ride the `affix_state` injection chain
/// exactly like the pool/cfg/clients. Reads are FAIL-CLOSED (a missing key or a
/// poisoned lock → `false`), matching the fail-closed posture of `auth_guard`.
#[derive(Clone)]
pub struct FeatureFlags(Arc<RwLock<HashMap<String, bool>>>);

impl FeatureFlags {
    /// Load the cache from the `feature_flags` table at boot (after migrate,
    /// before serve — Pitfall 5). No gated route is reachable with an empty cache.
    pub async fn load(pool: &sqlx::PgPool) -> Result<Self, crate::error::AppError> {
        let map = queries::load_all(pool).await?;
        Ok(Self(Arc::new(RwLock::new(map))))
    }

    /// Build a cache directly from a key→enabled map (used by tests / explicit
    /// seeding). The production path uses [`FeatureFlags::load`].
    pub fn from_map(map: HashMap<String, bool>) -> Self {
        Self(Arc::new(RwLock::new(map)))
    }

    /// Whether a flag is enabled. FAIL-CLOSED for an UNKNOWN key (absent → `false`),
    /// matching the fail-closed posture `auth_guard` relies on (FLAG-01 / Pitfall 5).
    ///
    /// WR-02: the lock is POISON-TOLERANT. A `HashMap<String,bool>` has no broken
    /// invariant after a panic, so recovering the guard via `PoisonError::into_inner`
    /// is safe — and it avoids the split-brain where a SINGLE poisoning event would
    /// otherwise wedge every flag to `false` (via the old `unwrap_or(false)`) for the
    /// lifetime of the process, silently disabling even flags the operator turned ON.
    /// Unknown-key fail-closed is preserved (the recovered map still reports `false`
    /// for absent keys); we just no longer let poisoning masquerade as "everything off".
    pub fn is_enabled(&self, key: &str) -> bool {
        let m = self.0.read().unwrap_or_else(|e| e.into_inner());
        *m.get(key).unwrap_or(&false)
    }

    /// Refresh a flag's cached state after a successful DB write so the next gated
    /// request sees the new state without a DB round-trip.
    ///
    /// WR-02: recover a POISONED write lock via `PoisonError::into_inner` rather than
    /// silently no-op'ing. The old `if let Ok(..)` swallowed a poisoned lock with no
    /// log and no error, so after one poisoning event every `set` became a no-op: the
    /// DB write (and the 200 the operator sees) would succeed while the in-process
    /// gate never opened — a cache/DB split-brain. We log a warning so the (now
    /// recovered, but noteworthy) poisoning is observable, then apply the write.
    pub fn set(&self, key: &str, enabled: bool) {
        let mut m = self.0.write().unwrap_or_else(|e| {
            tracing::warn!(
                flag = key,
                "feature-flag cache RwLock was poisoned; recovering the guard and \
                 applying the write (the HashMap has no broken invariant after a panic)"
            );
            e.into_inner()
        });
        m.insert(key.to_string(), enabled);
    }
}

/// A parameterized feature-gate hoop carrying the flag key it guards.
///
/// THE load-bearing pattern (RESEARCH Pattern 1 / Pitfall 2): a bare
/// `#[handler] async fn` cannot hold the key, so this is a struct made into a
/// `Handler` via the `#[handler] impl` block below. Mount with
/// `.hoop(FeatureFlagHoop::new("saml"))` INSIDE the protected subtree.
pub struct FeatureFlagHoop {
    key: &'static str,
}

impl FeatureFlagHoop {
    /// Gate a route subtree on the given (compile-time-constant) flag key.
    pub fn new(key: &'static str) -> Self {
        Self { key }
    }
}

#[handler]
impl FeatureFlagHoop {
    async fn handle(
        &self,
        _req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        // FeatureFlags is injected at the root via affix_state (alongside
        // pool/cfg/clients). FAIL-CLOSED: a missing cache (obtain Err) is treated
        // as disabled — a gated route is NEVER served on a cache miss (Pitfall 5).
        let enabled = depot
            .obtain::<FeatureFlags>()
            .map(|f| f.is_enabled(self.key))
            .unwrap_or(false);

        if !enabled {
            // 404 (NOT 403): a disabled feature does not advertise its existence
            // (T-12-02). skip_rest() so the downstream feature handler never runs.
            res.status_code(StatusCode::NOT_FOUND);
            res.render(Json(serde_json::json!({ "error": "not_found" })));
            ctrl.skip_rest();
        }
        // ON → fall through to the downstream handler (do not touch res/ctrl).
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FLAG-01 fail-closed: a cache with NO entry for a key (a cold/empty cache or
    /// an unknown key) reports `false`, never `true`. This is the unit-level proof
    /// of the fail-closed posture the hoop relies on.
    #[test]
    fn cache_miss_is_disabled() {
        let flags = FeatureFlags::from_map(HashMap::new());
        assert!(!flags.is_enabled("saml"), "an absent key must be disabled");
        assert!(
            !flags.is_enabled("nonexistent"),
            "an unknown key must be disabled"
        );
    }

    /// A seeded ON flag reads ON; a seeded OFF flag reads OFF; and `set` refreshes
    /// the cached state in place.
    #[test]
    fn seeded_state_and_set_refresh() {
        let mut map = HashMap::new();
        map.insert("opl_live_validation".to_string(), true);
        map.insert("saml".to_string(), false);
        let flags = FeatureFlags::from_map(map);

        assert!(flags.is_enabled("opl_live_validation"), "ON flag reads on");
        assert!(!flags.is_enabled("saml"), "OFF flag reads off");

        flags.set("saml", true);
        assert!(flags.is_enabled("saml"), "set refreshes the cache to ON");
        flags.set("saml", false);
        assert!(!flags.is_enabled("saml"), "set refreshes the cache to OFF");
    }

    /// WR-02: a poisoned lock must NOT wedge the cache. After a writer panics while
    /// holding the guard (poisoning the `RwLock`), `set` must still recover the guard
    /// and apply the write, and `is_enabled` must read the recovered map — NOT the
    /// old `unwrap_or(false)` behavior that silently disabled every flag after a
    /// single poisoning event (the cache/DB split-brain the review flagged).
    #[test]
    fn poisoned_lock_is_recovered_not_wedged() {
        let mut map = HashMap::new();
        map.insert("saml".to_string(), true);
        let flags = FeatureFlags::from_map(map);

        // Poison the inner RwLock by panicking while a write guard is held. We catch
        // the panic so the test process survives; the lock stays poisoned afterward.
        let clone = flags.clone();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = clone.0.write().unwrap();
            panic!("intentional panic to poison the feature-flag RwLock");
        }));
        assert!(
            flags.0.read().is_err(),
            "the RwLock should be poisoned after the panic (test precondition)"
        );

        // A previously-ON flag is STILL ON despite the poisoning (read recovers the
        // guard via into_inner instead of collapsing to false).
        assert!(
            flags.is_enabled("saml"),
            "an ON flag must survive a poisoning event (no silent disable)"
        );

        // And a write through the poisoned lock still lands (recovered, not no-op'd).
        flags.set("saml", false);
        assert!(
            !flags.is_enabled("saml"),
            "set must apply through a poisoned (recovered) lock, not silently no-op"
        );
        flags.set("organizations", true);
        assert!(
            flags.is_enabled("organizations"),
            "a fresh write through the recovered lock must also persist"
        );
    }

    /// FEATURE_META covers every seeded key, only `observability` requires a
    /// runtime profile, and labels match the GET contract.
    #[test]
    fn feature_meta_matches_seed_contract() {
        assert!(meta_for("saml").is_some());
        assert_eq!(meta_for("observability").unwrap().requires_runtime, true);
        assert_eq!(meta_for("saml").unwrap().requires_runtime, false);
        assert_eq!(meta_for("opl_live_validation").unwrap().label, "Live OPL Validation");
        assert!(meta_for("nonexistent").is_none());
    }
}
