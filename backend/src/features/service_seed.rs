//! Env-driven boot reconcile of the service-domain feature flags (CLI-builder —
//! SVC-SELECT / CASCADE).
//!
//! The compose layer makes each Ory service independently
//! `in-stack | bring-your-own (byo) | off` by toggling its `svc-*` profile. The
//! backend learns the operator's selection from the `CONSOLE_SERVICE_*` env vars
//! and CASCADES a service's absence into its dependent console feature flag(s):
//! a service set `off` forces its dependent flag(s) OFF so the v1 Ory routes 404
//! server-side (the [`super::FeatureFlagHoop`] gate added on those subtrees) and
//! the nav items hide. A `byo` service keeps the feature ON (the backend admin
//! URL points at the external instance via the existing `*_ADMIN_URL` env
//! override — no code change needed). `in-stack` (the default) also keeps it ON.
//!
//! FAIL-CLOSED / one-directional: the reconcile ONLY ever forces a flag OFF
//! (T-CB-A02). It never silently turns a flag ON, so a tampered env can never
//! WIDEN console access — it can only narrow it. An `in-stack`/`byo`/unknown/
//! empty value leaves the flag UNTOUCHED, so an operator who later toggles a
//! feature ON via the management API is respected on the next boot.
//!
//! The OFF state is PERSISTED (via [`super::queries::set_enabled`]) as well as
//! written to the in-process cache, so a cascade-off survives a restart even
//! before the next reconcile runs.

use sqlx::PgPool;

use crate::error::AppError;

use super::FeatureFlags;

/// The five selectable Ory services and the `CONSOLE_SERVICE_*` env var + the
/// dependent feature flag key each one cascades into when set `off`.
///
///   kratos     -> identities    (Identities & Sessions, courier, auth config)
///   hydra      -> oauth2         (OAuth2 clients + inspector + config)
///   keto       -> permissions    (relationships, check/expand, permission model)
///   oathkeeper -> access_rules   (access-rules editor + read-only rules list)
///   polis      -> saml           (SAML sign-in / connections)
const SERVICE_FLAG_MAP: &[(&str, &str)] = &[
    ("CONSOLE_SERVICE_KRATOS", "identities"),
    ("CONSOLE_SERVICE_HYDRA", "oauth2"),
    ("CONSOLE_SERVICE_KETO", "permissions"),
    ("CONSOLE_SERVICE_OATHKEEPER", "access_rules"),
    ("CONSOLE_SERVICE_POLIS", "saml"),
];

/// A service's selected mode. Parsed permissively from a `CONSOLE_SERVICE_*`
/// value; an unknown/empty/unset value is treated as [`ServiceMode::InStack`]
/// (the all-on default) so a typo can never silently DISABLE a feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceMode {
    /// Run the container in this compose stack (default). Feature stays ON.
    InStack,
    /// Bring-your-own external instance. Feature stays ON; the backend admin URL
    /// points at the external instance via the existing `*_ADMIN_URL` override.
    Byo,
    /// The service is absent. Cascade-disable its dependent feature flag(s).
    Off,
}

impl ServiceMode {
    /// Parse a `CONSOLE_SERVICE_*` value permissively (case/whitespace tolerant).
    /// `off` -> [`ServiceMode::Off`]; `byo`/`bring-your-own` -> [`ServiceMode::Byo`];
    /// everything else (incl. `in-stack`, an unknown token, or an empty/absent
    /// value) -> [`ServiceMode::InStack`]. ONLY `off` ever forces a flag off.
    pub fn parse(value: Option<&str>) -> ServiceMode {
        match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
            Some("off") => ServiceMode::Off,
            Some("byo") | Some("bring-your-own") | Some("bring_your_own") => ServiceMode::Byo,
            // "in-stack", "", unknown, or None all default to in-stack (ON).
            _ => ServiceMode::InStack,
        }
    }

    /// Whether this mode cascade-disables the dependent feature flag.
    pub fn forces_flag_off(self) -> bool {
        matches!(self, ServiceMode::Off)
    }
}

/// PURE core of the reconcile (unit-testable without a DB): given a lookup of
/// `CONSOLE_SERVICE_*` values (an `env` resolver), return the list of feature
/// flag keys that must be forced OFF because their service is `off`. Order
/// follows [`SERVICE_FLAG_MAP`]. `in-stack`/`byo`/unknown services contribute
/// nothing (the flag is left untouched).
pub fn flags_to_force_off<F>(env: F) -> Vec<&'static str>
where
    F: Fn(&str) -> Option<String>,
{
    SERVICE_FLAG_MAP
        .iter()
        .filter(|(env_key, _)| ServiceMode::parse(env(env_key).as_deref()).forces_flag_off())
        .map(|(_, flag_key)| *flag_key)
        .collect()
}

/// Boot-time env-driven reconcile of the service-domain flags (called from
/// `main.rs` AFTER [`FeatureFlags::load`] and BEFORE serve). Reads the five
/// `CONSOLE_SERVICE_*` vars from the process environment; for each service set
/// `off`, forces its dependent flag OFF in BOTH the persisted `feature_flags`
/// table (so the state survives a restart) AND the in-process cache (so the
/// gate is closed from the first request). `in-stack`/`byo` leave the flag
/// as-is. Idempotent: running it twice with the same env yields the same state.
///
/// FAIL-CLOSED: this only ever forces a flag OFF — it never turns one ON
/// (T-CB-A02). A persisted-but-unknown flag key is a no-op on the DB side
/// (`set_enabled` UPDATEs by key and returns `None` for an absent row), but the
/// four service-domain keys are seeded by migration `0010`, so the UPDATE lands.
pub async fn reconcile_service_flags(
    pool: &PgPool,
    flags: &FeatureFlags,
) -> Result<(), AppError> {
    let force_off = flags_to_force_off(|key| std::env::var(key).ok());

    if force_off.is_empty() {
        return Ok(());
    }

    for key in &force_off {
        // Persist first so a crash mid-loop still leaves the DB fail-closed; then
        // refresh the in-process cache so the gate is shut for the next request.
        super::queries::set_enabled(pool, key, false).await?;
        flags.set(key, false);
    }

    tracing::info!(
        forced_off = ?force_off,
        "service-domain feature flags cascade-disabled from CONSOLE_SERVICE_* (services set off)"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// `ServiceMode::parse` is permissive and ONLY `off` forces a flag off.
    #[test]
    fn parse_mode_is_permissive_and_off_only() {
        assert_eq!(ServiceMode::parse(Some("off")), ServiceMode::Off);
        assert_eq!(ServiceMode::parse(Some("  OFF  ")), ServiceMode::Off);
        assert_eq!(ServiceMode::parse(Some("byo")), ServiceMode::Byo);
        assert_eq!(ServiceMode::parse(Some("bring-your-own")), ServiceMode::Byo);
        assert_eq!(ServiceMode::parse(Some("in-stack")), ServiceMode::InStack);
        // Unknown / empty / absent all default to in-stack (never off).
        assert_eq!(ServiceMode::parse(Some("garbage")), ServiceMode::InStack);
        assert_eq!(ServiceMode::parse(Some("")), ServiceMode::InStack);
        assert_eq!(ServiceMode::parse(None), ServiceMode::InStack);

        assert!(ServiceMode::Off.forces_flag_off());
        assert!(!ServiceMode::Byo.forces_flag_off());
        assert!(!ServiceMode::InStack.forces_flag_off());
    }

    /// The all-default env (everything in-stack / unset) forces NOTHING off —
    /// the cascade is inert when no service is off (the all-on default posture).
    #[test]
    fn no_service_off_forces_nothing() {
        let empty: HashMap<&str, String> = HashMap::new();
        let force_off = flags_to_force_off(|k| empty.get(k).cloned());
        assert!(force_off.is_empty(), "no off service => nothing forced off");

        let mut all_in_stack: HashMap<&str, String> = HashMap::new();
        for (env_key, _) in SERVICE_FLAG_MAP {
            all_in_stack.insert(env_key, "in-stack".to_string());
        }
        let force_off = flags_to_force_off(|k| all_in_stack.get(k).cloned());
        assert!(force_off.is_empty(), "all in-stack => nothing forced off");
    }

    /// A `byo` service keeps its feature ON (BYO points the admin URL at the
    /// external instance — it never cascades the flag off).
    #[test]
    fn byo_keeps_flag_on() {
        let mut env: HashMap<&str, String> = HashMap::new();
        env.insert("CONSOLE_SERVICE_KETO", "byo".to_string());
        let force_off = flags_to_force_off(|k| env.get(k).cloned());
        assert!(
            !force_off.contains(&"permissions"),
            "a byo Keto must NOT force `permissions` off"
        );
        assert!(force_off.is_empty(), "byo forces nothing off");
    }

    /// Each service set `off` cascades to EXACTLY its dependent flag key.
    #[test]
    fn off_service_maps_to_its_flag() {
        let cases = [
            ("CONSOLE_SERVICE_KRATOS", "identities"),
            ("CONSOLE_SERVICE_HYDRA", "oauth2"),
            ("CONSOLE_SERVICE_KETO", "permissions"),
            ("CONSOLE_SERVICE_OATHKEEPER", "access_rules"),
            ("CONSOLE_SERVICE_POLIS", "saml"),
        ];
        for (env_key, flag_key) in cases {
            let mut env: HashMap<&str, String> = HashMap::new();
            env.insert(env_key, "off".to_string());
            let force_off = flags_to_force_off(|k| env.get(k).cloned());
            assert_eq!(
                force_off,
                vec![flag_key],
                "{env_key}=off must force exactly [{flag_key}] off"
            );
        }
    }

    /// Multiple services off accumulate; idempotent (same env => same result).
    #[test]
    fn multiple_off_accumulate_and_idempotent() {
        let mut env: HashMap<&str, String> = HashMap::new();
        env.insert("CONSOLE_SERVICE_KETO", "off".to_string());
        env.insert("CONSOLE_SERVICE_POLIS", "off".to_string());
        env.insert("CONSOLE_SERVICE_HYDRA", "in-stack".to_string());

        let first = flags_to_force_off(|k| env.get(k).cloned());
        let second = flags_to_force_off(|k| env.get(k).cloned());
        assert_eq!(first, second, "idempotent: same env => same force-off set");
        assert!(first.contains(&"permissions"));
        assert!(first.contains(&"saml"));
        assert!(!first.contains(&"oauth2"), "in-stack Hydra stays on");
        assert_eq!(first.len(), 2);
    }

    /// Cache-application semantics: applying the force-off set to a FeatureFlags
    /// cache flips exactly the off services' flags to false and leaves the rest
    /// (mirrors what `reconcile_service_flags` does to the cache half, without a
    /// DB). Proves the cascade closes the gate (is_enabled => false).
    #[test]
    fn applying_force_off_closes_the_gate_in_cache() {
        let mut seed = HashMap::new();
        for key in ["identities", "oauth2", "permissions", "access_rules", "saml"] {
            seed.insert(key.to_string(), true); // all seeded ON
        }
        let flags = FeatureFlags::from_map(seed);

        let mut env: HashMap<&str, String> = HashMap::new();
        env.insert("CONSOLE_SERVICE_KETO", "off".to_string());
        let force_off = flags_to_force_off(|k| env.get(k).cloned());
        for key in &force_off {
            flags.set(key, false);
        }

        assert!(!flags.is_enabled("permissions"), "Keto off => permissions gate closed");
        // Untouched flags stay ON (the cascade is surgical, off-only).
        assert!(flags.is_enabled("identities"));
        assert!(flags.is_enabled("oauth2"));
        assert!(flags.is_enabled("access_rules"));
        assert!(flags.is_enabled("saml"));
    }
}
