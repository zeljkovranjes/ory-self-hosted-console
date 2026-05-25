//! Operator-facing config-edit API: `GET`/`PUT /api/config/<service>/<section>`
//! (BACK-04 / BACK-06). Mounted on the Phase-2 PROTECTED subtree so it inherits
//! `auth_guard` (401) and `csrf_guard` (403 on the state-changing PUT) — the PUT
//! is NOT exempted from CSRF.
//!
//! ## GET — present-allowlisted only, secret-free (T-04-15)
//!
//! `GET /api/config/<service>/<section>` returns ONLY the section's allowlisted
//! pointers that are PRESENT in the loaded doc, keyed by their JSON-Pointer. An
//! allowlisted pointer ABSENT in the doc (e.g. `/session/lifespan` on the live
//! Kratos doc that ships with no `session:` block) is OMITTED entirely — no
//! `null`, no key. Because the response is built solely from the per-section
//! allowlist (which never contains `dsn`/`secrets.*`/`serve.admin`), a secret or
//! denylisted value can never leak, even incidentally — we never serialise the
//! whole doc.
//!
//! ## PUT — the ordered 10-step transactional flow (RESEARCH diagram)
//!
//! 1. `locks::try_acquire(service)` — held -> 409 `config_busy`
//! 2. `allowlist::filter(patch)` — out-of-scope/sensitive -> 403 `forbidden_key`
//!    (BEFORE any disk/merge — allowlist is authoritative)
//! 3. `yaml::load` the live doc
//! 4. `yaml::apply_patch` the filtered pointers into the FULL doc (creates
//!    allowlist-bounded intermediate objects for an absent parent; NEVER adds an
//!    env-injected key like `dsn`)
//! 5. VALIDATE `schema::effective_for_validation(service, &merged)` — the merged
//!    doc UNION the env-injected required keys, so a committed doc that omits
//!    `dsn` does NOT 422. Failure -> 422 `validation_failed` + field errors;
//!    NO disk touched.
//! 6. `yaml::backup` the live file (last-known-good)
//! 7. `yaml::write_atomic` the MERGED doc (WITHOUT the env overlay — no `dsn`
//!    ever written) — status `applied`
//! 8. `restart::restart(service)` via broker — status `restarting`; broker
//!    failure -> 502
//! 9. `restart::wait_healthy(service)` — healthy -> status `healthy`, 200
//! 10. health timeout -> ROLLBACK: `yaml::restore` the `.bak`, restart, re-poll,
//!     report status `failed` (rolled back) -> 502 `health_failed`
//!
//! Every error body is a generic machine code; file paths, secrets, broker
//! bodies, raw YAML errors, and the dsn-overlay value are NEVER echoed. Each
//! status transition is `tracing`-logged WITHOUT any value (BACK-07 / T-04-15).

use std::path::PathBuf;
use std::time::Duration;

use salvo::prelude::*;
use serde_json::{Map, Value};

use crate::config::Config;
use crate::config_edit::{allowlist, locks, restart, schema, yaml};
use crate::error::AppError;
use crate::ory::fallback::fallback_client;

/// How long to wait for a restarted service to report healthy before rolling
/// back (RESEARCH Pitfall 6: services briefly 503; allow ample boot time).
const HEALTH_TIMEOUT: Duration = Duration::from_secs(60);

/// Map a [`restart::Service`] + service config dir to the YAML file path. Fixed
/// per the RESEARCH file table; the `<service>` came through `Service::parse`,
/// so the filename below is server-defined, never client input.
fn config_file_path(config_dir: &str, svc: restart::Service) -> PathBuf {
    let (dir, file) = match svc {
        restart::Service::Kratos => ("kratos", "kratos.yml"),
        restart::Service::Hydra => ("hydra", "hydra.yml"),
        restart::Service::Keto => ("keto", "keto.yml"),
        restart::Service::Oathkeeper => ("oathkeeper", "config.yaml"),
    };
    PathBuf::from(config_dir).join(dir).join(file)
}

/// Pull the `(service, section)` path params, mapping a missing/empty segment to
/// 404 (an unrecognised route shape must not fall through).
fn path_params(req: &Request) -> Result<(String, String), AppError> {
    let service = req.param::<String>("service").ok_or(AppError::NotFound)?;
    let section = req.param::<String>("section").ok_or(AppError::NotFound)?;
    if service.is_empty() || section.is_empty() {
        return Err(AppError::NotFound);
    }
    Ok((service, section))
}

/// Obtain the injected `Config` clone from the depot (RESEARCH Pattern 2).
fn config_from(depot: &Depot) -> Result<Config, AppError> {
    depot
        .obtain::<Config>()
        .cloned()
        .map_err(|_| AppError::Internal("config missing from depot".into()))
}

/// `GET /api/config/<service>/<section>` — current allowlisted values, absent
/// pointers omitted, never a secret/denylisted value (T-04-15).
#[handler]
pub async fn get_config(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<Value>, AppError> {
    let (service, section) = path_params(req)?;
    let cfg = config_from(depot)?;

    // Unknown (service, section) -> 404 (lookup is the ONLY allowlist source).
    let allow = allowlist::lookup(&service, &section)?;
    // Validate the service is a known config service (closed enum) before any
    // filesystem path is built — the filename is then server-defined.
    let svc = restart::Service::parse(&service)?;

    let doc = yaml::load(&config_file_path(&cfg.config_dir, svc))?;

    // Build the response from ONLY the section's allowlisted pointers that are
    // PRESENT in the doc. An absent pointer is OMITTED (no null, no key); the
    // response therefore never contains a denylisted/secret value, because the
    // allowlist never lists one and we never serialise the whole doc.
    let mut out = Map::new();
    for ptr in allow.allowed_paths {
        if let Some(value) = doc.pointer(ptr) {
            out.insert((*ptr).to_string(), value.clone());
        }
    }

    Ok(Json(Value::Object(out)))
}

/// Flatten an incoming PUT body into a `(json_pointer, value)` patch.
///
/// The body is a flat JSON object whose KEYS are RFC-6901 JSON-Pointers (the same
/// shape the allowlist + `apply_patch` consume), e.g.
/// `{ "/session/lifespan": "24h" }`. We deliberately accept ONLY this flat,
/// pointer-keyed shape so the allowlist's full-pointer match is exact — a nested
/// object body would require reconstructing pointers and risk the Pitfall-5
/// bypass. A non-object body is a 400.
fn body_to_patch(body: Value) -> Result<Vec<(String, Value)>, AppError> {
    match body {
        Value::Object(map) => Ok(map.into_iter().collect()),
        _ => Err(AppError::BadRequest(
            "config patch must be a flat JSON-Pointer object".into(),
        )),
    }
}

/// `PUT /api/config/<service>/<section>` — the ordered 10-step transactional
/// flow with status reporting and rollback-on-health-failure.
#[handler]
pub async fn put_config(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<Value>, AppError> {
    let (service, section) = path_params(req)?;
    let cfg = config_from(depot)?;

    // Resolve the closed allowlist + service BEFORE touching anything: an unknown
    // (service, section) is 404; an unknown service is 404 (no URL/path built).
    let allow = allowlist::lookup(&service, &section)?;
    let svc = restart::Service::parse(&service)?;

    // Parse the body up front (a malformed body is a 400 before we take the lock).
    let raw_body: Value = req
        .parse_json()
        .await
        .map_err(|_| AppError::BadRequest("invalid JSON body".into()))?;
    let patch = body_to_patch(raw_body)?;

    // --- Step 1: per-service write lock (busy -> 409 config_busy) ------------
    let _guard = locks::try_acquire(&service).await?;
    tracing::info!(service = svc.key(), "config put: lock acquired");

    // --- Step 2: ALLOWLIST-FILTER the patch (authoritative, pre-merge) -------
    // Out-of-scope/sensitive -> AppError::Forbidden -> 403 forbidden_key. The
    // rejected pointer's value is never echoed.
    let filtered = allowlist::filter(allow, &patch)?;

    // --- Step 3: LOAD the current live doc -----------------------------------
    let path = config_file_path(&cfg.config_dir, svc);
    let mut merged = yaml::load(&path)?;

    // --- Step 4: APPLY the filtered pointers into the FULL doc ---------------
    // Creates allowlist-bounded intermediate objects for an absent parent (e.g.
    // /session on a no-session Kratos doc); never adds an env-injected key.
    yaml::apply_patch(&mut merged, &filtered)?;

    // --- Step 5: VALIDATE the ENV-OVERLAID EFFECTIVE doc ---------------------
    // Validation runs on effective_for_validation (merged UNION env-injected
    // required keys) so a committed doc that omits dsn does NOT 422. The overlay
    // is a validation-only clone; the merged doc is what gets written.
    let validator = schema::validator_for(&service).map_err(|e| {
        tracing::error!(error = %e, service = svc.key(), "schema compile failed");
        AppError::Internal("config schema unavailable".into())
    })?;
    let effective = schema::effective_for_validation(&service, &merged);
    if let Err(fields) = schema::validate_full(validator, &effective) {
        // 422 with the field errors (path + value-free message). NO disk touched.
        tracing::debug!(service = svc.key(), count = fields.len(), "config put: validation failed");
        return Err(AppError::Validation(fields));
    }

    // --- Step 6: BACKUP the live file (last-known-good) ----------------------
    yaml::backup(&path)?;

    // --- Step 7: ATOMIC WRITE the MERGED doc (NO env overlay -> no dsn) -------
    let serialized = yaml::serialize(&merged)?;
    yaml::write_atomic(&path, &serialized)?;
    tracing::info!(service = svc.key(), status = "applied", "config put: written");

    // --- Step 8: RESTART only the affected container via the broker ----------
    let http = fallback_client()?;
    tracing::info!(service = svc.key(), status = "restarting", "config put: restarting");
    if let Err(e) = restart::restart(&http, &cfg.restart_broker_url, svc).await {
        // Broker failure: the write already applied but the restart did not fire.
        // Roll back to the last-known-good so the on-disk state matches the
        // running service, then surface the broker 502.
        tracing::warn!(service = svc.key(), "config put: broker restart failed; rolling back");
        rollback(&http, &path, &cfg, svc).await;
        return Err(e);
    }

    // --- Step 9: HEALTH-POLL until ready or timeout --------------------------
    if restart::wait_healthy(&http, svc, HEALTH_TIMEOUT, None).await {
        tracing::info!(service = svc.key(), status = "healthy", "config put: healthy");
        return Ok(Json(serde_json::json!({ "status": "healthy" })));
    }

    // --- Step 10: ROLLBACK on health failure ---------------------------------
    // Restore the .bak, restart, re-poll, report failed (rolled back). The detail
    // (which service, the values) is never placed in the body.
    tracing::warn!(service = svc.key(), "config put: health failed; rolling back");
    rollback(&http, &path, &cfg, svc).await;
    Err(AppError::HealthFailed)
}

/// Restore the last-known-good `.bak`, restart, and re-poll the service. Used by
/// both the broker-failure and health-timeout paths so the on-disk file always
/// returns to the state the running service can serve. A failure DURING rollback
/// is logged (server-side) but never changes the client-facing outcome — the
/// caller already returns the originating error. No value is logged.
async fn rollback(
    http: &reqwest::Client,
    path: &std::path::Path,
    cfg: &Config,
    svc: restart::Service,
) {
    if let Err(e) = yaml::restore(path) {
        tracing::error!(error = %e, service = svc.key(), "rollback: restore failed");
        return;
    }
    if let Err(e) = restart::restart(http, &cfg.restart_broker_url, svc).await {
        tracing::error!(error = %e, service = svc.key(), "rollback: restart failed");
        return;
    }
    let healthy = restart::wait_healthy(http, svc, HEALTH_TIMEOUT, None).await;
    tracing::warn!(
        service = svc.key(),
        status = "failed",
        recovered_healthy = healthy,
        "config put: rolled back to last-known-good"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A doc shaped like the live kratos.yml: NO `session:` block, secrets +
    /// serve present (so a GET must omit all three session pointers and never
    /// surface a secret/denylisted value).
    fn no_session_kratos() -> Value {
        json!({
            "serve": { "admin": { "base_url": "http://kratos:4434/" } },
            "dsn": "postgres://u:p@db/k",
            "identity": { "default_schema_id": "default" },
            "secrets": {
                "cookie": ["PLACEHOLDERcookieSECRET0123456789AB"],
                "cipher": ["PLACEHOLDERcipherSECRET0123456AB"]
            }
        })
    }

    /// Re-implement the GET response-building (the pure core of `get_config`)
    /// against an in-memory doc, so the omit-absent + secret-free behavior is
    /// unit-testable without a router/filesystem.
    fn build_get_response(allow: &allowlist::SectionAllowlist, doc: &Value) -> Value {
        let mut out = Map::new();
        for ptr in allow.allowed_paths {
            if let Some(value) = doc.pointer(ptr) {
                out.insert((*ptr).to_string(), value.clone());
            }
        }
        Value::Object(out)
    }

    #[test]
    fn get_omits_absent_allowlisted_pointers() {
        // The no-session doc has NONE of the three allowlisted session pointers ->
        // an EMPTY object (no null fields, no keys).
        let allow = allowlist::lookup("kratos", "session").expect("registered");
        let resp = build_get_response(allow, &no_session_kratos());
        let obj = resp.as_object().expect("object response");
        assert!(obj.is_empty(), "all absent pointers must be omitted: {obj:?}");
        // Explicitly: no null emitted for any allowlisted pointer.
        for ptr in allow.allowed_paths {
            assert!(!obj.contains_key(*ptr), "{ptr} must be omitted, not null");
        }

        // If ONLY /session/lifespan is present, ONLY that key appears.
        let mut doc = no_session_kratos();
        doc["session"] = json!({ "lifespan": "24h" });
        let resp = build_get_response(allow, &doc);
        let obj = resp.as_object().expect("object");
        assert_eq!(obj.len(), 1, "exactly the one present pointer");
        assert_eq!(obj.get("/session/lifespan"), Some(&json!("24h")));
        assert!(!obj.contains_key("/session/cookie/persistent"));
        assert!(!obj.contains_key("/session/cookie/same_site"));
    }

    #[test]
    fn get_never_returns_secret_or_denylisted() {
        // The response is built ONLY from the section allowlist, which lists no
        // secret/denylisted pointer — so dsn/secrets/serve.admin can never appear,
        // even though they are present in the doc.
        let allow = allowlist::lookup("kratos", "session").expect("registered");
        // Populate the session block fully so SOME keys are returned.
        let mut doc = no_session_kratos();
        doc["session"] = json!({
            "lifespan": "24h",
            "cookie": { "persistent": true, "same_site": "Lax" }
        });
        let resp = build_get_response(allow, &doc);
        let serialized = serde_json::to_string(&resp).unwrap();
        // Present allowlisted values appear...
        assert!(serialized.contains("/session/lifespan"));
        // ...but NO secret/denylisted value or key does.
        assert!(!serialized.contains("dsn"), "dsn must never appear: {serialized}");
        assert!(!serialized.contains("postgres://"), "dsn value must never appear");
        assert!(!serialized.contains("secrets"), "secrets must never appear");
        assert!(!serialized.contains("PLACEHOLDERcookie"), "secret value must never appear");
        assert!(!serialized.contains("base_url"), "serve.admin must never appear");
    }

    #[test]
    fn body_to_patch_requires_flat_object() {
        let patch = body_to_patch(json!({ "/session/lifespan": "24h" })).expect("object ok");
        assert_eq!(patch.len(), 1);
        assert_eq!(patch[0].0, "/session/lifespan");
        // A non-object body is a 400.
        assert!(matches!(
            body_to_patch(json!(["x"])),
            Err(AppError::BadRequest(_))
        ));
        assert!(matches!(
            body_to_patch(json!("x")),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn config_file_path_is_server_defined() {
        // The filename is fixed per closed Service — never client input.
        assert!(config_file_path("/etc/config", restart::Service::Kratos)
            .ends_with("kratos/kratos.yml"));
        assert!(config_file_path("/etc/config", restart::Service::Oathkeeper)
            .ends_with("oathkeeper/config.yaml"));
    }
}
