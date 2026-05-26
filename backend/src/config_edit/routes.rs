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
use crate::config_edit::secret_merge::{get_dot, set_dot};
use crate::config_edit::{allowlist, locks, restart, schema, secret_merge, yaml};
use crate::error::AppError;

/// The single fixed JSON-Pointer the dedicated SMTP write-only handler may touch.
/// It is on the hard `SENSITIVE_PREFIXES` denylist (carries the SMTP password), so
/// it is NEVER routed through the generic `{service}/{section}` allowlist — this
/// dedicated handler is the ONLY writer, exactly as IDENT-03 is the only writer of
/// the schema file (Pitfall 2 / threat T-07-07).
const SMTP_CONNECTION_URI_POINTER: &str = "/courier/smtp/connection_uri";

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

/// The server-defined path of the ACTIVE Kratos identity schema FILE
/// (`{config_dir}/kratos/identity.schema.json`).
///
/// IDENT-03: the schema editor targets THIS file only — it is NOT routed through
/// the `{service}/{section}` allowlist, so it can never write an arbitrary
/// `kratos.yml` key (config-injection guard, threat T-06-10). The path is built
/// purely from `Config::config_dir` + fixed segments; no part is client input.
pub fn identity_schema_path(config_dir: &str) -> PathBuf {
    PathBuf::from(config_dir)
        .join("kratos")
        .join("identity.schema.json")
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

/// Per-array-section descriptor: the secret-merge/mask spec + the Jsonnet source
/// field dot-paths within an item. The array-ROOT pointers themselves come from
/// the section allowlist (`KRATOS_OIDC`/`KRATOS_SMS`/`KRATOS_WEBHOOKS`) — every
/// allowlisted pointer in those three sections that holds an ARRAY of objects gets
/// the mask/merge + base64 treatment; non-array allowlisted pointers in the same
/// section (e.g. `oidc.enabled`) flow through unchanged.
struct ArraySectionDescriptor {
    spec: secret_merge::ArraySecretSpec,
    /// Dot-notation paths to the per-item Jsonnet SOURCE fields (stored as
    /// `base64://…`, decoded to source on GET / re-encoded on PUT).
    jsonnet_fields: &'static [&'static str],
}

/// Resolve the array-section descriptor for a section name, or `None` for a
/// non-array (scalar) section. Selection is by SECTION NAME (`oidc`/`sms`/
/// `webhooks`) — never guessed from the pointer.
fn array_section_descriptor(section: &str) -> Option<ArraySectionDescriptor> {
    match section {
        "oidc" => Some(ArraySectionDescriptor {
            spec: secret_merge::OIDC_SPEC,
            jsonnet_fields: &["mapper_url"],
        }),
        "sms" => Some(ArraySectionDescriptor {
            spec: secret_merge::SMS_SPEC,
            jsonnet_fields: &["request_config.body"],
        }),
        "webhooks" => Some(ArraySectionDescriptor {
            spec: secret_merge::WEBHOOK_SPEC,
            jsonnet_fields: &["config.body"],
        }),
        _ => None,
    }
}

// WR-04: the dot-path getter/setter live in `secret_merge` (the single canonical
// definition) and are imported above — NOT re-declared here. Keeping one copy
// guarantees the mask/merge/encode pipeline shares identical non-object/graceful
// semantics; a divergent second copy was the subtle secret-handling drift risk.

/// GET transform for an array value: mask per-item secrets, then DECODE each item's
/// Jsonnet `base64://` field back to source for the editor. A non-array value is
/// returned unchanged (defensive). Never returns a real secret; never fetches a
/// non-base64 URI (it passes through).
fn array_get_transform(value: &Value, desc: &ArraySectionDescriptor) -> Result<Value, AppError> {
    let Some(items) = value.as_array() else {
        return Ok(value.clone());
    };
    // 1) mask per-item secrets (never emit a real secret on GET).
    let mut masked = secret_merge::mask_array_secrets(items, &desc.spec);
    // 2) decode each item's Jsonnet source field for the editor.
    for item in &mut masked {
        for field in desc.jsonnet_fields {
            if let Some(Value::String(uri)) = get_dot(item, field) {
                let decoded = crate::config_edit::jsonnet::decode_base64_uri(uri)?;
                set_dot(item, field, Value::String(decoded));
            }
        }
    }
    Ok(Value::Array(masked))
}

/// PUT transform for an incoming array value: merge-by-id against the stored array
/// (preserving masked secrets, Pitfall 3), then ENCODE each item's edited Jsonnet
/// source field to `base64://` before it lands in the doc. A non-array incoming
/// value is returned unchanged (defensive — the schema validate will reject it).
///
/// CR-01: merge-by-id can FAIL CLOSED — if an incoming item carries the masked
/// sentinel for a secret but no stored value can be inherited (renamed id/url, or
/// an auth-kind switch left the stored item without that field), this returns a
/// 422 `AppError::Validation` telling the operator to re-enter the secret for the
/// named item, rather than writing the literal sentinel as a real credential.
fn array_put_transform(
    stored: &Value,
    incoming: &Value,
    desc: &ArraySectionDescriptor,
) -> Result<Value, AppError> {
    let Some(incoming_items) = incoming.as_array() else {
        return Ok(incoming.clone());
    };
    let empty: Vec<Value> = Vec::new();
    let stored_items = stored.as_array().unwrap_or(&empty);
    // 1) merge-by-id: a masked/absent incoming secret inherits the stored value.
    //    A masked secret with NO stored value to inherit fails closed (CR-01).
    let mut merged = secret_merge::merge_array_by_id(stored_items, incoming_items, &desc.spec)
        .map_err(|e| {
            // Value-free 422: name the item (operator-supplied id, never the secret)
            // and instruct the operator to re-enter the secret. The sentinel literal
            // is never logged or echoed.
            let which = e
                .item_id
                .as_deref()
                .map(|id| format!("'{id}'"))
                .unwrap_or_else(|| "the edited item".to_string());
            tracing::debug!("array put: masked secret with no stored value to inherit (fail-closed)");
            AppError::Validation(vec![schema::FieldError {
                path: String::new(),
                message: format!(
                    "re-enter the secret for {which} (its identifier changed, so the stored secret cannot be preserved)"
                ),
            }])
        })?;
    // 2) re-encode each edited Jsonnet source field to base64://. The editor sent
    //    PLAINTEXT source (the GET decoded it); store it back as base64://. If the
    //    field already carries a base64:// URI (untouched), re-encoding the decoded
    //    form is idempotent — but the editor always round-trips source, so we encode
    //    the string we received as source.
    for item in &mut merged {
        for field in desc.jsonnet_fields {
            if let Some(Value::String(src)) = get_dot(item, field) {
                let encoded = crate::config_edit::jsonnet::encode_base64_uri(src);
                set_dot(item, field, Value::String(encoded));
            }
        }
    }
    Ok(Value::Array(merged))
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
    //
    // WR-01: additionally run the SAME sensitive denylist the PUT path uses, on
    // the read path. Today the proof allowlist lists no sensitive pointer, but a
    // future mistake (adding a sensitive pointer to a section allowlist) must NOT
    // leak that secret via GET while PUT would still refuse it — the denylist's
    // authority holds on read too.
    // Array sections (oidc/sms/webhooks) get per-item secret MASKING + Jsonnet
    // base64:// DECODE applied to each present array-root value; scalar sections
    // pass through unchanged. Selection is by SECTION NAME, not pointer-guessing.
    let array_desc = array_section_descriptor(&section);

    let mut out = Map::new();
    for ptr in allow.allowed_paths {
        if allowlist::is_sensitive(ptr) {
            // Never surface a denylisted/secret value, even if it was mistakenly
            // allowlisted. (is_sensitive expects the canonical pointer form; the
            // const allowed_paths are authored canonical.)
            continue;
        }
        if let Some(value) = doc.pointer(ptr) {
            let emitted = match &array_desc {
                // An array-root pointer in an array section: mask secrets + decode
                // Jsonnet. A non-array allowlisted value (e.g. oidc.enabled) is
                // returned unchanged by array_get_transform's defensive guard.
                Some(desc) => array_get_transform(value, desc)?,
                None => value.clone(),
            };
            out.insert((*ptr).to_string(), emitted);
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

    // --- Step 3b: ARRAY-SECTION merge-by-id + base64 Jsonnet (pre-apply) ------
    // For oidc/sms/webhooks, each whole-array PUT is (a) merged-by-id against the
    // STORED array so a masked/untouched per-item secret is PRESERVED (never
    // clobbered, Pitfall 3), and (b) each edited Jsonnet source field re-encoded to
    // base64:// before it lands in the doc. The transformed array stays a single
    // allowlisted ROOT-pointer value (Pattern 1), so it already passed `filter`.
    // Scalar sections skip this entirely and flow through unchanged.
    let filtered = if let Some(desc) = array_section_descriptor(&section) {
        filtered
            .into_iter()
            .map(|(ptr, incoming)| {
                // The stored value at this exact root pointer (absent -> empty).
                let stored = merged.pointer(&ptr).cloned().unwrap_or(Value::Null);
                // CR-01: a masked secret with no stored value to inherit fails
                // closed here (422) BEFORE any disk touch — the sentinel literal
                // never reaches `apply_patch`/`write_atomic`.
                let transformed = array_put_transform(&stored, &incoming, &desc)?;
                Ok::<_, AppError>((ptr, transformed))
            })
            .collect::<Result<Vec<_>, _>>()?
    } else {
        filtered
    };

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

    // WR-02: never commit a write we cannot reverse. Assert the backup actually
    // landed BEFORE the atomic write, so the rollback paths below always have a
    // last-known-good to restore. A missing backup here is a hard internal fault
    // (the write has NOT happened yet, so the live file is still good).
    if !yaml::backup_exists(&path) {
        tracing::error!(service = svc.key(), "config put: backup missing after backup(); refusing reversible write");
        return Err(AppError::Internal("config backup missing".into()));
    }

    // --- Step 7: ATOMIC WRITE the MERGED doc (NO env overlay -> no dsn) -------
    let serialized = yaml::serialize(&merged)?;
    yaml::write_atomic(&path, &serialized)?;
    tracing::info!(service = svc.key(), status = "applied", "config put: written");

    // --- Step 8: RESTART only the affected container via the broker ----------
    // WR-04/WR-05: a dedicated redirect-disabled, short-timeout client for the
    // broker POST + health poll (NOT the 10s-timeout, redirect-following Ory
    // fallback client). A 3xx must never be followed or read as healthy.
    let http = restart::restart_client()?;
    tracing::info!(service = svc.key(), status = "restarting", "config put: restarting");
    if let Err(e) = restart::restart(&http, &cfg.restart_broker_url, svc).await {
        // WR-03 — BROKER-FAILURE path: the service NEVER restarted, so it is
        // still running its OLD (last-known-good) in-memory config. We only need
        // to restore the `.bak` so DISK matches the running service; issuing a
        // second restart through the just-failed broker would only fail again.
        tracing::warn!(service = svc.key(), "config put: broker restart failed; restoring disk (no re-restart)");
        restore_only(&path, svc);
        return Err(e);
    }

    // --- Step 9: HEALTH-POLL until ready or timeout --------------------------
    if restart::wait_healthy(&http, svc, HEALTH_TIMEOUT, None).await {
        tracing::info!(service = svc.key(), status = "healthy", "config put: healthy");
        return Ok(Json(serde_json::json!({ "status": "healthy" })));
    }

    // --- Step 10: ROLLBACK on health failure ---------------------------------
    // WR-03 — HEALTH-FAILURE path: the service DID restart into the bad config,
    // so we must restore the `.bak`, restart AGAIN, and re-poll to bring it back
    // onto the last-known-good. The detail (service, values) is never in the body.
    tracing::warn!(service = svc.key(), "config put: health failed; rolling back");
    rollback_and_restart(&http, &path, &cfg, svc).await;
    Err(AppError::HealthFailed)
}

/// `PUT /api/kratos/identity-schema` — validate-as-draft-07 + atomic-write the
/// identity schema FILE + restart Kratos + rollback on failure (IDENT-03).
///
/// This REUSES the Phase-4 engine's transactional machinery (lock -> validate ->
/// backup -> atomic-write -> restart -> health-poll -> rollback) but differs from
/// [`put_config`] in four ways:
///   1. the target is the FIXED schema file (`identity_schema_path`), NOT a
///      `{service}/{section}` allowlist lookup — the editor can only write the
///      schema file, never an arbitrary `kratos.yml` key (T-06-10);
///   2. the body is the FULL schema JSON object (not a flat pointer patch);
///   3. validation is [`schema::validate_identity_schema`] (draft-07 metaschema +
///      `properties.traits`-object), NOT a service-config schema check — a
///      malformed schema crashing Kratos is the primary risk (Pitfall 5);
///   4. the file is `.json`, so it is serialised with
///      [`serde_json::to_string_pretty`], NOT `yaml::serialize` (RESEARCH
///      anti-pattern: never YAML-serialise the schema file).
///
/// On the protected subtree: `auth_guard` (401 unauth) + `csrf_guard` (403 without
/// `X-CSRF-Token`, since this is state-changing — T-06-14).
#[handler]
pub async fn put_identity_schema(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<Value>, AppError> {
    let cfg = config_from(depot)?;
    let svc = restart::Service::Kratos;

    // Parse the body as the FULL candidate schema (a malformed body -> 400 before
    // the lock). The candidate is the operator's proposed identity schema.
    let candidate: Value = req
        .parse_json()
        .await
        .map_err(|_| AppError::BadRequest("invalid JSON body".into()))?;

    // --- Step 1: kratos write lock (busy -> 409 config_busy) -----------------
    // Shares the per-service lock with put_config so a schema edit and a config
    // edit for kratos can never interleave.
    let _guard = locks::try_acquire("kratos").await?;
    tracing::info!(service = svc.key(), "identity-schema put: lock acquired");

    // --- Step 2: VALIDATE the candidate AS a draft-07 JSON Schema ------------
    // Pitfall 5 / A3: reject a non-schema OR a schema lacking properties.traits
    // BEFORE any disk touch (422, no write). The engine rollback is the backstop,
    // not the primary guard.
    if let Err(fields) = schema::validate_identity_schema(&candidate) {
        tracing::debug!(
            service = svc.key(),
            count = fields.len(),
            "identity-schema put: validation failed"
        );
        return Err(AppError::Validation(fields));
    }

    // --- Step 3: BACKUP the live schema file (last-known-good) ---------------
    let path = identity_schema_path(&cfg.config_dir);
    yaml::backup(&path)?;

    // WR-02: never commit a write we cannot reverse. Assert the backup landed
    // BEFORE the atomic write so every rollback path has a last-known-good.
    if !yaml::backup_exists(&path) {
        tracing::error!(
            service = svc.key(),
            "identity-schema put: backup missing after backup(); refusing reversible write"
        );
        return Err(AppError::Internal("identity schema backup missing".into()));
    }

    // --- Step 4: ATOMIC WRITE the schema as pretty JSON (NOT YAML) -----------
    // The file is `.json`, consumed by Kratos as a JSON Schema — serialise with
    // serde_json, not serde_yaml_ng (RESEARCH anti-pattern). The atomic write
    // (temp+fsync+rename) is the reused engine primitive (T-06-15).
    let serialized = serde_json::to_string_pretty(&candidate)
        .map_err(|e| AppError::Internal(format!("serialize identity schema: {e}")))?;
    yaml::write_atomic(&path, &serialized)?;
    tracing::info!(service = svc.key(), status = "applied", "identity-schema put: written");

    // --- Step 5: RESTART kratos via the scoped broker ------------------------
    // WR-04/WR-05: dedicated redirect-disabled, short-timeout client.
    let http = restart::restart_client()?;
    tracing::info!(service = svc.key(), status = "restarting", "identity-schema put: restarting");
    if let Err(e) = restart::restart(&http, &cfg.restart_broker_url, svc).await {
        // BROKER-FAILURE: the service never restarted, so it still runs its old
        // (good) schema; restore disk only so disk matches the running service.
        tracing::warn!(
            service = svc.key(),
            "identity-schema put: broker restart failed; restoring disk (no re-restart)"
        );
        restore_only(&path, svc);
        return Err(e);
    }

    // --- Step 6: HEALTH-POLL until ready or timeout --------------------------
    if restart::wait_healthy(&http, svc, HEALTH_TIMEOUT, None).await {
        tracing::info!(service = svc.key(), status = "healthy", "identity-schema put: healthy");
        return Ok(Json(serde_json::json!({ "status": "healthy" })));
    }

    // --- Step 7: ROLLBACK on health failure ----------------------------------
    // HEALTH-FAILURE: kratos restarted into a schema it cannot load (Pitfall 5).
    // Restore the .bak, restart again, re-poll to bring it back onto the
    // last-known-good schema. The detail is never in the body.
    tracing::warn!(service = svc.key(), "identity-schema put: health failed; rolling back");
    rollback_and_restart(&http, &path, &cfg, svc).await;
    Err(AppError::HealthFailed)
}

/// `GET /api/kratos/smtp-connection` — report ONLY whether an SMTP connection_uri
/// is currently set, MASKED. The URI value (which carries the SMTP password) is
/// NEVER serialised, never logged, never echoed — not even a substring (T-07-05).
///
/// Returns `{ "set": true }` when `/courier/smtp/connection_uri` is present and a
/// non-empty string, else `{ "set": false }`. Mirrors the IDENT-03 dedicated path:
/// a fixed target file (`kratos.yml`), NOT the `{service}/{section}` allowlist.
///
/// On the protected subtree: `auth_guard` (401 unauth). GET is csrf-exempt.
#[handler]
pub async fn get_smtp_connection(
    _req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<Value>, AppError> {
    let cfg = config_from(depot)?;
    let path = config_file_path(&cfg.config_dir, restart::Service::Kratos);
    let doc = yaml::load(&path)?;

    // "set" iff the pointer is present AND a non-empty string. We read ONLY the
    // boolean presence — the value itself is never bound to a variable that could
    // reach the body or a log line.
    let set = matches!(
        doc.pointer(SMTP_CONNECTION_URI_POINTER),
        Some(Value::String(s)) if !s.is_empty()
    );
    Ok(Json(serde_json::json!({ "set": set })))
}

/// `PUT /api/kratos/smtp-connection` — dedicated write-only setter for the SMTP
/// `connection_uri`, reusing the Phase-4 transactional engine (lock -> validate ->
/// backup -> atomic-write -> restart Kratos -> health-poll -> rollback).
///
/// Body: `{ "connection_uri": "<smtps://…>" }`.
///   - value == [`secret_merge::MASKED`] OR empty/absent => "unchanged":
///       * if a value is ALREADY stored, this is an idempotent NO-OP (no lock-held
///         write, no restart) returning `{status:"healthy"}` (write-only-preserve);
///       * if NO value is stored, 422 a value-free FieldError ("connection_uri
///         required") — there is nothing to preserve.
///   - a real value => single-pointer patch `[(/courier/smtp/connection_uri, v)]`
///     through the engine.
///
/// This dedicated handler is the authorization: it can only EVER touch the one
/// fixed pointer, so it deliberately does NOT route through `allowlist::filter`
/// (which would 403 the denylisted pointer, Pitfall 2). The URI value never
/// appears in any response body or tracing line (BACK-07).
///
/// On the protected subtree: `auth_guard` (401) + `csrf_guard` (403 without
/// `X-CSRF-Token`, since this is state-changing).
#[handler]
pub async fn put_smtp_connection(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<Value>, AppError> {
    #[derive(serde::Deserialize)]
    struct SmtpBody {
        connection_uri: Option<String>,
    }

    let cfg = config_from(depot)?;
    let svc = restart::Service::Kratos;

    // Parse the body up front (malformed -> 400 before the lock). The value is
    // never logged.
    let body: SmtpBody = req
        .parse_json()
        .await
        .map_err(|_| AppError::BadRequest("invalid JSON body".into()))?;
    let incoming = body.connection_uri.unwrap_or_default();
    // "unchanged" signal: the masked sentinel or an empty value.
    let unchanged = incoming.is_empty() || incoming == secret_merge::MASKED;

    // --- Step 1: kratos write lock (busy -> 409 config_busy) -----------------
    // Shares the per-service lock with put_config/put_identity_schema.
    let _guard = locks::try_acquire("kratos").await?;
    tracing::info!(service = svc.key(), "smtp-connection put: lock acquired");

    let path = config_file_path(&cfg.config_dir, svc);

    // Write-only-preserve: a masked/empty PUT must NEVER overwrite a stored value.
    if unchanged {
        let doc = yaml::load(&path)?;
        let already_set = matches!(
            doc.pointer(SMTP_CONNECTION_URI_POINTER),
            Some(Value::String(s)) if !s.is_empty()
        );
        if already_set {
            // Idempotent no-op: keep the stored secret, no write, no restart.
            tracing::info!(
                service = svc.key(),
                status = "unchanged",
                "smtp-connection put: masked/empty with a stored value — preserved (no write)"
            );
            return Ok(Json(serde_json::json!({ "status": "healthy" })));
        }
        // Nothing stored to preserve -> a value is required. Value-free 422.
        return Err(AppError::Validation(vec![schema::FieldError {
            path: SMTP_CONNECTION_URI_POINTER.to_string(),
            message: "connection_uri required".to_string(),
        }]));
    }

    // --- Real value: single-pointer engine flow -----------------------------
    let mut merged = yaml::load(&path)?;
    // Single fixed-pointer patch — NOT via allowlist::filter (the pointer is
    // denylisted; this dedicated handler IS the authorization, T-07-07).
    let patch = vec![(
        SMTP_CONNECTION_URI_POINTER.to_string(),
        Value::String(incoming),
    )];
    yaml::apply_patch(&mut merged, &patch)?;

    // --- VALIDATE the env-overlaid effective doc (dsn overlay, T-07-09) ------
    let validator = schema::validator_for("kratos").map_err(|e| {
        tracing::error!(error = %e, service = svc.key(), "schema compile failed");
        AppError::Internal("config schema unavailable".into())
    })?;
    let effective = schema::effective_for_validation("kratos", &merged);
    if let Err(fields) = schema::validate_full(validator, &effective) {
        tracing::debug!(service = svc.key(), count = fields.len(), "smtp-connection put: validation failed");
        return Err(AppError::Validation(fields));
    }

    // --- BACKUP + WR-02 assert ----------------------------------------------
    yaml::backup(&path)?;
    if !yaml::backup_exists(&path) {
        tracing::error!(service = svc.key(), "smtp-connection put: backup missing after backup(); refusing reversible write");
        return Err(AppError::Internal("config backup missing".into()));
    }

    // --- ATOMIC WRITE the merged doc (no env overlay) ------------------------
    let serialized = yaml::serialize(&merged)?;
    yaml::write_atomic(&path, &serialized)?;
    tracing::info!(service = svc.key(), status = "applied", "smtp-connection put: written");

    // --- RESTART kratos + health-poll + rollback ----------------------------
    let http = restart::restart_client()?;
    tracing::info!(service = svc.key(), status = "restarting", "smtp-connection put: restarting");
    if let Err(e) = restart::restart(&http, &cfg.restart_broker_url, svc).await {
        tracing::warn!(service = svc.key(), "smtp-connection put: broker restart failed; restoring disk (no re-restart)");
        restore_only(&path, svc);
        return Err(e);
    }
    if restart::wait_healthy(&http, svc, HEALTH_TIMEOUT, None).await {
        tracing::info!(service = svc.key(), status = "healthy", "smtp-connection put: healthy");
        return Ok(Json(serde_json::json!({ "status": "healthy" })));
    }
    tracing::warn!(service = svc.key(), "smtp-connection put: health failed; rolling back");
    rollback_and_restart(&http, &path, &cfg, svc).await;
    Err(AppError::HealthFailed)
}

/// WR-03 broker-failure rollback: restore the last-known-good `.bak` ONLY (no
/// restart — the broker just failed and the service never left its old config).
/// Surfaces the restore outcome distinctly (WR-02): a missing backup or a
/// restore IO fault is logged at error with a clear marker so an operator can
/// detect that disk may NOT match the running service. The client still receives
/// the originating broker error regardless.
fn restore_only(path: &std::path::Path, svc: restart::Service) {
    match yaml::restore(path) {
        Ok(yaml::RestoreOutcome::Restored) => {
            tracing::info!(
                service = svc.key(),
                status = "rolled_back_disk_only",
                "config put: broker failed; disk restored to last-known-good (service never restarted)"
            );
        }
        Ok(yaml::RestoreOutcome::NoBackup) => {
            tracing::error!(
                service = svc.key(),
                status = "rollback_no_backup",
                "config put: broker failed AND no backup to restore — DISK MAY DIFFER from running config"
            );
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                service = svc.key(),
                status = "rollback_restore_failed",
                "config put: broker failed AND restore failed — DISK LEFT IN WRITTEN (BAD) STATE"
            );
        }
    }
}

/// WR-03 health-failure rollback: restore the last-known-good `.bak`, restart,
/// and re-poll the service so it returns onto a config it can serve. The restore
/// outcome AND the rollback-restart outcome are each surfaced distinctly
/// (WR-02/WR-03) at error level with a stable marker so operators can detect a
/// stuck service. A failure DURING rollback never changes the client-facing
/// outcome — the caller already returns the originating error. No value logged.
async fn rollback_and_restart(
    http: &reqwest::Client,
    path: &std::path::Path,
    cfg: &Config,
    svc: restart::Service,
) {
    match yaml::restore(path) {
        Ok(yaml::RestoreOutcome::Restored) => {}
        Ok(yaml::RestoreOutcome::NoBackup) => {
            // Nothing to restore: the service is running the bad config and we
            // have no last-known-good. Loudly flag it; do NOT restart into bad.
            tracing::error!(
                service = svc.key(),
                status = "rollback_no_backup",
                "config put: health failed AND no backup to restore — service may be STUCK on bad config"
            );
            return;
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                service = svc.key(),
                status = "rollback_restore_failed",
                "config put: health failed AND restore failed — service may be STUCK on bad config"
            );
            return;
        }
    }

    // Restart back into the restored last-known-good config; report the outcome.
    if let Err(e) = restart::restart(http, &cfg.restart_broker_url, svc).await {
        tracing::error!(
            error = %e,
            service = svc.key(),
            status = "rollback_restart_failed",
            "config put: rollback restart FAILED — service may be STUCK; disk is last-known-good"
        );
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
    /// unit-testable without a router/filesystem. Mirrors the handler EXACTLY,
    /// including the WR-01 sensitive-denylist filter on the read path.
    fn build_get_response(allow: &allowlist::SectionAllowlist, doc: &Value) -> Value {
        let mut out = Map::new();
        for ptr in allow.allowed_paths {
            if allowlist::is_sensitive(ptr) {
                continue; // WR-01: never surface a denylisted/secret value on GET
            }
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
    fn get_applies_denylist_even_if_allowlisted() {
        // WR-01: if a sensitive pointer were MISTAKENLY added to a section
        // allowlist, GET must still refuse to surface its value (the denylist
        // wins on the read path, exactly as it does on PUT).
        let mistaken = allowlist::SectionAllowlist {
            service: "kratos",
            section: "mistaken",
            allowed_paths: &["/session/lifespan", "/dsn", "/secrets/cookie/0"],
        };
        let mut doc = no_session_kratos();
        doc["session"] = json!({ "lifespan": "24h" });
        let resp = build_get_response(&mistaken, &doc);
        let obj = resp.as_object().expect("object");
        // The benign allowlisted pointer is returned...
        assert_eq!(obj.get("/session/lifespan"), Some(&json!("24h")));
        // ...but the sensitive ones are filtered out by the denylist, even
        // though they are present in the doc AND (wrongly) in the allowlist.
        assert!(!obj.contains_key("/dsn"), "denylisted /dsn must be filtered on GET");
        assert!(
            !obj.contains_key("/secrets/cookie/0"),
            "denylisted /secrets/* must be filtered on GET"
        );
        let serialized = serde_json::to_string(&resp).unwrap();
        assert!(!serialized.contains("postgres://"), "no dsn value leaks via GET");
        assert!(!serialized.contains("PLACEHOLDERcookie"), "no secret value leaks via GET");
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

    // ─── Task 3: array-section selection + GET-mask/decode, PUT-merge/encode ───

    #[test]
    fn array_descriptor_selected_by_section_name_only() {
        // The three array sections resolve a descriptor; scalar sections do NOT.
        assert!(array_section_descriptor("oidc").is_some());
        assert!(array_section_descriptor("sms").is_some());
        assert!(array_section_descriptor("webhooks").is_some());
        for scalar in ["methods", "mfa", "sessions", "recovery", "verification", "smtp", "session"] {
            assert!(
                array_section_descriptor(scalar).is_none(),
                "scalar section `{scalar}` must not be treated as an array section"
            );
        }
    }

    #[test]
    fn get_transform_masks_oidc_secret_and_decodes_mapper() {
        // An OIDC providers array with a real client_secret and a base64:// mapper:
        // GET must mask the secret and decode the mapper to plaintext source.
        let mapper_uri = crate::config_edit::jsonnet::encode_base64_uri("local jsonnet = 1;");
        let providers = json!([{
            "id": "google",
            "provider": "google",
            "client_id": "public-id",
            "client_secret": "REAL-SECRET",
            "mapper_url": mapper_uri
        }]);
        let desc = array_section_descriptor("oidc").unwrap();
        let out = array_get_transform(&providers, &desc).expect("transform ok");
        let item = &out.as_array().unwrap()[0];
        assert_eq!(item["client_secret"], json!(secret_merge::MASKED), "secret masked");
        assert_eq!(item["client_id"], json!("public-id"), "non-secret untouched");
        assert_eq!(item["mapper_url"], json!("local jsonnet = 1;"), "mapper decoded to source");
        // No real secret survives in the serialized GET payload.
        let s = serde_json::to_string(&out).unwrap();
        assert!(!s.contains("REAL-SECRET"), "client_secret leaked on GET: {s}");
    }

    #[test]
    fn put_transform_preserves_masked_secret_and_encodes_mapper() {
        // Stored has a real secret; incoming leaves it masked and edits the mapper
        // (as plaintext source). After the PUT transform: the stored secret is
        // preserved and the mapper is re-encoded to base64://.
        let stored = json!([{
            "id": "google",
            "provider": "google",
            "client_id": "public-id",
            "client_secret": "REAL-SECRET",
            "mapper_url": crate::config_edit::jsonnet::encode_base64_uri("old;")
        }]);
        let incoming = json!([{
            "id": "google",
            "provider": "google",
            "client_id": "public-id",
            "client_secret": secret_merge::MASKED,
            "mapper_url": "new source;"
        }]);
        let desc = array_section_descriptor("oidc").unwrap();
        let out = array_put_transform(&stored, &incoming, &desc).expect("transform ok");
        let item = &out.as_array().unwrap()[0];
        // Stored secret preserved (NOT clobbered with the mask).
        assert_eq!(item["client_secret"], json!("REAL-SECRET"));
        // Mapper re-encoded to base64:// of the new source; decode round-trips.
        let stored_uri = item["mapper_url"].as_str().unwrap();
        assert!(stored_uri.starts_with("base64://"), "mapper stored as base64://: {stored_uri}");
        assert_eq!(
            crate::config_edit::jsonnet::decode_base64_uri(stored_uri).unwrap(),
            "new source;"
        );
    }

    #[test]
    fn array_transform_passes_through_non_array_value() {
        // A scalar allowlisted pointer in an array section (e.g. oidc.enabled =
        // true) must pass through both transforms unchanged.
        let desc = array_section_descriptor("oidc").unwrap();
        let scalar = json!(true);
        assert_eq!(array_get_transform(&scalar, &desc).unwrap(), json!(true));
        assert_eq!(
            array_put_transform(&json!(null), &scalar, &desc).expect("passthrough ok"),
            json!(true)
        );
    }

    #[test]
    fn array_put_transform_fails_closed_on_renamed_id_masked_secret() {
        // CR-01: an OIDC PUT that renames the provider id while leaving the
        // client_secret masked has no stored value to inherit -> 422 (the
        // sentinel literal must NEVER be written to disk).
        let stored = json!([{
            "id": "google",
            "provider": "google",
            "client_id": "public-id",
            "client_secret": "REAL-SECRET",
            "mapper_url": crate::config_edit::jsonnet::encode_base64_uri("m;")
        }]);
        let incoming = json!([{
            "id": "g00gle",
            "provider": "google",
            "client_id": "public-id",
            "client_secret": secret_merge::MASKED,
            "mapper_url": "m;"
        }]);
        let desc = array_section_descriptor("oidc").unwrap();
        let err = array_put_transform(&stored, &incoming, &desc)
            .expect_err("renamed-id + masked secret must 422");
        match err {
            AppError::Validation(fields) => {
                assert_eq!(fields.len(), 1);
                // The operator-safe message names the item and asks to re-enter;
                // it never contains the secret value or the sentinel literal.
                assert!(fields[0].message.contains("g00gle"));
                assert!(fields[0].message.contains("re-enter the secret"));
                assert!(!fields[0].message.contains(secret_merge::MASKED));
            }
            other => panic!("expected Validation 422, got {other:?}"),
        }
    }
}
