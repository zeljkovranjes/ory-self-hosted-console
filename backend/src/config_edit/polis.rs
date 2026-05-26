//! Dedicated Ory Polis ENV/settings writer (SSO-01, Phase 13 — RESEARCH Pattern 3).
//!
//! Polis (boxyhq/jackson) is ENV-configured: there is NO `polis.config.schema.json`
//! and NO mounted JSON-Schema'd YAML to patch. Routing it through the Phase-4
//! `{service}/{section}` allowlist + `schema::*` + `yaml::apply_patch` engine is the
//! Dex-carryover trap (RESEARCH Pitfall 1). So this is a PURPOSE-BUILT writer that
//! edits ONLY a small, fixed, code-defined allowlist of NON-secret Polis settings and
//! persists them to `<config_dir>/polis/settings.env` (a `KEY=value` env file the
//! Polis container reads).
//!
//! It REUSES only the restart/health machinery and the disk discipline:
//! lock -> filter -> backup -> `backup_exists` assert -> atomic-write -> restart
//! ONLY `Service::Polis` -> health-poll `/api/health` -> rollback on timeout. The
//! `restore_only` (broker-failure, no re-restart) vs `rollback_and_restart`
//! (health-failure) split mirrors `routes.rs` exactly.
//!
//! ## Three hard rules the filter enforces BEFORE any disk touch
//!
//! 1. **Allowlist (T-13-06):** any key not in [`POLIS_EDITABLE`] -> `Forbidden`
//!    (403 `forbidden_key`). The rejected key's VALUE is never echoed/logged.
//! 2. **Write-only secrets (T-13-07 / BACK-07):** any [`POLIS_SECRETS`] key is
//!    explicitly rejected (also `Forbidden`) — these are deploy-time-only env/secret
//!    values the backend can never mint or rotate (`DB_ENCRYPTION_KEY`, `API_KEYS`,
//!    `NEXTAUTH_SECRET`, `OPENID_RSA_PRIVATE_KEY`/`OPENID_RSA_PUBLIC_KEY`, `DB_URL`).
//!    They are never read into a returnable var on GET either.
//! 3. **Signature/redirect weakening (T-13-08):** a value that would disable a
//!    security control — e.g. `OPENID_REDIRECT_EXACT_MATCH` set to anything other
//!    than `"true"` — is a hard `Validation` (422) reject (CONTEXT mandate: never
//!    let the console weaken SAML/OIDC redirect or signature enforcement).
//!
//! On the protected subtree: `auth_guard` (401) + `csrf_guard` (403 on the
//! state-changing PUT). The route itself is gated by `FeatureFlagHoop::new("saml")`
//! (404 when OFF) — mounted in `routes/mod.rs`.

use std::path::PathBuf;
use std::time::Duration;

use salvo::prelude::*;
use serde_json::{Map, Value};

use crate::config::Config;
use crate::config_edit::schema::FieldError;
use crate::config_edit::{locks, restart, yaml};
use crate::error::AppError;

/// The fixed, code-defined allowlist of NON-secret Polis settings the console may
/// edit. Anything outside this set is `Forbidden` (403) BEFORE any disk touch
/// (config-injection guard, T-13-06). These map 1:1 to Polis env names.
///
/// - `LOG_LEVEL` — log verbosity.
/// - `OPENID_REDIRECT_EXACT_MATCH` — exact OIDC redirect-URL match (v26.2.0
///   hardening). The filter additionally enforces it can only ever be `"true"`
///   (T-13-08) — it is editable but NOT weakenable.
/// - `BOXYHQ_NO_TELEMETRY` / `DO_NOT_TRACK` — disable anonymous telemetry.
const POLIS_EDITABLE: &[&str] = &[
    "LOG_LEVEL",
    "OPENID_REDIRECT_EXACT_MATCH",
    "BOXYHQ_NO_TELEMETRY",
    "DO_NOT_TRACK",
];

/// The fixed set of WRITE-ONLY Polis secrets / deploy-time-only env names. These are
/// NEVER editable through this page and NEVER read into a returnable var on GET
/// (BACK-07 / T-13-07). They are explicitly rejected on PUT (rather than merely
/// "not in the allowlist") so the refusal is unambiguous and intentional — rotating
/// `DB_ENCRYPTION_KEY` or the OIDC keypair after data exists strands encrypted rows /
/// invalidates issued tokens (RESEARCH Pitfall 5).
const POLIS_SECRETS: &[&str] = &[
    "DB_ENCRYPTION_KEY",
    "API_KEYS",
    "NEXTAUTH_SECRET",
    "OPENID_RSA_PRIVATE_KEY",
    "OPENID_RSA_PUBLIC_KEY",
    "DB_URL",
];

/// The single security-control key that is editable but value-CONSTRAINED: it may
/// only ever be `"true"`. Any other value is a hard `Validation` (422) reject
/// (T-13-08 — never weaken OIDC redirect enforcement from the console).
const OPENID_REDIRECT_EXACT_MATCH: &str = "OPENID_REDIRECT_EXACT_MATCH";

/// How long to wait for the restarted Polis to report healthy before rolling back
/// (mirrors `routes.rs::HEALTH_TIMEOUT`; Polis briefly refuses while it boots).
const HEALTH_TIMEOUT: Duration = Duration::from_secs(60);

/// The server-defined path of the Polis settings env file
/// (`<config_dir>/polis/settings.env`).
///
/// SSO-01: the dedicated writer targets THIS file only — fixed segments, NO part is
/// ever client input (mirrors `routes.rs::opl_file_path`/`identity_schema_path`;
/// config-injection / path-traversal guard, T-13-06 / T-13-10).
pub fn polis_settings_path(config_dir: &str) -> PathBuf {
    PathBuf::from(config_dir).join("polis").join("settings.env")
}

/// Obtain the injected [`Config`] clone from the depot (RESEARCH Pattern 2).
fn config_from(depot: &Depot) -> Result<Config, AppError> {
    depot
        .obtain::<Config>()
        .cloned()
        .map_err(|_| AppError::Internal("config missing from depot".into()))
}

/// Parse a `KEY=value` env file into ordered `(key, value)` pairs.
///
/// Blank lines and `#` comments are skipped. A line without `=` is ignored
/// (defensive — we never fail a GET on a stray malformed line; the file is
/// console-owned). The VALUE is taken verbatim after the first `=` (values may
/// contain `=`). Leading/trailing whitespace around the KEY is trimmed; the value is
/// kept as-authored except for a trailing CR (CRLF tolerance).
fn parse_env(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim().to_string();
        if key.is_empty() {
            continue;
        }
        let value = v.strip_suffix('\r').unwrap_or(v).to_string();
        out.push((key, value));
    }
    out
}

/// Serialize ordered `(key, value)` pairs back to a `KEY=value` env file (one per
/// line, trailing newline). Insertion order is preserved so an edit produces a
/// minimal diff.
fn serialize_env(pairs: &[(String, String)]) -> String {
    let mut s = String::new();
    for (k, v) in pairs {
        s.push_str(k);
        s.push('=');
        s.push_str(v);
        s.push('\n');
    }
    s
}

/// Pure allowlist + secret-refusal + insecure-value gate over an incoming PUT body.
///
/// The body is a flat JSON object whose KEYS are Polis env names. For each entry:
///   - a [`POLIS_SECRETS`] key -> `Forbidden` (explicit write-only refusal, T-13-07);
///   - a key NOT in [`POLIS_EDITABLE`] -> `Forbidden` (config-injection guard,
///     T-13-06);
///   - `OPENID_REDIRECT_EXACT_MATCH` whose value != `"true"` -> `Validation` (422)
///     (signature/redirect-weakening hard reject, T-13-08);
///   - otherwise the value is coerced to its string form.
///
/// NO rejected VALUE ever appears in the returned error (only the offending KEY name,
/// which is operator-supplied and non-secret by definition of being out-of-allowlist
/// — and for a secret KEY the value is never touched). A non-object body is a 400.
///
/// Pure: no router, no filesystem, no live Polis — fully unit-testable.
fn filter_polis_patch(body: &Value) -> Result<Vec<(String, String)>, AppError> {
    let Value::Object(map) = body else {
        return Err(AppError::BadRequest(
            "polis settings patch must be a flat JSON object".into(),
        ));
    };

    let mut out = Vec::with_capacity(map.len());
    for (key, value) in map {
        // 1) Write-only secret: explicit refusal (never written, never logged). The
        //    VALUE is never read/echoed; only the (operator-supplied) key name.
        if POLIS_SECRETS.contains(&key.as_str()) {
            tracing::debug!(key = %key, "polis put: refused write-only secret key");
            return Err(AppError::Forbidden);
        }
        // 2) Allowlist: anything else outside POLIS_EDITABLE is forbidden.
        if !POLIS_EDITABLE.contains(&key.as_str()) {
            tracing::debug!(key = %key, "polis put: refused out-of-allowlist key");
            return Err(AppError::Forbidden);
        }
        // Coerce to the string form stored in the env file. Reject a non-scalar
        // (object/array) value structurally (422, value-free).
        let as_str = match value {
            Value::String(s) => s.clone(),
            Value::Bool(b) => b.to_string(),
            Value::Number(n) => n.to_string(),
            Value::Null | Value::Object(_) | Value::Array(_) => {
                return Err(AppError::Validation(vec![FieldError {
                    path: key.clone(),
                    message: "value must be a string, number, or boolean".to_string(),
                }]));
            }
        };
        // 3) Security-control hard rule: OPENID_REDIRECT_EXACT_MATCH may only be
        //    "true". Anything falsy/other weakens OIDC redirect enforcement (T-13-08).
        if key == OPENID_REDIRECT_EXACT_MATCH && as_str != "true" {
            tracing::debug!("polis put: refused weakening of OPENID_REDIRECT_EXACT_MATCH");
            return Err(AppError::Validation(vec![FieldError {
                path: key.clone(),
                message: "OPENID_REDIRECT_EXACT_MATCH cannot be disabled — it must remain \"true\""
                    .to_string(),
            }]));
        }
        out.push((key.clone(), as_str));
    }
    Ok(out)
}

/// `GET /api/config/polis` — return ONLY the current NON-secret allowlisted Polis
/// settings (SSO-01).
///
/// Reads the server-built [`polis_settings_path`] and emits a flat JSON object of
/// the present [`POLIS_EDITABLE`] keys. A secret ([`POLIS_SECRETS`]) value is NEVER
/// read into a returnable var — the response is built solely from the editable
/// allowlist, so a secret can never leak even incidentally (T-13-07). An absent
/// settings file yields an empty object (the operator has not customised anything
/// yet). On the protected subtree: `auth_guard` (401) + gated by the `saml` flag.
/// GET is csrf-exempt.
#[handler]
pub async fn get_polis_settings(
    _req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<Value>, AppError> {
    let cfg = config_from(depot)?;
    let path = polis_settings_path(&cfg.config_dir);

    // An absent file is the "nothing customised yet" state -> empty object (NOT an
    // error). A read error on an EXISTING file is a generic internal fault (no path
    // echoed, BACK-07).
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            tracing::error!(error = %e, "polis settings read failed");
            return Err(AppError::Internal("polis settings read failed".into()));
        }
    };

    // Build the response from ONLY the editable allowlist that is PRESENT in the
    // file. A secret key in the file is never matched here (it is not in
    // POLIS_EDITABLE), so its value is never read into `out`.
    let parsed = parse_env(&text);
    let mut out = Map::new();
    for (k, v) in parsed {
        if POLIS_EDITABLE.contains(&k.as_str()) {
            out.insert(k, Value::String(v));
        }
    }
    Ok(Json(Value::Object(out)))
}

/// `PUT /api/config/polis` — filter (allowlist + secret-refusal + insecure-value
/// reject) -> merge -> backup -> atomic-write -> restart ONLY Polis -> health-poll
/// `/api/health` -> rollback on timeout (SSO-01).
///
/// Mirrors the Phase-4 dedicated-writer discipline (`routes.rs`) but uses the
/// dedicated [`filter_polis_patch`] gate and a `KEY=value` env file instead of the
/// `{service}/{section}` YAML schema engine (Pitfall 1). On the protected subtree:
/// `auth_guard` (401) + `csrf_guard` (403 without `X-CSRF-Token`) + gated by the
/// `saml` flag (404 when OFF).
#[handler]
pub async fn put_polis_settings(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<Value>, AppError> {
    let cfg = config_from(depot)?;
    let svc = restart::Service::Polis;

    // Parse the body up front (malformed -> 400 before the lock). Values are never
    // logged.
    let raw_body: Value = req
        .parse_json()
        .await
        .map_err(|_| AppError::BadRequest("invalid JSON body".into()))?;

    // --- Step 1: polis write lock (busy -> 409 config_busy) ------------------
    let _guard = locks::try_acquire("polis").await?;
    tracing::info!(service = svc.key(), "polis put: lock acquired");

    // --- Step 2: FILTER (allowlist + secret-refusal + insecure-value) --------
    // Out-of-allowlist/secret -> 403; weakening value -> 422. NO disk touched yet,
    // and no rejected value is ever echoed.
    let filtered = filter_polis_patch(&raw_body)?;
    // An empty (post-filter) patch is a no-op: nothing to write, nothing to restart.
    if filtered.is_empty() {
        tracing::info!(service = svc.key(), status = "unchanged", "polis put: empty patch — no write");
        return Ok(Json(serde_json::json!({ "status": "healthy" })));
    }

    // --- Step 3: LOAD + MERGE into the current env file ----------------------
    let path = polis_settings_path(&cfg.config_dir);
    let existing_text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            tracing::error!(error = %e, "polis settings read failed");
            return Err(AppError::Internal("polis settings read failed".into()));
        }
    };
    let mut pairs = parse_env(&existing_text);
    // Upsert each filtered (allowlisted) key, preserving the order of unmanaged keys
    // (e.g. a deploy-time secret line, if present, is left byte-untouched — we only
    // ever rewrite an allowlisted key's value or append it).
    for (k, v) in filtered {
        if let Some(slot) = pairs.iter_mut().find(|(ek, _)| *ek == k) {
            slot.1 = v;
        } else {
            pairs.push((k, v));
        }
    }
    let serialized = serialize_env(&pairs);

    // --- Step 3b: ENSURE the parent dir exists (SSO-01 first-edit) -----------
    // The server-built path is `<config_dir>/polis/settings.env`. Unlike the four
    // Ory services, Polis ships NO seeded config directory, so on the very FIRST
    // console edit the `polis/` subdir does not exist yet and `write_atomic`'s
    // `NamedTempFile::new_in(<dir>)` would fail (500). Create the parent dir
    // (idempotent) before the backup/write. The path is fully server-built (fixed
    // segments, no client input — T-13-06), so this introduces no traversal risk.
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            tracing::error!(error = %e, service = svc.key(), "polis put: could not create the polis config dir");
            return Err(AppError::Internal("polis settings dir create failed".into()));
        }
    }

    // --- Step 4: BACKUP + WR-02 assert ---------------------------------------
    // If the file does not exist yet there is nothing to back up; in that case a
    // rollback target is the "remove the file" state. We only `backup` (and assert
    // the .bak) when a live file exists, so a brand-new write is reversible by
    // truncation handled in the rollback path. Mirror routes.rs WR-02 when a live
    // file is present.
    let had_existing = path.is_file();
    if had_existing {
        yaml::backup(&path)?;
        if !yaml::backup_exists(&path) {
            tracing::error!(service = svc.key(), "polis put: backup missing after backup(); refusing reversible write");
            return Err(AppError::Internal("polis settings backup missing".into()));
        }
    }

    // --- Step 5: ATOMIC WRITE the merged env file ----------------------------
    // Written RAW (NOT YAML/JSON serialised) — it is a `KEY=value` env file Polis
    // reads. The atomic write (temp-in-same-dir + fsync + rename) is the reused
    // engine primitive.
    yaml::write_atomic(&path, &serialized)?;
    tracing::info!(service = svc.key(), status = "applied", "polis put: written");

    // --- Step 6: RESTART only Polis via the scoped broker --------------------
    let http = restart::restart_client()?;
    tracing::info!(service = svc.key(), status = "restarting", "polis put: restarting");
    if let Err(e) = restart::restart(&http, &cfg.restart_broker_url, svc).await {
        // BROKER-FAILURE: Polis never restarted, so it still runs its OLD env;
        // restore disk only so disk matches the running service (no re-restart
        // through the just-failed broker). Mirrors routes.rs restore_only.
        tracing::warn!(service = svc.key(), "polis put: broker restart failed; restoring disk (no re-restart)");
        polis_restore_only(&path, had_existing, svc);
        return Err(e);
    }

    // --- Step 7: HEALTH-POLL /api/health until ready or timeout --------------
    if restart::wait_healthy(&http, svc, HEALTH_TIMEOUT, None).await {
        tracing::info!(service = svc.key(), status = "healthy", "polis put: healthy");
        return Ok(Json(serde_json::json!({ "status": "healthy" })));
    }

    // --- Step 8: ROLLBACK on health failure ----------------------------------
    // HEALTH-FAILURE: Polis restarted into the new env and is unhealthy; restore the
    // last-known-good (or remove a brand-new file), restart again, re-poll.
    tracing::warn!(service = svc.key(), "polis put: health failed; rolling back");
    polis_rollback_and_restart(&http, &path, had_existing, &cfg, svc).await;
    Err(AppError::HealthFailed)
}

/// Broker-failure rollback (no re-restart): restore the `.bak`, or if the write
/// CREATED a brand-new file (no prior backup), remove it so disk returns to the
/// "not customised" state. Mirrors `routes.rs::restore_only`. No value logged.
fn polis_restore_only(path: &std::path::Path, had_existing: bool, svc: restart::Service) {
    if !had_existing {
        // A brand-new file: the last-known-good is "absent". Remove it so disk
        // matches the still-running (pre-write) Polis env.
        if let Err(e) = std::fs::remove_file(path) {
            tracing::error!(error = %e, service = svc.key(), status = "rollback_remove_failed", "polis put: broker failed AND removing the new file failed — DISK LEFT IN WRITTEN STATE");
        } else {
            tracing::info!(service = svc.key(), status = "rolled_back_disk_only", "polis put: broker failed; new settings file removed (service never restarted)");
        }
        return;
    }
    match yaml::restore(path) {
        Ok(yaml::RestoreOutcome::Restored) => {
            tracing::info!(service = svc.key(), status = "rolled_back_disk_only", "polis put: broker failed; disk restored to last-known-good (service never restarted)");
        }
        Ok(yaml::RestoreOutcome::NoBackup) => {
            tracing::error!(service = svc.key(), status = "rollback_no_backup", "polis put: broker failed AND no backup to restore — DISK MAY DIFFER from running config");
        }
        Err(e) => {
            tracing::error!(error = %e, service = svc.key(), status = "rollback_restore_failed", "polis put: broker failed AND restore failed — DISK LEFT IN WRITTEN (BAD) STATE");
        }
    }
}

/// Health-failure rollback: restore the last-known-good (or remove a brand-new
/// file), restart Polis again, and re-poll so it returns onto a config it can serve.
/// Mirrors `routes.rs::rollback_and_restart`. A failure DURING rollback never
/// changes the client-facing outcome (the caller already returns `HealthFailed`).
async fn polis_rollback_and_restart(
    http: &reqwest::Client,
    path: &std::path::Path,
    had_existing: bool,
    cfg: &Config,
    svc: restart::Service,
) {
    if !had_existing {
        // Brand-new file: remove it to return to the "not customised" state, then
        // restart back onto the original env.
        if let Err(e) = std::fs::remove_file(path) {
            tracing::error!(error = %e, service = svc.key(), status = "rollback_remove_failed", "polis put: health failed AND removing the new file failed — service may be STUCK on bad config");
            return;
        }
    } else {
        match yaml::restore(path) {
            Ok(yaml::RestoreOutcome::Restored) => {}
            Ok(yaml::RestoreOutcome::NoBackup) => {
                tracing::error!(service = svc.key(), status = "rollback_no_backup", "polis put: health failed AND no backup to restore — service may be STUCK on bad config");
                return;
            }
            Err(e) => {
                tracing::error!(error = %e, service = svc.key(), status = "rollback_restore_failed", "polis put: health failed AND restore failed — service may be STUCK on bad config");
                return;
            }
        }
    }

    if let Err(e) = restart::restart(http, &cfg.restart_broker_url, svc).await {
        tracing::error!(error = %e, service = svc.key(), status = "rollback_restart_failed", "polis put: rollback restart FAILED — service may be STUCK; disk is last-known-good");
        return;
    }
    let healthy = restart::wait_healthy(http, svc, HEALTH_TIMEOUT, None).await;
    if healthy {
        tracing::info!(service = svc.key(), status = "rolled_back", "polis put: rolled back to last-known-good and healthy");
    } else {
        tracing::error!(service = svc.key(), status = "rollback_unhealthy", "polis put: rolled back but service still UNHEALTHY");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn out_of_allowlist_key_is_forbidden() {
        // A key not in POLIS_EDITABLE (and not a known secret) is a 403 forbidden_key
        // BEFORE any disk touch. The rejected VALUE never appears in the error.
        let err = filter_polis_patch(&json!({ "ARBITRARY_KEY": "supersecretvalue" }))
            .expect_err("out-of-allowlist must be forbidden");
        assert!(matches!(err, AppError::Forbidden), "got {err:?}");
        assert!(
            !err.to_string().contains("supersecretvalue"),
            "the rejected value must never appear in the error: {err}"
        );
    }

    #[test]
    fn every_secret_key_is_forbidden() {
        // Each write-only secret is explicitly refused (403), and its value is never
        // echoed into the error (T-13-07 / BACK-07).
        for secret in POLIS_SECRETS {
            let body = json!({ *secret: "THE-RAW-SECRET-MATERIAL" });
            let err = filter_polis_patch(&body).expect_err("secret must be forbidden");
            assert!(matches!(err, AppError::Forbidden), "{secret}: got {err:?}");
            assert!(
                !err.to_string().contains("THE-RAW-SECRET-MATERIAL"),
                "{secret}: the secret value must never appear in the error: {err}"
            );
        }
    }

    #[test]
    fn weakening_redirect_exact_match_is_validation() {
        // OPENID_REDIRECT_EXACT_MATCH set to anything other than "true" is a hard
        // 422 (T-13-08), even though the key IS in the editable allowlist.
        for bad in ["false", "0", "no", ""] {
            let err = filter_polis_patch(&json!({ "OPENID_REDIRECT_EXACT_MATCH": bad }))
                .expect_err("weakening must be a validation error");
            assert!(
                matches!(err, AppError::Validation(_)),
                "value {bad:?}: got {err:?}"
            );
        }
        // A boolean false likewise (coerced to "false").
        let err = filter_polis_patch(&json!({ "OPENID_REDIRECT_EXACT_MATCH": false }))
            .expect_err("bool false must be a validation error");
        assert!(matches!(err, AppError::Validation(_)), "got {err:?}");
    }

    #[test]
    fn valid_non_secret_patch_is_ok() {
        // A patch of allowlisted, non-secret keys with safe values passes. The
        // hardening key set to "true" is allowed; values are coerced to strings.
        let patch = filter_polis_patch(&json!({
            "LOG_LEVEL": "debug",
            "OPENID_REDIRECT_EXACT_MATCH": "true",
            "BOXYHQ_NO_TELEMETRY": "1",
            "DO_NOT_TRACK": true,
        }))
        .expect("valid non-secret patch must pass");
        // All four keys are present and coerced to string values.
        let map: std::collections::HashMap<_, _> = patch.into_iter().collect();
        assert_eq!(map.get("LOG_LEVEL").map(String::as_str), Some("debug"));
        assert_eq!(
            map.get("OPENID_REDIRECT_EXACT_MATCH").map(String::as_str),
            Some("true")
        );
        assert_eq!(map.get("DO_NOT_TRACK").map(String::as_str), Some("true"));
    }

    #[test]
    fn non_object_body_is_bad_request() {
        let err = filter_polis_patch(&json!(["LOG_LEVEL", "debug"]))
            .expect_err("array body must be a 400");
        assert!(matches!(err, AppError::BadRequest(_)), "got {err:?}");
    }

    #[test]
    fn env_round_trips_and_merges() {
        // parse_env tolerates comments/blank lines and keeps order; serialize is the
        // inverse for the data lines; merge upserts in place / appends.
        let text = "# header comment\nLOG_LEVEL=info\n\nDO_NOT_TRACK=1\n";
        let pairs = parse_env(text);
        assert_eq!(
            pairs,
            vec![
                ("LOG_LEVEL".to_string(), "info".to_string()),
                ("DO_NOT_TRACK".to_string(), "1".to_string()),
            ]
        );
        // A value containing '=' is preserved verbatim after the first '='.
        let with_eq = parse_env("DB_URL=postgres://u:p@h/db?a=b\n");
        assert_eq!(with_eq[0].1, "postgres://u:p@h/db?a=b");
        // serialize is the inverse of the data lines (comments are dropped — this is
        // an env file, not a doc with comment nodes).
        let out = serialize_env(&pairs);
        assert_eq!(out, "LOG_LEVEL=info\nDO_NOT_TRACK=1\n");
    }

    #[test]
    fn settings_path_is_server_built() {
        // Fixed segments only — no client input can steer the path.
        let p = polis_settings_path("/etc/config");
        assert!(p.ends_with("polis/settings.env") || p.ends_with("polis\\settings.env"));
    }
}
