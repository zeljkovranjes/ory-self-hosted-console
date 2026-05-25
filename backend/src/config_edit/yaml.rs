//! YAML load / merge (create-bounded) / atomic-write / backup / restore primitives
//! over `serde_json::Value` (BACK-04). The pure, Docker-free mechanism every config
//! page (P7–P10) reuses.
//!
//! ## The two doc invariant (threats T-04-22 / T-04-23)
//!
//! - **validate(effective):** schema validation always runs on
//!   [`crate::config_edit::schema::effective_for_validation`]`(svc, &merged)` —
//!   the merged FILE doc UNION the env-injected required keys the committed file
//!   omits (e.g. `/dsn`). The overlay exists ONLY in that validation clone.
//! - **write(file-merged-without-env-keys):** [`apply_patch`] and [`write_atomic`]
//!   operate on the FILE doc ONLY. They NEVER add an env-injected key. The doc
//!   written to disk (and returned to the client) therefore never contains `dsn`,
//!   even though the overlay was used to validate it.
//!
//! ## Serialization & ordering (Pitfall 3 / WR-06)
//!
//! `serde_json::Value` is built WITH the `preserve_order` feature (see
//! `backend/Cargo.toml`), so its map is an `IndexMap` that keeps INSERTION order.
//! The round-trip through this module therefore PRESERVES the operator's original
//! key ORDER for unmanaged keys: the first save of a hand-authored file no longer
//! alphabetises it into a noisy diff. The round-trip still DROPS YAML comments
//! (the serde data model has no comment node); comment loss is accepted per
//! CONTEXT ("best-effort") and documented in the README — operators must not rely
//! on comments in editable files. We serialize with a SINGLE consistent path
//! ([`serde_yaml_ng::to_string`] of the order-preserving `serde_json::Value`) so
//! behavior is stable.

use std::io::Write;
use std::path::Path;

use serde_json::Value;
use tempfile::NamedTempFile;

use crate::error::AppError;

/// Load a YAML file into a `serde_json::Value` via the serde data model.
///
/// YAML scalar typing maps to JSON (`true`->bool, `123`->number, `"x"`->string) as
/// draft-07 type checks expect. Parse / IO errors map to a generic
/// `AppError::Internal` — we NEVER echo the file path or the raw parse error into a
/// client-facing body (BACK-07 / threat T-04-09); the detail is logged server-side.
pub fn load(path: &Path) -> Result<Value, AppError> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        tracing::error!(error = %e, "config yaml read failed");
        AppError::Internal("config read failed".to_string())
    })?;
    serde_yaml_ng::from_str(&text).map_err(|e| {
        tracing::error!(error = %e, "config yaml parse failed");
        AppError::Internal("config parse failed".to_string())
    })
}

/// Serialize a `serde_json::Value` config doc back to YAML text.
///
/// Single consistent serialize path (see module docs re: ordering / comment loss).
pub fn serialize(doc: &Value) -> Result<String, AppError> {
    serde_yaml_ng::to_string(doc).map_err(|e| {
        tracing::error!(error = %e, "config yaml serialize failed");
        AppError::Internal("config serialize failed".to_string())
    })
}

/// Split an RFC-6901 JSON-Pointer into its decoded reference tokens.
///
/// `""` -> empty (the whole document); `/a/b~1c` -> `["a", "b/c"]`. Unescapes
/// `~1`->`/` and `~0`->`~` (order matters: `~1`/`~0` first, then `~`-escapes).
///
/// This is the SINGLE canonical decode the whole subsystem agrees on: the
/// allowlist gate ([`super::allowlist::filter`]) decodes the incoming pointer
/// with this same function so the gate's verdict is computed against the exact
/// token sequence [`apply_patch`] will use to address the doc (CR-01 — the gate
/// and the writer must compute the identical target).
pub(crate) fn pointer_tokens(pointer: &str) -> Vec<String> {
    if pointer.is_empty() {
        return Vec::new();
    }
    pointer
        .split('/')
        .skip(1) // the leading "" before the first '/'
        .map(|t| t.replace("~1", "/").replace("~0", "~"))
        .collect()
}

/// Re-encode decoded reference tokens into the CANONICAL RFC-6901 pointer
/// (`~`->`~0`, `/`->`~1`, in that order, joined by `/` with a leading `/`).
///
/// `["a", "b/c"]` -> `/a/b~1c`; `[]` -> `""`. Pairing [`pointer_tokens`] with
/// this gives an idempotent normal form: `canonical_pointer(&pointer_tokens(p))`
/// is the unique canonical spelling of `p`. The allowlist gate matches on this
/// form so any escape spelling that DECODES to the same tokens (and only those)
/// is accepted, and the gate can never disagree with the writer about the
/// target (CR-01).
pub(crate) fn canonical_pointer(tokens: &[String]) -> String {
    let mut out = String::new();
    for token in tokens {
        out.push('/');
        // Order matters: escape `~` first, THEN `/`, so a literal `/` does not
        // get double-escaped by the `~`->`~0` pass.
        out.push_str(&token.replace('~', "~0").replace('/', "~1"));
    }
    out
}

/// Apply an ALREADY-ALLOWLIST-FILTERED patch into the FULL file doc, CREATING
/// allowlist-bounded intermediate objects for any absent parent.
///
/// The live `config/kratos/kratos.yml` ships with NO `session:` block, so a naive
/// `pointer_mut`-only approach would 400 on `/session/lifespan` (RESEARCH Code
/// Examples caveat). Instead, for each `(pointer, value)` we walk the pointer's own
/// segments from the doc root:
///   - non-final segment, current node is an object MISSING the key -> insert an
///     empty `Value::Object` and descend (bounded creation);
///   - non-final segment, current node EXISTS but is NOT an object -> `BadRequest`
///     ("unknown config path"): we never coerce/overwrite an existing non-object
///     node, which could clobber unmanaged data (threat T-04-21);
///   - final segment -> set the value.
///
/// The walk is driven SOLELY by the segments of the (already-allowlisted) pointer,
/// so it can never create a node outside that pointer's own path. Allowlist
/// filtering happens upstream ([`super::allowlist::filter`], wired in Plan 04-03);
/// this function trusts only the pointer segments it is handed.
///
/// INVARIANT: operates on the FILE doc only — never adds an env-injected key (`dsn`).
/// Validation against the schema is the caller's job, on
/// `schema::effective_for_validation(svc, &merged)`, NOT on this written doc.
pub fn apply_patch(doc: &mut Value, patch: &[(String, Value)]) -> Result<(), AppError> {
    for (pointer, value) in patch {
        let tokens = pointer_tokens(pointer);
        if tokens.is_empty() {
            // A root ("") pointer would replace the whole doc — never allowlisted.
            return Err(AppError::BadRequest("unknown config path".to_string()));
        }
        let mut cur = &mut *doc;
        for (i, token) in tokens.iter().enumerate() {
            let last = i + 1 == tokens.len();
            // The current node MUST be an object to hold `token`.
            let Value::Object(map) = cur else {
                return Err(AppError::BadRequest("unknown config path".to_string()));
            };
            if last {
                map.insert(token.clone(), value.clone());
                break;
            }
            cur = map
                .entry(token.clone())
                .or_insert_with(|| Value::Object(serde_json::Map::new()));
        }
    }
    Ok(())
}

/// Atomically write `contents` over `target`: temp file in the SAME directory ->
/// fsync -> rename-over (RESEARCH Pattern 3 / Pitfall 2).
///
/// Same-dir placement is mandatory: `persist`/`rename` is atomic only within one
/// filesystem; a `/tmp` temp would degrade to a non-atomic cross-fs copy on the
/// bind mount, risking a torn config (threat T-04-07).
pub fn write_atomic(target: &Path, contents: &str) -> Result<(), AppError> {
    let dir = target.parent().ok_or_else(|| {
        AppError::Internal("config target has no parent directory".to_string())
    })?;
    let mut tmp = NamedTempFile::new_in(dir).map_err(|e| {
        tracing::error!(error = %e, "atomic write: temp create failed");
        AppError::Internal("config write failed".to_string())
    })?;
    tmp.write_all(contents.as_bytes()).map_err(|e| {
        tracing::error!(error = %e, "atomic write: temp write failed");
        AppError::Internal("config write failed".to_string())
    })?;
    tmp.as_file().sync_all().map_err(|e| {
        tracing::error!(error = %e, "atomic write: fsync failed");
        AppError::Internal("config write failed".to_string())
    })?;
    tmp.persist(target).map_err(|e| {
        tracing::error!(error = %e, "atomic write: persist/rename failed");
        AppError::Internal("config write failed".to_string())
    })?;
    Ok(())
}

/// Path of the single last-known-good backup for `target` (`<file>.bak`).
fn backup_path(target: &Path) -> std::path::PathBuf {
    let mut name = target.as_os_str().to_os_string();
    name.push(".bak");
    std::path::PathBuf::from(name)
}

/// Copy the current live `target` to `<target>.bak` (single last-known-good backup,
/// RESEARCH Open Question 2 — RESOLVED). Overwrites any prior `.bak`.
pub fn backup(target: &Path) -> Result<(), AppError> {
    let bak = backup_path(target);
    std::fs::copy(target, &bak).map_err(|e| {
        tracing::error!(error = %e, "config backup failed");
        AppError::Internal("config backup failed".to_string())
    })?;
    Ok(())
}

/// True iff the last-known-good backup for `target` (`<target>.bak`) exists.
///
/// WR-02: the PUT flow asserts this immediately AFTER [`backup`] and BEFORE the
/// `write_atomic` it intends to be reversible, so the engine never commits a
/// write it cannot roll back.
pub fn backup_exists(target: &Path) -> bool {
    backup_path(target).is_file()
}

/// Outcome of a [`restore`] attempt — distinguishes a real rollback from the
/// "there was no backup to restore" case (WR-02). The caller must NOT claim
/// "rolled back to last-known-good" on [`RestoreOutcome::NoBackup`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreOutcome {
    /// The `.bak` existed and was written back over `target` byte-for-byte.
    Restored,
    /// No `.bak` existed: nothing was restored. The live file is UNCHANGED
    /// (still whatever the failing flow last wrote) — a distinct, loud condition.
    NoBackup,
}

/// Restore `target` byte-for-byte from `<target>.bak` via an atomic write, so a
/// failed restore can never leave a torn live file (threat T-04-07).
///
/// WR-02: a MISSING backup is NOT a generic internal error that silently leaves
/// the (possibly broken) live file in place — it is reported distinctly as
/// [`RestoreOutcome::NoBackup`] so the caller never claims a rollback that did
/// not happen. A backup that EXISTS but cannot be read/written is still a hard
/// `AppError::Internal` (a genuine IO fault).
pub fn restore(target: &Path) -> Result<RestoreOutcome, AppError> {
    let bak = backup_path(target);
    if !bak.is_file() {
        // No last-known-good to restore. Surface it loudly and distinctly; the
        // caller must not report "rolled back" (WR-02).
        tracing::error!(
            "config restore: NO backup present — cannot roll back; live file left as-is"
        );
        return Ok(RestoreOutcome::NoBackup);
    }
    let contents = std::fs::read_to_string(&bak).map_err(|e| {
        tracing::error!(error = %e, "config restore: backup read failed");
        AppError::Internal("config restore failed".to_string())
    })?;
    write_atomic(target, &contents)?;
    Ok(RestoreOutcome::Restored)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_edit::schema::{self, validator_for};
    use serde_json::json;

    /// A doc shaped like the live kratos.yml: serve/identity/selfservice/secrets
    /// present, NO `session` block, NO `dsn`.
    fn no_session_kratos() -> Value {
        json!({
            "serve": {
                "public": { "base_url": "http://kratos:4433/" },
                "admin": { "base_url": "http://kratos:4434/" }
            },
            "identity": {
                "default_schema_id": "default",
                "schemas": [ { "id": "default", "url": "file:///etc/config/kratos/identity.schema.json" } ]
            },
            "selfservice": { "default_browser_return_url": "http://localhost:3000/" },
            "secrets": {
                "cookie": ["PLACEHOLDERcookieSECRET0123456789AB"],
                "cipher": ["PLACEHOLDERcipherSECRET0123456AB"]
            }
        })
    }

    #[test]
    fn load_yaml_to_json_value() {
        let yaml = "a: true\nb: 123\nc: hello\nd:\n  - 1\n  - 2\n";
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t.yml");
        std::fs::write(&p, yaml).unwrap();
        let v = load(&p).expect("load ok");
        assert_eq!(v.pointer("/a"), Some(&json!(true)), "bool typing");
        assert_eq!(v.pointer("/b"), Some(&json!(123)), "number typing");
        assert_eq!(v.pointer("/c"), Some(&json!("hello")), "string typing");
        assert_eq!(v.pointer("/d/0"), Some(&json!(1)));
        // write-back produces parseable YAML.
        let out = serialize(&v).expect("serialize ok");
        let reparsed: Value = serde_yaml_ng::from_str(&out).expect("reparse");
        assert_eq!(reparsed, v);
    }

    #[test]
    fn atomic_write_backup_restore() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("kratos.yml");
        let bak = dir.path().join("kratos.yml.bak");

        // initial write
        write_atomic(&target, "version: 1\n").unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "version: 1\n");

        // The temp file used by the writer lives in the SAME dir as the target:
        // NamedTempFile::new_in(parent) guarantees this. Assert no stray temp
        // leaked into the dir and that persist landed exactly the target file.
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert!(
            entries.iter().any(|n| n == "kratos.yml"),
            "target present after persist"
        );

        // backup captures the PRIOR content, then overwrite.
        backup(&target).unwrap();
        assert!(bak.exists(), ".bak created");
        assert_eq!(std::fs::read_to_string(&bak).unwrap(), "version: 1\n");
        write_atomic(&target, "version: 2\n").unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "version: 2\n");

        // A backup is present, so backup_exists is true (WR-02 invariant the PUT
        // flow asserts before committing a reversible write).
        assert!(backup_exists(&target), "backup present after backup()");

        // restore returns Restored and the file is byte-identical to the backup.
        assert_eq!(restore(&target).unwrap(), RestoreOutcome::Restored);
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            std::fs::read_to_string(&bak).unwrap(),
            "restore is byte-identical to the .bak"
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "version: 1\n");
    }

    #[test]
    fn restore_without_backup_reports_no_backup_distinctly() {
        // WR-02: with NO `.bak`, restore must NOT hard-fail and must NOT claim a
        // rollback — it returns NoBackup and leaves the live file untouched.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("kratos.yml");
        write_atomic(&target, "version: 99\n").unwrap();
        assert!(!backup_exists(&target), "precondition: no .bak");

        let outcome = restore(&target).expect("missing backup is not a hard error");
        assert_eq!(outcome, RestoreOutcome::NoBackup);
        // The live file is unchanged (nothing to restore from).
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "version: 99\n");
    }

    #[test]
    fn round_trip_preserves_unmanaged_key_order() {
        // WR-06: with serde_json `preserve_order`, loading a hand-authored,
        // NON-alphabetical YAML and serializing it back keeps the operator's key
        // ORDER (no alphabetisation on the first save).
        let yaml = "version: v0.13.0\n\
                    serve:\n  \
                      public:\n    \
                        base_url: http://kratos:4433/\n  \
                      admin:\n    \
                        base_url: http://kratos:4434/\n\
                    selfservice:\n  \
                      default_browser_return_url: http://localhost:3000/\n\
                    identity:\n  \
                      default_schema_id: default\n";
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("kratos.yml");
        std::fs::write(&p, yaml).unwrap();

        let doc = load(&p).expect("load ok");
        // Top-level key order as authored (NOT alphabetical — `version` would
        // sort after `selfservice`/`serve`/`identity` under a BTreeMap).
        let top_keys: Vec<&str> = doc
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            top_keys,
            vec!["version", "serve", "selfservice", "identity"],
            "top-level key order must match the authored order, not alphabetical"
        );

        // Serialize back and reparse: the order survives the full round-trip.
        let out = serialize(&doc).expect("serialize ok");
        let reparsed = load_from_str(&out);
        let reparsed_keys: Vec<&str> = reparsed
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            reparsed_keys,
            vec!["version", "serve", "selfservice", "identity"],
            "serialized YAML must preserve the unmanaged key order"
        );
        // Nested order preserved too (public before admin).
        let serve_keys: Vec<&str> = reparsed["serve"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(serve_keys, vec!["public", "admin"], "nested order preserved");
    }

    /// Parse YAML text into a Value via the same path `load` uses (for tests).
    fn load_from_str(text: &str) -> Value {
        serde_yaml_ng::from_str(text).expect("reparse YAML")
    }

    #[test]
    fn merge_preserves_unmanaged() {
        let mut doc = no_session_kratos();
        let secrets_before = doc.pointer("/secrets").cloned();
        let serve_before = doc.pointer("/serve").cloned();
        let identity_before = doc.pointer("/identity").cloned();

        // Apply an allowlisted non-secret patch.
        apply_patch(
            &mut doc,
            &[("/session/lifespan".to_string(), json!("24h"))],
        )
        .unwrap();

        // The patched pointer changed...
        assert_eq!(doc.pointer("/session/lifespan"), Some(&json!("24h")));
        // ...and EVERYTHING unmanaged is byte-identical (value-equal).
        assert_eq!(doc.pointer("/secrets").cloned(), secrets_before);
        assert_eq!(doc.pointer("/serve").cloned(), serve_before);
        assert_eq!(doc.pointer("/identity").cloned(), identity_before);
    }

    #[test]
    fn apply_patch_creates_absent_allowlisted_parent() {
        // One-level absent parent: /session created, /session/lifespan set.
        let mut doc = no_session_kratos();
        assert!(doc.pointer("/session").is_none(), "precondition: no session");
        let secrets_before = doc.pointer("/secrets").cloned();
        let serve_before = doc.pointer("/serve").cloned();

        apply_patch(&mut doc, &[("/session/lifespan".to_string(), json!("24h"))]).unwrap();
        assert_eq!(doc.pointer("/session/lifespan"), Some(&json!("24h")));
        // Only `session` was added; pre-existing keys untouched.
        assert_eq!(doc.pointer("/secrets").cloned(), secrets_before);
        assert_eq!(doc.pointer("/serve").cloned(), serve_before);
        // No sibling/arbitrary node beyond the pointer's own path.
        assert_eq!(
            doc.pointer("/session").unwrap().as_object().unwrap().len(),
            1,
            "session has exactly the one created key"
        );

        // Two-level absent parent: /session/cookie/same_site on a no-session doc.
        let mut doc2 = no_session_kratos();
        apply_patch(
            &mut doc2,
            &[("/session/cookie/same_site".to_string(), json!("Lax"))],
        )
        .unwrap();
        assert_eq!(doc2.pointer("/session/cookie/same_site"), Some(&json!("Lax")));
        assert_eq!(
            doc2.pointer("/session/cookie").unwrap().as_object().unwrap().len(),
            1,
            "cookie has exactly the one created key"
        );
    }

    #[test]
    fn apply_patch_non_object_clobber_is_bad_request() {
        // /identity/default_schema_id is a STRING; descending through it for an
        // object child must BadRequest, never overwrite the scalar.
        let mut doc = no_session_kratos();
        let err = apply_patch(
            &mut doc,
            &[("/identity/default_schema_id/x".to_string(), json!(1))],
        )
        .expect_err("clobbering a scalar must fail");
        assert!(matches!(err, AppError::BadRequest(_)));
        // The scalar is intact.
        assert_eq!(
            doc.pointer("/identity/default_schema_id"),
            Some(&json!("default"))
        );
    }

    #[test]
    fn apply_patch_full_doc_still_validates() {
        // Create the absent session parent + lifespan on the real-shaped Kratos
        // doc (NO dsn). The RAW merged doc must FAIL on the missing required dsn,
        // and the env-overlaid EFFECTIVE doc must validate Ok — proving the overlay
        // is what makes it pass and the merged doc itself has no dsn.
        let v = validator_for("kratos").expect("kratos compiles");
        let mut merged = no_session_kratos();
        apply_patch(&mut merged, &[("/session/lifespan".to_string(), json!("24h"))]).unwrap();

        // raw merged: missing dsn -> fails.
        let raw_err =
            schema::validate_full(v, &merged).expect_err("raw merged (no dsn) must fail");
        assert!(
            raw_err.iter().any(|e| e.message.contains("dsn") || e.path.contains("dsn")),
            "expected missing-dsn error on the raw merged doc; got {raw_err:?}"
        );

        // effective (env-overlaid) merged: validates Ok.
        let effective = schema::effective_for_validation("kratos", &merged);
        assert!(
            schema::validate_full(v, &effective).is_ok(),
            "the env-overlaid effective doc must validate Ok"
        );
        // The merged doc itself still has NO dsn (overlay worked on a clone).
        assert!(merged.pointer("/dsn").is_none(), "merged doc has no dsn");
    }

    #[test]
    fn shipped_kratos_yml_load_overlay_validate_ok() {
        // Regression pin: the REAL shipped config/kratos/kratos.yml loads + overlays
        // + validates Ok — pinning the schema<->config<->env contract. A future edit
        // to the schema, the YAML, or the overlay map that breaks the contract fails
        // here. Path resolved relative to the crate (CARGO_MANIFEST_DIR/../config).
        let shipped = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("config")
            .join("kratos")
            .join("kratos.yml");
        let doc = load(&shipped).expect("shipped kratos.yml loads");
        assert!(doc.pointer("/dsn").is_none(), "shipped kratos.yml has no dsn");

        let v = validator_for("kratos").expect("kratos compiles");
        let effective = schema::effective_for_validation("kratos", &doc);
        assert!(
            schema::validate_full(v, &effective).is_ok(),
            "shipped kratos.yml must validate via the env overlay"
        );

        // Apply the allowlisted patch, write_atomic to a temp-dir copy, reload, and
        // assert the written-back doc has NO dsn (the env key is never written even
        // though it was overlaid for validation — threat T-04-23).
        let mut merged = doc.clone();
        apply_patch(&mut merged, &[("/session/lifespan".to_string(), json!("24h"))]).unwrap();
        // re-validate the patched effective doc to be safe.
        let eff2 = schema::effective_for_validation("kratos", &merged);
        assert!(schema::validate_full(v, &eff2).is_ok(), "patched doc validates");

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("kratos.yml");
        write_atomic(&target, &serialize(&merged).unwrap()).unwrap();
        let written = load(&target).expect("written file reloads");
        assert!(
            written.pointer("/dsn").is_none(),
            "the written-back file must have NO dsn"
        );
        assert_eq!(written.pointer("/session/lifespan"), Some(&json!("24h")));
    }
}
