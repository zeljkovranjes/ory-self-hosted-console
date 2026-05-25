//! Offline JSON-Schema validation for the four Ory service configs.
//!
//! The Ory `kratos`/`hydra`/`keto`/`oathkeeper` `config.schema.json` files are
//! JSON-Schema **draft-07** and `$ref` a custom `ory://` URI scheme
//! (`ory://tracing-config`, `ory://logging-config`, and for Hydra
//! `ory://serve-config`/`ory://cors-config`/`ory://tls-config`). Ory's Go loader
//! registers those URIs programmatically before compiling; a naive
//! `jsonschema::options().build(&schema)` FAILS to resolve them (RESEARCH
//! Pitfall 1 — the single highest-risk finding of this phase).
//!
//! We solve it with a custom [`Retrieve`] ([`OryRefs`]) backed by five
//! sub-schemas vendored (pinned to v26.2.0) under `backend/config/schemas/ory/`
//! and embedded via `include_str!`. The retriever answers ONLY the five known
//! `ory://` URIs and returns `Err` for anything else, so an unresolved ref fails
//! the build instead of passing vacuously.
//!
//! ## Env-injected required keys (the `dsn` problem)
//!
//! The committed `config/<svc>/*.yml` deliberately OMIT `dsn` (and other
//! runtime-overridden secrets) — `dsn` is injected via the `DSN` env var at
//! container runtime and must never be committed (a password in version control).
//! But Kratos's and Keto's schemas mark `dsn` as root-`required`, so validating
//! the committed file alone always fails. [`effective_for_validation`] fixes this
//! by overlaying a schema-satisfying placeholder for exactly those
//! env-injected-and-absent required keys onto a CLONE used ONLY for validation —
//! never written to disk, never returned in a response, never logged.

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

use jsonschema::{Retrieve, Uri, Validator};
use serde_json::Value;

// --- Vendored service schemas (pinned v26.2.0; see config/schemas/SOURCES.md) ---
const KRATOS_CONFIG_SCHEMA: &str =
    include_str!("../../config/schemas/kratos.config.schema.json");
const HYDRA_CONFIG_SCHEMA: &str = include_str!("../../config/schemas/hydra.config.schema.json");
const KETO_CONFIG_SCHEMA: &str = include_str!("../../config/schemas/keto.config.schema.json");
const OATHKEEPER_CONFIG_SCHEMA: &str =
    include_str!("../../config/schemas/oathkeeper.config.schema.json");

// --- Vendored ory:// sub-schemas (resolved offline by OryRefs) ---
const OTELX_SCHEMA: &str = include_str!("../../config/schemas/ory/tracing-config.json");
const LOGRUSX_SCHEMA: &str = include_str!("../../config/schemas/ory/logging-config.json");
const SERVE_SCHEMA: &str = include_str!("../../config/schemas/ory/serve-config.json");
const CORS_SCHEMA: &str = include_str!("../../config/schemas/ory/cors-config.json");
const TLS_SCHEMA: &str = include_str!("../../config/schemas/ory/tls-config.json");

/// A field-level validation error, safe to return to the client as JSON.
///
/// Carries ONLY the instance `path` (an RFC-6901-ish JSON-Pointer to the
/// offending location) and a human-readable `message`. It deliberately NEVER
/// includes the offending VALUE, a file path, or a raw parse error (BACK-07 /
/// threat T-04-03): the schema-derived message is value-free.
#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct FieldError {
    /// JSON-Pointer to the offending field (e.g. `/session/lifespan`). May be
    /// empty (`""`) for a root-level error such as a missing required key.
    pub path: String,
    /// Human-readable, value-free message from the schema validator.
    pub message: String,
}

/// Offline retriever for Ory's custom `ory://` `$ref` scheme.
///
/// Answers EXACTLY the five known `ory://` URIs from the embedded sub-schemas
/// and returns `Err` for any other URI (threat T-04-01: an unresolved ref must
/// fail the build, never pass vacuously). Note the configx serve/cors/tls files
/// carry a NON-`ory://` `$id`; Ory binds the `ory://…` URIs programmatically, so
/// we key on the URI the parent schema `$ref`s, not on each file's own `$id`.
#[derive(Debug, Clone, Copy)]
pub struct OryRefs;

impl Retrieve for OryRefs {
    fn retrieve(
        &self,
        uri: &Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        // Normalise: match the scheme+path of the ory:// URI, tolerant of a
        // trailing slash the referencing layer may append.
        let raw = uri.as_str();
        let key = raw.trim_end_matches('/');
        let embedded = match key {
            "ory://tracing-config" => OTELX_SCHEMA,
            "ory://logging-config" => LOGRUSX_SCHEMA,
            "ory://serve-config" => SERVE_SCHEMA,
            "ory://cors-config" => CORS_SCHEMA,
            "ory://tls-config" => TLS_SCHEMA,
            other => {
                return Err(format!("unresolvable schema reference: {other}").into());
            }
        };
        Ok(serde_json::from_str(embedded)?)
    }
}

/// Raw embedded schema JSON text for a service name, or `None` if unknown.
fn service_schema_str(service: &str) -> Option<&'static str> {
    match service {
        "kratos" => Some(KRATOS_CONFIG_SCHEMA),
        "hydra" => Some(HYDRA_CONFIG_SCHEMA),
        "keto" => Some(KETO_CONFIG_SCHEMA),
        "oathkeeper" => Some(OATHKEEPER_CONFIG_SCHEMA),
        _ => None,
    }
}

/// Validate an OPERATOR-SUPPLIED identity schema (IDENT-03, Pitfall 5 / A3).
///
/// This is DISTINCT from the service-config path ([`validator_for`] /
/// [`validate_full`]): there, the operator JSON is validated AGAINST a fixed Ory
/// service-config schema. Here, the operator JSON IS the schema — Kratos loads it
/// at boot to drive identity traits — so we validate it as a JSON Schema in two
/// layers, refusing anything Kratos would reject (a malformed schema crashes
/// Kratos on restart; the engine health-poll + rollback is only the backstop):
///
/// - **Layer 1 (draft-07 metaschema):** validate `candidate` against the built-in
///   draft-07 metaschema via [`jsonschema::draft7::meta`]. A value that is not a
///   valid JSON Schema (e.g. `{"type": 123}`) yields one [`FieldError`] per
///   violation, using the SAME `instance_path()` -> JSON-Pointer mapping
///   [`validate_full`] uses; messages are schema-derived and value-free (BACK-07 /
///   T-04-03).
/// - **Layer 2 (Kratos structural requirement, A3):** Kratos requires the schema
///   to define `properties.traits` as an object. If `properties` is absent/not an
///   object, or `properties.traits` is absent/not an object, push a single
///   `FieldError` at `/properties/traits`.
/// - **Layer 3 (external-reference rejection, WR-02 / T-04-01 latent SSRF):** an
///   operator-supplied schema is written to `identity.schema.json` and then loaded
///   by Kratos. A `$ref` pointing at `file://`, `http(s)://`, or any other
///   non-same-document URI would make Kratos RESOLVE (dereference) a remote/file
///   reference. We refuse any `$ref` that is not a same-document JSON-Pointer
///   fragment (`#`/`#/…`), pushing a value-free `FieldError` at the offending
///   pointer. This closes the schema-injection surface at the layer that WRITES
///   the file rather than relying on the downstream resolver + health-rollback as
///   the only guard. NOTE: we deliberately restrict `$ref` (the keyword that
///   triggers DEREFERENCING) and NOT `$id`. In draft-07 `$id` is a non-resolving
///   document identifier — the shipped Ory starter schemas and the editor presets
///   legitimately set `$id` to a `https://schemas.ory.sh/…` label that Kratos
///   never fetches. Because every external `$ref` is rejected, an `$id` base-URI
///   cannot be exploited to smuggle a relative ref to an external resource.
///
/// Returns `Ok(())` only when ALL layers pass; otherwise `Err(non-empty Vec)`
/// with every collected violation. No offending value is ever included.
pub fn validate_identity_schema(candidate: &Value) -> Result<(), Vec<FieldError>> {
    let mut errors: Vec<FieldError> = Vec::new();

    // --- Layer 1: the candidate must itself be a valid draft-07 JSON Schema ---
    // `jsonschema::draft7::meta::validator()` returns the built-in draft-07
    // metaschema validator (a `MetaValidator`, which Derefs to `Validator` so it
    // exposes the same `iter_errors` we use in `validate_full`). NOTE: the concrete
    // `MetaValidator` type is NOT publicly nameable in jsonschema 0.46.5 (its
    // module is private), so unlike the per-service `validator_for` cache we cannot
    // hold it in a `OnceLock`; we build it per call instead. Identity-schema PUTs
    // are rare operator actions, so the per-call metaschema build is acceptable.
    let meta = jsonschema::draft7::meta::validator();
    for e in meta.iter_errors(candidate) {
        errors.push(FieldError {
            // The JSON-Pointer instance path (value-free). Unlike `validate_full`,
            // we use `e.masked()` for the message: the default `Display` echoes the
            // offending instance VALUE (e.g. "123 is not valid under ..."), and an
            // operator-supplied schema must produce a value-free message (BACK-07 /
            // T-04-03). `MaskedValidationError`'s Display replaces the value with a
            // "{}" placeholder, keeping the schema-derived reason only.
            path: e.instance_path().to_string(),
            message: e.masked().to_string(),
        });
    }

    // --- Layer 2: Kratos requires properties.traits to be an object (A3) ------
    // Run regardless of Layer-1 outcome so the operator sees the traits
    // requirement even if other metaschema errors are present. The check is a
    // pure structural inspection — no value is read into the message.
    let traits_is_object = candidate
        .get("properties")
        .and_then(Value::as_object)
        .and_then(|props| props.get("traits"))
        .map(Value::is_object)
        .unwrap_or(false);
    if !traits_is_object {
        errors.push(FieldError {
            path: "/properties/traits".to_string(),
            message: "identity schema must define properties.traits as an object".to_string(),
        });
    }

    // --- Layer 3: reject any external/non-local $ref (WR-02) ------------------
    // Walk the whole candidate and refuse a `$ref` whose value is not a
    // same-document JSON-Pointer fragment. This runs regardless of Layers 1/2 so
    // every offending reference is reported in one pass.
    reject_external_refs(candidate, String::new(), &mut errors);

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// True when a `$ref` string is a SAFE same-document reference — i.e. a
/// JSON-Pointer fragment (`#` or `#/…`). Anything else (an absolute URI such as
/// `file://`, `http(s)://`, `urn:`, a bare relative path, or an empty string) is
/// treated as external and rejected (WR-02). The match is intentionally strict:
/// only a leading `#` is allowed.
fn is_local_reference(value: &str) -> bool {
    value == "#" || value.starts_with("#/")
}

/// Recursively walk `node`, pushing a value-free [`FieldError`] for every `$ref`
/// whose VALUE is not a same-document fragment (WR-02). `pointer` is the RFC-6901
/// JSON-Pointer of `node` within the candidate schema, used for the error path so
/// the operator can locate the offending reference. The offending value itself is
/// never placed in the message (BACK-07 / T-04-03).
fn reject_external_refs(node: &Value, pointer: String, errors: &mut Vec<FieldError>) {
    match node {
        Value::Object(map) => {
            if let Some(v) = map.get("$ref") {
                // A `$ref` MUST be a string; a non-string is itself invalid and a
                // non-local string is an external (dereferencing) reference.
                let ok = v.as_str().map(is_local_reference).unwrap_or(false);
                if !ok {
                    errors.push(FieldError {
                        path: format!("{pointer}/$ref"),
                        message:
                            "$ref must be a same-document fragment (\"#\" or \"#/…\"); \
                             external references (file://, http(s)://, …) are not allowed"
                                .to_string(),
                    });
                }
            }
            for (k, child) in map {
                // RFC-6901 escaping for the child token: ~ -> ~0, / -> ~1.
                let escaped = k.replace('~', "~0").replace('/', "~1");
                reject_external_refs(child, format!("{pointer}/{escaped}"), errors);
            }
        }
        Value::Array(items) => {
            for (i, child) in items.iter().enumerate() {
                reject_external_refs(child, format!("{pointer}/{i}"), errors);
            }
        }
        _ => {}
    }
}

/// Per-service compiled-`Validator` cache. The compile (parse + ref resolution)
/// is paid once per service for the process lifetime.
fn validator_cache() -> &'static RwLock<HashMap<&'static str, &'static Validator>> {
    static CACHE: OnceLock<RwLock<HashMap<&'static str, &'static Validator>>> = OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Compile (or fetch the cached) offline [`Validator`] for a service config.
///
/// Resolves all `ory://` refs via [`OryRefs`] WITHOUT any network access. Returns
/// an `Err` string (never a panic) if the service is unknown, the schema text is
/// not valid JSON, or a ref cannot be resolved.
pub fn validator_for(service: &str) -> Result<&'static Validator, String> {
    // Canonicalise the service key to a 'static str so it can live in the cache.
    let key: &'static str = match service {
        "kratos" => "kratos",
        "hydra" => "hydra",
        "keto" => "keto",
        "oathkeeper" => "oathkeeper",
        other => return Err(format!("unknown service: {other}")),
    };

    // IN-01: recover the guard from a poisoned lock instead of panicking. The
    // validator build is pure/deterministic, so a poisoned read view is still
    // sound to use; turning every subsequent validation into a 500 panic would be
    // a worse failure mode than reading through the recovered guard.
    if let Some(v) = validator_cache()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(key)
    {
        return Ok(v);
    }

    let schema_text = service_schema_str(key).ok_or_else(|| format!("unknown service: {key}"))?;
    let schema: Value = serde_json::from_str(schema_text)
        .map_err(|e| format!("vendored {key} schema is not valid JSON: {e}"))?;
    let validator = jsonschema::options()
        .with_retriever(OryRefs)
        .build(&schema)
        .map_err(|e| format!("compiling {key} schema failed: {e}"))?;

    // Leak the compiled validator to obtain a 'static reference. There are
    // exactly four services, compiled at most once each, so the leak is a tiny,
    // bounded, one-time cost (a process-lifetime singleton) — not a growing leak.
    let leaked: &'static Validator = Box::leak(Box::new(validator));
    // IN-01: recover from a poisoned write lock rather than panicking (see the
    // read path above). The insert-after-build ordering is preserved, keeping the
    // Box::leak bound (IN-02) structural.
    validator_cache()
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .insert(key, leaked);
    Ok(leaked)
}

/// Validate a FULL config instance against a compiled service [`Validator`],
/// collecting EVERY violation as a [`FieldError`] (path + message).
///
/// `Ok(())` on a fully valid instance; `Err(non-empty Vec)` otherwise.
///
/// CALL CONVENTION (threat T-04-22): callers validate
/// `effective_for_validation(svc, &merged)` — the merged doc UNION the
/// env-injected required keys — but PERSIST/RETURN the original `merged`. The
/// overlay exists ONLY for validation; it must never reach disk or a response.
pub fn validate_full(validator: &Validator, instance: &Value) -> Result<(), Vec<FieldError>> {
    let errors: Vec<FieldError> = validator
        .iter_errors(instance)
        .map(|e| FieldError {
            // `instance_path()` is the JSON-Pointer location of the offending
            // field; safe to return. The Display message is schema-derived and
            // value-free — we deliberately do NOT echo the offending value.
            // (jsonschema 0.46.5: the iterator item exposes it as a method.)
            path: e.instance_path().to_string(),
            message: e.to_string(),
        })
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Per-service map of env-injected, schema-required, committed-file-ABSENT keys,
/// as RFC-6901 JSON-Pointers.
///
/// Derivation rule: a pointer belongs here iff it is (a) root-`required` in that
/// service's vendored schema AND (b) absent from the committed `config/<svc>/*.yml`
/// because the value is injected via env at container runtime (verified against
/// `docker-compose.yml` + the committed YAML).
///
/// - **kratos** → `["/dsn"]` — `dsn` is root-required (`["identity","dsn",
///   "selfservice"]`) and the committed `kratos.yml` omits it (DSN env injected).
/// - **hydra** → `[]` — Hydra's schema root `required` is `[]`, so `dsn` is
///   schema-OPTIONAL; no overlay is needed (and `secrets.system` already ships
///   as a placeholder in `hydra.yml`, so it is NOT overlaid either). Listed
///   explicitly as empty to make the derivation visible.
/// - **keto** → `["/dsn"]` — `dsn` is root-required and `keto.yml` omits it.
/// - **oathkeeper** → `[]` — stateless, no DSN; root `required` is `[]`.
///
/// If a service schema later requires an additional env-injected-and-absent key,
/// add its pointer here. NEVER list a key the committed file already contains.
pub const ENV_INJECTED_KEYS: &[(&str, &[&str])] = &[
    ("kratos", &["/dsn"]),
    ("hydra", &[]),
    ("keto", &["/dsn"]),
    ("oathkeeper", &[]),
];

/// The env-injected required-key pointers for `service` (empty slice if none).
fn env_injected_keys_for(service: &str) -> &'static [&'static str] {
    ENV_INJECTED_KEYS
        .iter()
        .find(|(svc, _)| *svc == service)
        .map(|(_, ptrs)| *ptrs)
        .unwrap_or(&[])
}

/// A schema-satisfying placeholder value for an env-injected required key.
///
/// All overlaid keys are currently DSN-shaped (`/dsn`, schema type `string`).
/// Prefer the REAL `DSN` env value if the backend process has it (so the overlay
/// matches the value the service will actually run with), else a constant
/// placeholder whose shape satisfies the schema's `string` type. The value is
/// used ONLY inside the validation clone — it is never persisted or returned.
fn placeholder_for(pointer: &str) -> Value {
    match pointer {
        "/dsn" => std::env::var("DSN")
            .ok()
            .filter(|s| !s.is_empty())
            .map(Value::String)
            .unwrap_or_else(|| Value::String("postgres://placeholder".to_string())),
        // Future env-injected keys: add a schema-satisfying placeholder here.
        _ => Value::String("placeholder".to_string()),
    }
}

/// Build the EFFECTIVE document used for validation: a CLONE of `doc` with each
/// env-injected required key (per [`ENV_INJECTED_KEYS`]) that is ABSENT filled
/// with a schema-satisfying placeholder.
///
/// VALIDATION-ONLY INVARIANT (threat T-04-22): the returned value is a SEPARATE
/// clone used solely by [`validate_full`]. The caller still WRITES and RETURNS
/// the original `doc`; the env-injected overlay value (the real DSN or the
/// placeholder) is NEVER persisted to disk, NEVER serialized into a response
/// body, and NEVER logged. The input `doc` is left unmodified.
///
/// The overlay only FILLS absent keys — a key already present in `doc` (e.g. a
/// `dsn` the caller did supply) is left intact. For services with an empty
/// overlay map (hydra/oathkeeper) this is an exact clone (a no-op overlay).
pub fn effective_for_validation(service: &str, doc: &Value) -> Value {
    let mut effective = doc.clone();
    for pointer in env_injected_keys_for(service) {
        // Only fill keys that are ABSENT; never clobber a present value.
        if effective.pointer(pointer).is_none() {
            set_pointer(&mut effective, pointer, placeholder_for(pointer));
        }
    }
    effective
}

/// Set a value at an RFC-6901 JSON-Pointer, creating intermediate objects as
/// needed. Used only by [`effective_for_validation`] for the (currently
/// shallow, e.g. `/dsn`) env-injected keys. A no-op on an empty pointer.
fn set_pointer(root: &mut Value, pointer: &str, value: Value) {
    if pointer.is_empty() {
        return;
    }
    // RFC-6901: split on '/', unescape ~1 -> '/' and ~0 -> '~'.
    let tokens: Vec<String> = pointer
        .split('/')
        .skip(1) // leading "" before the first '/'
        .map(|t| t.replace("~1", "/").replace("~0", "~"))
        .collect();
    let mut cur = root;
    for (i, token) in tokens.iter().enumerate() {
        let last = i + 1 == tokens.len();
        if last {
            if let Value::Object(map) = cur {
                map.insert(token.clone(), value);
            } else {
                // WR-03: the final-token parent is not an object, so the overlay
                // value cannot be inserted. For the current single-level keys (e.g.
                // `/dsn` onto the always-object root) this is unreachable, but a
                // future multi-segment env-injected key whose parent slot is a
                // scalar would otherwise be DROPPED silently — producing a spurious
                // 422 or validating a doc that differs from the operator's intent.
                // Emit an error-level trace (value-free) so the no-op is observable.
                tracing::error!(
                    pointer = %pointer,
                    "config validation overlay: parent at final token is not an object; \
                     env-injected key was not applied"
                );
            }
            return;
        }
        // Descend, creating an object if the slot is absent or not an object.
        if !cur.is_object() {
            *cur = Value::Object(serde_json::Map::new());
        }
        let map = cur.as_object_mut().expect("ensured object above");
        cur = map
            .entry(token.clone())
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A minimal instance shaped like the committed kratos.yml (NO `dsn`),
    /// carrying the other root-required keys so the ONLY failure is the missing
    /// `dsn`. `selfservice` is an object (schema requires its presence).
    fn committed_like_kratos() -> Value {
        json!({
            "identity": {
                "default_schema_id": "default",
                "schemas": [ { "id": "default", "url": "file:///etc/config/kratos/identity.schema.json" } ]
            },
            "selfservice": {
                "default_browser_return_url": "http://localhost:3000/"
            }
        })
    }

    fn committed_like_keto() -> Value {
        json!({
            "namespaces": { "location": "file:///etc/config/keto/namespaces.ts" }
        })
    }

    #[test]
    fn compiles_all_service_schemas_offline() {
        for svc in ["kratos", "hydra", "keto", "oathkeeper"] {
            let v = validator_for(svc);
            assert!(
                v.is_ok(),
                "service {svc} schema must compile offline via OryRefs, got: {:?}",
                v.err()
            );
        }
    }

    #[test]
    fn hydra_strict_case_resolves_serve_cors_tls_tracing() {
        // Hydra is the strict case: it exercises serve/cors/tls + tracing refs.
        // If any ory:// ref fails to resolve, build() errors here.
        assert!(
            validator_for("hydra").is_ok(),
            "hydra must resolve serve/cors/tls/tracing ory:// refs offline"
        );
    }

    #[test]
    fn retriever_errors_on_unknown_ory_uri() {
        // A bare schema whose $ref points at an UNKNOWN ory:// URI must fail to
        // compile (Pitfall 1 warning sign) — never pass vacuously.
        let bad = json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": { "x": { "$ref": "ory://does-not-exist" } }
        });
        let built = jsonschema::options().with_retriever(OryRefs).build(&bad);
        assert!(
            built.is_err(),
            "an unresolvable ory:// ref must surface as a build error"
        );
    }

    #[test]
    fn rejects_invalid_with_field_paths() {
        let v = validator_for("kratos").expect("kratos compiles");
        // `dsn` must be a string; an integer is a type error with a path.
        let mut instance = committed_like_kratos();
        instance["dsn"] = json!(12345);
        let errs = validate_full(v, &instance).expect_err("type-invalid dsn must fail");
        assert!(!errs.is_empty(), "expected at least one field error");
        assert!(
            errs.iter().any(|e| !e.path.is_empty()),
            "at least one error must carry a non-empty instance path; got {errs:?}"
        );
    }

    #[test]
    fn minimal_valid_instance_yields_empty_vec() {
        let v = validator_for("kratos").expect("kratos compiles");
        // committed-like doc WITH a valid dsn -> all root-required satisfied.
        let mut instance = committed_like_kratos();
        instance["dsn"] = json!("postgres://u:p@db:5432/k");
        assert!(
            validate_full(v, &instance).is_ok(),
            "a minimal valid kratos instance must validate clean"
        );
    }

    #[test]
    fn dsn_required_but_absent_fails_without_overlay() {
        // PIN that dsn really is schema-required for kratos: the raw committed-
        // like doc (NO dsn, NO overlay) must fail with a dsn-related error.
        let v = validator_for("kratos").expect("kratos compiles");
        let raw = committed_like_kratos();
        let errs = validate_full(v, &raw).expect_err("raw committed kratos must fail (no dsn)");
        assert!(
            errs.iter().any(|e| e.message.contains("dsn") || e.path.contains("dsn")),
            "expected a missing-required-`dsn` error; got {errs:?}"
        );
    }

    #[test]
    fn effective_for_validation_overlays_dsn_then_passes() {
        // kratos: overlay fills /dsn -> validates; input doc unmodified.
        let kv = validator_for("kratos").expect("kratos compiles");
        let input = committed_like_kratos();
        let effective = effective_for_validation("kratos", &input);
        assert!(
            effective.pointer("/dsn").is_some(),
            "effective doc must contain the overlaid /dsn"
        );
        assert!(
            validate_full(kv, &effective).is_ok(),
            "kratos must validate after the /dsn overlay"
        );
        // The caller's original doc is UNMODIFIED (overlay works on a clone).
        assert!(
            input.pointer("/dsn").is_none(),
            "the input doc must still have NO /dsn after overlay"
        );

        // keto: same — overlay fills /dsn and validates.
        let kev = validator_for("keto").expect("keto compiles");
        let keto_in = committed_like_keto();
        let keto_eff = effective_for_validation("keto", &keto_in);
        assert!(keto_eff.pointer("/dsn").is_some(), "keto /dsn overlaid");
        assert!(
            validate_full(kev, &keto_eff).is_ok(),
            "keto must validate after the /dsn overlay"
        );

        // oathkeeper: empty overlay map -> exact no-op clone.
        let ok_in = json!({});
        let ok_eff = effective_for_validation("oathkeeper", &ok_in);
        assert_eq!(ok_eff, ok_in, "oathkeeper overlay must be a no-op");
    }

    // --- IDENT-03: identity-schema metaschema + properties.traits (Pitfall 5/A3) ---

    /// The SHIPPED active identity schema text, embedded so the unit test pins the
    /// real `config/kratos/identity.schema.json` against the validator (a future
    /// edit that breaks draft-07 validity or drops properties.traits fails here).
    const SHIPPED_IDENTITY_SCHEMA: &str =
        include_str!("../../../config/kratos/identity.schema.json");

    /// A minimal, draft-07-valid identity schema WITH a properties.traits object.
    fn valid_identity_schema() -> Value {
        json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": {
                "traits": {
                    "type": "object",
                    "properties": { "email": { "type": "string", "format": "email" } },
                    "required": ["email"],
                    "additionalProperties": false
                }
            }
        })
    }

    #[test]
    fn shipped_identity_schema_validates_ok() {
        // Pin the shipped active schema: it must be a valid draft-07 schema AND
        // carry properties.traits as an object.
        let shipped: Value =
            serde_json::from_str(SHIPPED_IDENTITY_SCHEMA).expect("shipped schema is JSON");
        assert!(
            validate_identity_schema(&shipped).is_ok(),
            "the shipped config/kratos/identity.schema.json must validate"
        );
    }

    #[test]
    fn minimal_valid_identity_schema_ok() {
        assert!(
            validate_identity_schema(&valid_identity_schema()).is_ok(),
            "a draft-07-valid schema with properties.traits must validate"
        );
    }

    #[test]
    fn layer1_rejects_non_schema_value() {
        // `{"type": 123}` is NOT a valid JSON Schema (`type` must be a string or an
        // array of strings) — Layer 1 (metaschema) must reject it.
        let bad = json!({ "type": 123, "properties": { "traits": { "type": "object" } } });
        let errs = validate_identity_schema(&bad).expect_err("non-schema must be rejected");
        assert!(!errs.is_empty(), "expected at least one metaschema field error");
        // Value-free: the offending value (123) must not appear in any message.
        for e in &errs {
            assert!(
                !e.message.contains("123"),
                "metaschema message must not echo the offending value: {}",
                e.message
            );
        }
    }

    #[test]
    fn layer2_rejects_missing_properties_traits() {
        // A draft-07-VALID schema that omits properties.traits must be rejected by
        // Layer 2 at the /properties/traits pointer (Kratos requires it, A3).
        let no_traits = json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": { "not_traits": { "type": "string" } }
        });
        let errs =
            validate_identity_schema(&no_traits).expect_err("missing properties.traits rejected");
        assert!(
            errs.iter().any(|e| e.path == "/properties/traits"),
            "expected a /properties/traits field error; got {errs:?}"
        );
    }

    #[test]
    fn layer2_rejects_traits_not_an_object() {
        // properties.traits present but NOT an object (a string) -> Layer 2 rejects.
        let traits_string = json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": { "traits": "not-an-object" }
        });
        let errs = validate_identity_schema(&traits_string)
            .expect_err("non-object traits must be rejected");
        assert!(
            errs.iter().any(|e| e.path == "/properties/traits"),
            "expected a /properties/traits field error; got {errs:?}"
        );
    }

    #[test]
    fn no_properties_object_is_rejected() {
        // `properties` absent entirely -> the Layer-2 traits check fails too.
        let no_props = json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object"
        });
        let errs = validate_identity_schema(&no_props).expect_err("no properties -> rejected");
        assert!(
            errs.iter().any(|e| e.path == "/properties/traits"),
            "missing properties must surface the traits requirement; got {errs:?}"
        );
    }

    // --- WR-02: external $ref rejection (latent SSRF / schema injection) ------

    #[test]
    fn layer3_rejects_http_ref() {
        // A draft-07-VALID schema (with properties.traits) carrying an http(s)
        // $ref must be rejected: Kratos would dereference it on load.
        let bad = json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": {
                "traits": {
                    "type": "object",
                    "properties": { "x": { "$ref": "http://attacker.example/x" } }
                }
            }
        });
        let errs = validate_identity_schema(&bad).expect_err("http $ref must be rejected");
        assert!(
            errs.iter().any(|e| e.path.ends_with("/$ref")),
            "expected a $ref field error; got {errs:?}"
        );
        // Value-free: the offending URL must not appear in any message (BACK-07).
        for e in &errs {
            assert!(
                !e.message.contains("attacker.example"),
                "message must not echo the offending ref value: {}",
                e.message
            );
        }
    }

    #[test]
    fn layer3_rejects_file_ref() {
        // A `file://` $ref (local file disclosure) must be rejected.
        let bad = json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": {
                "traits": { "type": "object", "$ref": "file:///etc/passwd" }
            }
        });
        let errs = validate_identity_schema(&bad).expect_err("file:// $ref must be rejected");
        assert!(
            errs.iter().any(|e| e.path.ends_with("/$ref")),
            "expected a $ref field error; got {errs:?}"
        );
    }

    #[test]
    fn layer3_allows_local_fragment_ref() {
        // A same-document JSON-Pointer fragment $ref is allowed (self-contained).
        let ok = json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "definitions": { "Email": { "type": "string", "format": "email" } },
            "properties": {
                "traits": {
                    "type": "object",
                    "properties": { "email": { "$ref": "#/definitions/Email" } },
                    "required": ["email"]
                }
            }
        });
        assert!(
            validate_identity_schema(&ok).is_ok(),
            "a self-contained #/… fragment $ref must validate"
        );
    }

    #[test]
    fn layer3_allows_https_id_label() {
        // `$id` is a non-resolving document identifier in draft-07; the shipped
        // Ory starter schema + presets legitimately set a `https://schemas.ory.sh`
        // $id. It must NOT be rejected (only $ref dereferences).
        let ok = json!({
            "$id": "https://schemas.ory.sh/presets/identity.schema.json",
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": {
                "traits": {
                    "type": "object",
                    "properties": { "email": { "type": "string" } },
                    "required": ["email"]
                }
            }
        });
        assert!(
            validate_identity_schema(&ok).is_ok(),
            "a non-resolving https $id label must be allowed (shipped-schema parity)"
        );
    }

    #[test]
    fn overlay_does_not_clobber_present_keys() {
        // hydra: empty overlay map -> never touches the present secrets.system.
        let hydra_doc = json!({
            "secrets": { "system": ["PLACEHOLDER_SYSTEM_SECRET_VALUE_32CHARS"] }
        });
        let hydra_eff = effective_for_validation("hydra", &hydra_doc);
        assert_eq!(
            hydra_eff.pointer("/secrets/system"),
            hydra_doc.pointer("/secrets/system"),
            "hydra overlay must not touch the present secrets.system"
        );
        // hydra overlay map is empty -> no /dsn added.
        assert!(
            hydra_eff.pointer("/dsn").is_none(),
            "hydra (empty overlay) must NOT add /dsn"
        );

        // A doc that ALREADY has a dsn: overlay leaves the existing value intact.
        let mut have_dsn = committed_like_kratos();
        have_dsn["dsn"] = json!("postgres://real:real@db:5432/k");
        let eff = effective_for_validation("kratos", &have_dsn);
        assert_eq!(
            eff.pointer("/dsn"),
            Some(&json!("postgres://real:real@db:5432/k")),
            "overlay must keep an already-present /dsn intact"
        );
    }
}
