//! Transactional YAML config-edit subsystem (BACK-04 / BACK-06).
//!
//! Every YAML-backed config page in later phases (P7 Kratos auth, P8 Hydra,
//! P9 Keto/Oathkeeper, P10 branding) reuses this engine. The full PUT flow is:
//!
//! 1. acquire the per-service write lock (busy -> 409 `config_busy`)
//! 2. ALLOWLIST-FILTER the incoming patch (out-of-scope/sensitive key -> 403)
//! 3. LOAD the current `/etc/config/<svc>/<file>` YAML into a `serde_json::Value`
//! 4. MERGE the allowlisted changes into the FULL doc (unmanaged keys preserved)
//! 5. VALIDATE the FULL merged doc against the service JSON Schema, PRE-DISK
//!    — validation runs on `effective_for_validation(svc, &merged)`, i.e. the
//!    merged doc UNION the env-injected required keys (e.g. `dsn`) the committed
//!    file omits; the overlay is VALIDATION-ONLY and is never written/returned.
//! 6. BACKUP the last-known-good file
//! 7. ATOMIC WRITE (temp-in-same-dir -> fsync -> rename) of the ORIGINAL `merged`
//!    (NOT the overlaid doc — the overlay never touches disk)
//! 8. RESTART only the affected container via the scoped restart broker
//! 9. HEALTH-POLL the service `/health/ready`
//! 10. on health failure: restore the backup, restart, re-poll, report `failed`
//!
//! This plan (04-01) lays the validation foundation: [`schema`] — the offline
//! schema loader with the `ory://` retriever, `validate_full`, the
//! `ENV_INJECTED_KEYS` map and `effective_for_validation`. The remaining
//! submodules (allowlist / yaml / restart / locks / routes) are added by
//! later plans in this phase.

pub mod allowlist;
pub mod locks;
pub mod schema;
pub mod yaml;
