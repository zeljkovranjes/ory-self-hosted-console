//! Keto permissions data plane (PERM-02 / PERM-03 / PERM-01 OPL validate).
//!
//! Thin, typed pass-throughs to `ory_keto_client` (09-RESEARCH Pattern 2/3): each
//! handler obtains [`OryClients`] from the `Depot`, CLONES it BEFORE any `.await`
//! (never holds a `Depot` borrow across an await — 09-RESEARCH Pitfall 6), calls
//! the typed fn, maps any crate `Error<T>` to [`AppError::Upstream`] (502) via
//! `map_keto_err` (body/URL-free, BACK-07), and serialises the typed model.
//!
//! ## The three-port split (the headline correctness pattern — 09-RESEARCH P1)
//!
//! Keto serves read, write, and OPL-syntax on THREE distinct ports, and the
//! typed crate routes every fn off a single `Configuration.base_path`. So each
//! handler names the EXACT Configuration:
//!
//! - create / delete (relation tuples) → [`OryClients::keto_write`] (`:4467`)
//! - list / check / expand              → [`OryClients::keto_read`]  (`:4466`)
//! - OPL syntax validate                → [`OryClients::keto_opl`]   (`:4469`)
//!
//! Routing a write through the read client (or vice versa) is the headline
//! tampering risk (T-9-port) — the 09-04 live gate asserts a write+read
//! round-trip to prove the ports are wired correctly.
//!
//! ## Security invariants
//!
//! - **T-9-subject-xor (create):** a tuple's subject is EITHER a direct
//!   `subject_id` OR a `subject_set`, never both and never neither. The create
//!   handler rejects both-set / neither-set with `AppError::Validation` (422)
//!   BEFORE calling Keto (09-RESEARCH Pitfall 3).
//! - **T-9-delete-broad (delete):** delete is BY QUERY, not by a single tuple id.
//!   A too-broad filter deletes MANY tuples. The delete handler requires
//!   namespace + object + relation AND exactly one complete subject form to be
//!   present, else 422 — so a row delete removes exactly the named tuple
//!   (09-RESEARCH Pitfall 2).
//! - **T-9-deny-vs-error (check):** uses `check_permission` (200 + `{allowed}`),
//!   NOT the deny-as-error variant (403 on deny). A deny is a NORMAL 200 result;
//!   a 502 from `map_keto_err` surfaces as `AppError::Upstream` and is NEVER
//!   collapsed into "denied".
//! - **T-9-leak:** `map_keto_err` → `AppError::Upstream(502)`, body/URL-free.
//!
//! Mounted on the Phase-2 PROTECTED subtree (behind `auth_guard`): an
//! unauthenticated request is rejected with 401. GET (list/check/expand) is
//! auto-exempt from `csrf_guard`; POST/PUT/DELETE (create/delete/validate)
//! require a matching `X-CSRF-Token` — the frontend `lib/api.ts` echoes it.

use ory_keto_client::apis::{permission_api, relationship_api};
use ory_keto_client::models::{CreateRelationshipBody, SubjectSet};
use salvo::prelude::*;
use serde::Deserialize;

use crate::config_edit::schema::FieldError;
use crate::error::AppError;
use crate::ory::clients::OryClients;
use crate::ory::error::map_keto_err;
use crate::ory::DEFAULT_LIST_PAGE_SIZE;

/// Obtain the injected [`OryClients`], cloned (never hold a `Depot` borrow across
/// the subsequent `.await` — 09-RESEARCH Pitfall 6; mirrors the hydra.rs helper).
fn ory_clients(depot: &mut Depot) -> Result<OryClients, AppError> {
    depot
        .obtain::<OryClients>()
        .map_err(|_| AppError::Internal("ory clients not injected".into()))
        .cloned()
}

/// Serialise a typed Keto model to JSON; a serialise failure is `Internal` (500),
/// never silently coerced.
fn json_of<T: serde::Serialize>(value: T) -> Result<Json<serde_json::Value>, AppError> {
    serde_json::to_value(value)
        .map(Json)
        .map_err(|e| AppError::Internal(format!("serialize ory response: {e}")))
}

/// A single root-level validation error (422) at the given JSON-Pointer `path`.
fn field_err(path: &str, message: &str) -> AppError {
    AppError::Validation(vec![FieldError {
        path: path.to_string(),
        message: message.to_string(),
    }])
}

// =============================================================================
// Subject-set query parameters (shared by list / delete / check)
// =============================================================================

/// The three `subject_set_*` query params Keto's relation/permission APIs accept,
/// read individually so list/check filters can be partial. A complete subject set
/// requires ALL THREE; a complete subject id is the single `subject_id` param.
struct SubjectSetParams {
    namespace: Option<String>,
    object: Option<String>,
    relation: Option<String>,
}

impl SubjectSetParams {
    /// Read the `subject_set_namespace` / `subject_set_object` /
    /// `subject_set_relation` query params, trimming blanks to `None`.
    fn from_query(req: &mut Request) -> Self {
        let q = |req: &mut Request, key: &str| {
            req.query::<String>(key)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        };
        SubjectSetParams {
            namespace: q(req, "subject_set_namespace"),
            object: q(req, "subject_set_object"),
            relation: q(req, "subject_set_relation"),
        }
    }

    /// Whether all three subject-set fields are present (a complete subject set).
    fn is_complete(&self) -> bool {
        self.namespace.is_some() && self.object.is_some() && self.relation.is_some()
    }

    /// Whether any subject-set field is present (a partial or complete set).
    fn is_present(&self) -> bool {
        self.namespace.is_some() || self.object.is_some() || self.relation.is_some()
    }
}

/// Read a trimmed, non-empty query string param (`None` for absent/blank).
fn query_opt(req: &mut Request, key: &str) -> Option<String> {
    req.query::<String>(key)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

// =============================================================================
// PERM-02 / PERM-03: list + query (READ :4466)
// =============================================================================

/// `GET /api/keto/relationships` — list/query relation tuples (PERM-02/03).
///
/// READ path → [`OryClients::keto_read`] (`:4466`). Reads `page_size` (default
/// [`DEFAULT_LIST_PAGE_SIZE`], capped 1000), an opaque `page_token` cursor, and
/// the five server-side filters (namespace / object / relation / subject_id /
/// subject_set_{namespace,object,relation}). Returns the typed `Relationships`
/// JSON verbatim — including `next_page_token` for the frontend cursor map. This
/// REPLACES the Phase-3 first-page proof slice (the TODO(P9) cursor note is now
/// due).
#[handler]
pub async fn list_relationships(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    let clients = ory_clients(depot)?;

    let page_size = req
        .query::<i64>("page_size")
        .filter(|n| *n > 0 && *n <= 1000)
        .unwrap_or(DEFAULT_LIST_PAGE_SIZE);
    let page_token = query_opt(req, "page_token");
    let namespace = query_opt(req, "namespace");
    let object = query_opt(req, "object");
    let relation = query_opt(req, "relation");
    let subject_id = query_opt(req, "subject_id");
    let ss = SubjectSetParams::from_query(req);

    // get_relationships(cfg, page_size, page_token, namespace, object, relation,
    //   subject_id, subject_set_namespace, subject_set_object, subject_set_relation)
    let relationships = relationship_api::get_relationships(
        &clients.keto_read,
        Some(page_size),
        page_token.as_deref(),
        namespace.as_deref(),
        object.as_deref(),
        relation.as_deref(),
        subject_id.as_deref(),
        ss.namespace.as_deref(),
        ss.object.as_deref(),
        ss.relation.as_deref(),
    )
    .await
    .map_err(map_keto_err)?;

    json_of(relationships)
}

// =============================================================================
// PERM-02: create (WRITE :4467)
// =============================================================================

/// JSON body for `POST /api/keto/relationships`: a single tuple. The subject is
/// EITHER `subject_id` OR `subject_set` (mutually exclusive — T-9-subject-xor).
#[derive(Debug, Deserialize)]
struct CreateTupleBody {
    namespace: String,
    object: String,
    relation: String,
    #[serde(default)]
    subject_id: Option<String>,
    #[serde(default)]
    subject_set: Option<SubjectSetBody>,
}

/// A subject-set reference (`namespace:object#relation`) on a create body.
#[derive(Debug, Deserialize)]
struct SubjectSetBody {
    namespace: String,
    object: String,
    relation: String,
}

/// Build the typed [`CreateRelationshipBody`] from the operator body, enforcing
/// the subject XOR (exactly one of `subject_id` / `subject_set`). Pulled out so it
/// is unit-testable without an HTTP request (T-9-subject-xor).
fn build_create_body(body: CreateTupleBody) -> Result<CreateRelationshipBody, AppError> {
    let id = body
        .subject_id
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let set = body.subject_set;

    match (id.is_some(), set.is_some()) {
        (true, true) => {
            return Err(field_err(
                "/subject",
                "provide exactly one of subject_id or subject_set, not both",
            ))
        }
        (false, false) => {
            return Err(field_err(
                "/subject",
                "a subject is required: provide either subject_id or subject_set",
            ))
        }
        _ => {}
    }

    let subject_set = set.map(|s| {
        Box::new(SubjectSet::new(
            s.namespace.trim().to_string(),
            s.object.trim().to_string(),
            s.relation.trim().to_string(),
        ))
    });

    Ok(CreateRelationshipBody {
        namespace: Some(body.namespace.trim().to_string()),
        object: Some(body.object.trim().to_string()),
        relation: Some(body.relation.trim().to_string()),
        subject_id: id,
        subject_set,
    })
}

/// `POST /api/keto/relationships` — create a relation tuple (PERM-02).
///
/// WRITE path → [`OryClients::keto_write`] (`:4467`). Enforces the subject XOR
/// (422 on both/neither) BEFORE calling Keto, then returns the created
/// `Relationship` JSON. CSRF-guarded (POST).
#[handler]
pub async fn create_relationship(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    let body: CreateTupleBody = req
        .parse_json::<CreateTupleBody>()
        .await
        .map_err(|e| AppError::BadRequest(format!("invalid create relationship body: {e}")))?;

    let create_body = build_create_body(body)?;

    let clients = ory_clients(depot)?;
    let created = relationship_api::create_relationship(&clients.keto_write, Some(create_body))
        .await
        .map_err(map_keto_err)?;

    json_of(created)
}

// =============================================================================
// PERM-02: delete (WRITE :4467)
// =============================================================================

/// `DELETE /api/keto/relationships` — delete a relation tuple by exact query
/// (PERM-02).
///
/// WRITE path → [`OryClients::keto_write`] (`:4467`). Delete is BY QUERY, so a
/// too-broad filter would delete MANY tuples (T-9-delete-broad). This handler
/// REQUIRES namespace + object + relation AND exactly one complete subject form
/// (a `subject_id`, OR all three `subject_set_*`) — else 422 with NO Keto call,
/// so a row delete removes exactly the named tuple. CSRF-guarded (DELETE).
#[handler]
pub async fn delete_relationship(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<StatusCode, AppError> {
    let namespace = query_opt(req, "namespace")
        .ok_or_else(|| field_err("/namespace", "namespace is required to delete a tuple"))?;
    let object = query_opt(req, "object")
        .ok_or_else(|| field_err("/object", "object is required to delete a tuple"))?;
    let relation = query_opt(req, "relation")
        .ok_or_else(|| field_err("/relation", "relation is required to delete a tuple"))?;

    let subject_id = query_opt(req, "subject_id");
    let ss = SubjectSetParams::from_query(req);

    // Exactly one complete subject form must be present (avoid an over-broad
    // delete that would match every tuple sharing the n/o/r triple).
    match (subject_id.is_some(), ss.is_present()) {
        (true, true) => {
            return Err(field_err(
                "/subject",
                "provide exactly one of subject_id or subject_set, not both",
            ))
        }
        (false, false) => {
            return Err(field_err(
                "/subject",
                "a complete subject (subject_id, or all three subject_set fields) is required to delete a tuple",
            ))
        }
        (false, true) if !ss.is_complete() => {
            return Err(field_err(
                "/subject_set",
                "a subject_set delete requires all three of subject_set_namespace, subject_set_object, subject_set_relation",
            ))
        }
        _ => {}
    }

    let clients = ory_clients(depot)?;
    relationship_api::delete_relationships(
        &clients.keto_write,
        Some(&namespace),
        Some(&object),
        Some(&relation),
        subject_id.as_deref(),
        ss.namespace.as_deref(),
        ss.object.as_deref(),
        ss.relation.as_deref(),
    )
    .await
    .map_err(map_keto_err)?;

    Ok(StatusCode::NO_CONTENT)
}

// =============================================================================
// PERM-03: check (READ :4466)
// =============================================================================

/// `GET /api/keto/check` — check whether a subject has a permission/relation
/// (PERM-03).
///
/// READ path → [`OryClients::keto_read`] (`:4466`). Requires namespace + object +
/// relation + a subject (id or complete set), plus optional `max_depth`. For an
/// OPL-defined permission, the operator passes the permits-function name as
/// `relation` (the check API is relation-agnostic — 09-RESEARCH Pattern 3).
///
/// Uses `check_permission` (200 + `{allowed}`), NOT the deny-as-error variant
/// (403 on deny). A deny is a normal 200 `{allowed:false}`; an upstream failure
/// maps to `AppError::Upstream` (502) and is NEVER collapsed into "denied"
/// (T-9-deny-vs-error). GET — csrf-exempt, read-only.
#[handler]
pub async fn check_permission(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    let namespace = query_opt(req, "namespace")
        .ok_or_else(|| field_err("/namespace", "namespace is required"))?;
    let object =
        query_opt(req, "object").ok_or_else(|| field_err("/object", "object is required"))?;
    let relation = query_opt(req, "relation")
        .ok_or_else(|| field_err("/relation", "relation is required"))?;

    let subject_id = query_opt(req, "subject_id");
    let ss = SubjectSetParams::from_query(req);

    match (subject_id.is_some(), ss.is_present()) {
        (true, true) => {
            return Err(field_err(
                "/subject",
                "provide exactly one of subject_id or subject_set, not both",
            ))
        }
        (false, false) => {
            return Err(field_err(
                "/subject",
                "a subject is required: provide subject_id or a complete subject_set",
            ))
        }
        (false, true) if !ss.is_complete() => {
            return Err(field_err(
                "/subject_set",
                "a subject_set check requires all three of subject_set_namespace, subject_set_object, subject_set_relation",
            ))
        }
        _ => {}
    }

    let max_depth = req.query::<i64>("max_depth").filter(|n| *n > 0);

    let clients = ory_clients(depot)?;
    let result = permission_api::check_permission(
        &clients.keto_read,
        Some(&namespace),
        Some(&object),
        Some(&relation),
        subject_id.as_deref(),
        ss.namespace.as_deref(),
        ss.object.as_deref(),
        ss.relation.as_deref(),
        max_depth,
    )
    .await
    .map_err(map_keto_err)?;

    json_of(result)
}

// =============================================================================
// PERM-03: expand (READ :4466)
// =============================================================================

/// `GET /api/keto/expand` — expand a relation/permission to its subject tree
/// (PERM-03).
///
/// READ path → [`OryClients::keto_read`] (`:4466`). `namespace` / `object` /
/// `relation` are REQUIRED (the crate takes them as `&str`, not `Option`) — a
/// missing one is 422. Optional `max_depth`. Returns the typed
/// `ExpandedPermissionTree` JSON. GET — csrf-exempt, read-only.
#[handler]
pub async fn expand_permission(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    let namespace = query_opt(req, "namespace")
        .ok_or_else(|| field_err("/namespace", "namespace is required"))?;
    let object =
        query_opt(req, "object").ok_or_else(|| field_err("/object", "object is required"))?;
    let relation = query_opt(req, "relation")
        .ok_or_else(|| field_err("/relation", "relation is required"))?;

    let max_depth = req.query::<i64>("max_depth").filter(|n| *n > 0);

    let clients = ory_clients(depot)?;
    let tree =
        permission_api::expand_permissions(&clients.keto_read, &namespace, &object, &relation, max_depth)
            .await
            .map_err(map_keto_err)?;

    json_of(tree)
}

// =============================================================================
// PERM-01: OPL syntax validate passthrough (OPL :4469)
// =============================================================================

/// JSON body for `POST /api/keto/opl/validate`: the OPL source to syntax-check.
#[derive(Debug, Deserialize)]
struct ValidateOplBody {
    source: String,
}

/// `POST /api/keto/opl/validate` — pre-save OPL syntax validation (PERM-01).
///
/// OPL path → [`OryClients::keto_opl`] (`:4469`) ONLY — Keto's dedicated OPL
/// server, distinct from read/write. Calls `check_opl_syntax` and returns the
/// typed `CheckOplSyntaxResult` JSON (a clean parse => `errors` is null/empty;
/// otherwise each `ParseError` carries `message` + `start`/`end` `SourcePosition`).
///
/// This handler NEVER writes a file — it is read/validate only. The actual
/// model file write (gated on a clean validate) is a separate Phase-4 config-edit
/// route owned by 09-02. CSRF-guarded (POST).
#[handler]
pub async fn validate_opl(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<serde_json::Value>, AppError> {
    let body: ValidateOplBody = req
        .parse_json::<ValidateOplBody>()
        .await
        .map_err(|e| AppError::BadRequest(format!("invalid validate opl body: {e}")))?;

    let clients = ory_clients(depot)?;
    let result = relationship_api::check_opl_syntax(&clients.keto_opl, Some(&body.source))
        .await
        .map_err(map_keto_err)?;

    json_of(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(
        subject_id: Option<&str>,
        subject_set: Option<(&str, &str, &str)>,
    ) -> CreateTupleBody {
        CreateTupleBody {
            namespace: "documents".into(),
            object: "doc:readme".into(),
            relation: "viewer".into(),
            subject_id: subject_id.map(|s| s.to_string()),
            subject_set: subject_set.map(|(n, o, r)| SubjectSetBody {
                namespace: n.into(),
                object: o.into(),
                relation: r.into(),
            }),
        }
    }

    /// T-9-subject-xor: exactly one subject form (a direct id) builds a tuple with
    /// `subject_id` set and `subject_set` unset.
    #[test]
    fn build_create_body_accepts_subject_id_only() {
        let built = build_create_body(body(Some("user:alice"), None)).expect("one subject ok");
        assert_eq!(built.subject_id.as_deref(), Some("user:alice"));
        assert!(built.subject_set.is_none());
        assert_eq!(built.namespace.as_deref(), Some("documents"));
        assert_eq!(built.relation.as_deref(), Some("viewer"));
    }

    /// T-9-subject-xor: exactly one subject form (a subject set) builds a tuple
    /// with `subject_set` set and `subject_id` unset.
    #[test]
    fn build_create_body_accepts_subject_set_only() {
        let built = build_create_body(body(None, Some(("groups", "group:eng", "member"))))
            .expect("one subject ok");
        assert!(built.subject_id.is_none());
        let set = built.subject_set.expect("subject_set present");
        assert_eq!(set.namespace, "groups");
        assert_eq!(set.object, "group:eng");
        assert_eq!(set.relation, "member");
    }

    /// T-9-subject-xor: BOTH subject forms set → 422 Validation, no tuple built.
    #[test]
    fn build_create_body_rejects_both_subjects() {
        let err = build_create_body(body(Some("user:alice"), Some(("groups", "group:eng", "member"))))
            .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "got {err:?}");
        assert_eq!(err.machine_code(), "validation_failed");
    }

    /// T-9-subject-xor: NEITHER subject form set → 422 Validation, no tuple built.
    #[test]
    fn build_create_body_rejects_neither_subject() {
        let err = build_create_body(body(None, None)).unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "got {err:?}");
        assert_eq!(err.machine_code(), "validation_failed");
    }

    /// A blank/whitespace subject_id is treated as absent, so id-only-blank with no
    /// set is the neither-subject case (422) — a blank string never sneaks through
    /// as a valid subject.
    #[test]
    fn build_create_body_treats_blank_subject_id_as_absent() {
        let err = build_create_body(body(Some("   "), None)).unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "got {err:?}");
    }

    /// T-9-leak / error-mapping shape: a Keto upstream `ResponseError` maps to
    /// `AppError::Upstream` (502) whose machine code is `upstream_error` and whose
    /// Display never carries the raw upstream body (BACK-07). Mirrors the hydra.rs
    /// error-mapping discipline against the Keto crate's distinct `Error<T>`.
    #[test]
    fn keto_response_error_maps_to_upstream_without_body_leak() {
        use ory_keto_client::apis::{Error, ResponseContent};
        let secret_body = "SECRET_KETO_UPSTREAM_BODY_should_never_surface";
        let rc: ResponseContent<()> = ResponseContent {
            status: reqwest::StatusCode::NOT_FOUND,
            content: secret_body.to_string(),
            entity: None,
        };
        let err = map_keto_err::<()>(Error::ResponseError(rc));
        assert!(matches!(err, AppError::Upstream(_)), "got {err:?}");
        assert_eq!(err.machine_code(), "upstream_error");
        let detail = err.to_string();
        assert!(
            !detail.contains(secret_body),
            "upstream body leaked into AppError detail: {detail}"
        );
    }
}
