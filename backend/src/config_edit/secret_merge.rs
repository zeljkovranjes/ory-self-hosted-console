//! Array secret merge-by-id + per-item secret masking (07-RESEARCH Pattern 2 /
//! Pitfall 3 — the secret-clobber guard).
//!
//! Several Kratos config sections are WHOLE-ARRAY-REPLACE arrays of objects whose
//! items carry per-item secrets (07-RESEARCH):
//!   - OIDC providers (`/selfservice/methods/oidc/config/providers`) — each item's
//!     `client_secret` and `apple_private_key`;
//!   - courier SMS channels (`/courier/channels`) — each item's
//!     `request_config.auth.config.{password,value}`;
//!   - flow web_hooks (each `…/hooks` array) — each item's
//!     `config.auth.config.{password,value}`.
//!
//! Because the console edits the WHOLE array at the array-root pointer (Pattern 1 /
//! Pitfall 4 — never a per-index pointer), a naive PUT would round-trip whatever
//! the GET returned. If the GET returned the real secret, the operator's browser
//! would see and re-PUT it (leak); if the GET masked it, a naive PUT would write
//! the MASK over the real stored secret (clobber, Pitfall 3). This module solves
//! both:
//!
//!   - [`mask_array_secrets`] (GET path): replace every per-item secret field with
//!     the [`MASKED`] sentinel so the real value never leaves the backend.
//!   - [`merge_array_by_id`] (PUT path): for each incoming item, where a secret
//!     field is the [`MASKED`] sentinel (or absent) AND the stored item with the
//!     same `id` carries a real value, copy the stored value back in (preserve);
//!     a freshly-typed secret OVERWRITES; a new id keeps incoming verbatim; an id
//!     present only in `stored` is DROPPED (removal). Stable order = incoming.
//!
//! ## AUTHORITATIVE CROSS-PLAN CONTRACT — the masked-secret sentinel
//!
//! [`MASKED`] is the ONE literal the backend emits on GET in place of any stored
//! secret AND the ONE literal it detects on PUT to mean "preserve the stored
//! value". It is exported from THIS module and reused by the SMTP write-only
//! handler, the array GET-mask/PUT-merge wiring, the integration tests, the
//! frontend (which echoes back EXACTLY what GET returned — it must NOT hardcode
//! its own constant), and the Plan-05 live gate (which derives the expected
//! literal from a GET, not a guess). If this literal ever changes, it changes
//! HERE ONLY; every consumer reads it from a GET response rather than re-declaring
//! it. A frontend/backend mismatch would silently clobber secrets (Pitfall 3)
//! while unit tests still pass — that is why the contract is pinned to this single
//! definition and the FE/gate echo it verbatim.

use serde_json::Value;

/// The single masked-secret sentinel (AUTHORITATIVE CROSS-PLAN CONTRACT — pin this
/// exact literal). Emitted on GET for any stored secret; detected on PUT to mean
/// "preserve the existing stored value".
pub const MASKED: &str = "__ory_console_masked__";

/// Per-section descriptor: the item `id` field and the dot-notation paths of the
/// per-item secret fields within an item. Dot paths address NESTED object fields
/// (e.g. `request_config.auth.config.password`); a missing intermediate object is
/// treated gracefully (no panic, nothing masked/merged for that field).
#[derive(Debug, Clone, Copy)]
pub struct ArraySecretSpec {
    /// The field that uniquely identifies an item across stored/incoming arrays
    /// (e.g. `id` for OIDC providers / courier channels). Items are matched by the
    /// STRING form of this field's value.
    pub id_field: &'static str,
    /// Dot-notation paths to the per-item secret fields (e.g.
    /// `["client_secret", "apple_private_key"]` or
    /// `["request_config.auth.config.password"]`).
    pub secret_fields: &'static [&'static str],
}

/// OIDC provider item: `id` keyed; `client_secret` + `apple_private_key` secret.
pub const OIDC_SPEC: ArraySecretSpec = ArraySecretSpec {
    id_field: "id",
    secret_fields: &["client_secret", "apple_private_key"],
};

/// Courier SMS channel item: `id` keyed; HTTP auth password/value secret.
pub const SMS_SPEC: ArraySecretSpec = ArraySecretSpec {
    id_field: "id",
    secret_fields: &[
        "request_config.auth.config.password",
        "request_config.auth.config.value",
    ],
};

/// Flow web_hook item: keyed by the destination `config.url` (web_hooks have no
/// `id`); `config.auth.config.{password,value}` secret. The id_field is a
/// DOT-PATH (`config.url`), resolved the same way as the secret fields.
pub const WEBHOOK_SPEC: ArraySecretSpec = ArraySecretSpec {
    id_field: "config.url",
    secret_fields: &["config.auth.config.password", "config.auth.config.value"],
};

/// Read the STRING form of the `id_field` (a dot-path) from an item, if present
/// and scalar. Returns `None` for an absent/object/array id.
fn item_id(item: &Value, id_field: &str) -> Option<String> {
    match get_dot(item, id_field) {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Number(n)) => Some(n.to_string()),
        Some(Value::Bool(b)) => Some(b.to_string()),
        _ => None,
    }
}

/// Walk a dot-notation path to an existing scalar/leaf node (immutable). Returns
/// `None` if any intermediate is missing or not an object (graceful).
fn get_dot<'a>(item: &'a Value, dot_path: &str) -> Option<&'a Value> {
    let mut cur = item;
    for seg in dot_path.split('.') {
        cur = cur.as_object()?.get(seg)?;
    }
    Some(cur)
}

/// Set a dot-notation path to `value`, CREATING intermediate objects as needed.
/// If an intermediate exists but is NOT an object, the set is a graceful no-op
/// (we never coerce/clobber a non-object node — mirrors the engine's
/// apply_patch non-object guard).
fn set_dot(item: &mut Value, dot_path: &str, value: Value) {
    let segs: Vec<&str> = dot_path.split('.').collect();
    let mut cur = item;
    for (i, seg) in segs.iter().enumerate() {
        let last = i + 1 == segs.len();
        let Value::Object(map) = cur else {
            return; // non-object intermediate: graceful no-op
        };
        if last {
            map.insert((*seg).to_string(), value);
            return;
        }
        cur = map
            .entry((*seg).to_string())
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
    }
}

/// True iff the dot-path field on the item is PRESENT and equal to the [`MASKED`]
/// sentinel string. A masked OR absent secret on an incoming item is the
/// "preserve" signal in [`merge_array_by_id`].
fn is_masked(item: &Value, dot_path: &str) -> bool {
    matches!(get_dot(item, dot_path), Some(Value::String(s)) if s == MASKED)
}

/// GET path: return `items` with every per-item secret field (present, scalar)
/// replaced by the [`MASKED`] sentinel. Never returns a real secret value; never
/// panics on a missing/typed path (a missing secret field is simply left absent).
pub fn mask_array_secrets(items: &[Value], spec: &ArraySecretSpec) -> Vec<Value> {
    items
        .iter()
        .map(|item| {
            let mut masked = item.clone();
            for field in spec.secret_fields {
                // Only mask a field that is actually PRESENT (don't invent keys).
                if get_dot(&masked, field).is_some() {
                    set_dot(&mut masked, field, Value::String(MASKED.to_string()));
                }
            }
            masked
        })
        .collect()
}

/// PUT path: merge `incoming` against `stored` by `id`, preserving any per-item
/// secret the operator left masked/absent.
///
/// For each `incoming` item (in incoming order — the result preserves it):
///   - if the same-id item exists in `stored`, then for each secret field where
///     the incoming value is the [`MASKED`] sentinel OR absent, copy the stored
///     value back in (preserve); a freshly-typed (non-sentinel) secret is KEPT
///     (overwrite);
///   - if no same-id stored item exists, the incoming item is kept verbatim (a
///     brand-new provider with a real secret).
///
/// An id present ONLY in `stored` is DROPPED (the operator removed it).
///
/// An incoming item with NO resolvable id is kept verbatim (it cannot match a
/// stored item; treated as new).
pub fn merge_array_by_id(stored: &[Value], incoming: &[Value], spec: &ArraySecretSpec) -> Vec<Value> {
    incoming
        .iter()
        .map(|inc| {
            let mut merged = inc.clone();
            let Some(id) = item_id(inc, spec.id_field) else {
                return merged; // no id -> treat as new, keep verbatim
            };
            // Find the stored item with the same id.
            let stored_item = stored
                .iter()
                .find(|s| item_id(s, spec.id_field).as_deref() == Some(id.as_str()));
            let Some(stored_item) = stored_item else {
                return merged; // new id -> keep incoming verbatim (incl. real secret)
            };
            for field in spec.secret_fields {
                // Preserve the stored secret iff the incoming value is masked or
                // absent AND the stored item has a real (present) value.
                let incoming_missing = get_dot(inc, field).is_none();
                if is_masked(inc, field) || incoming_missing {
                    if let Some(stored_secret) = get_dot(stored_item, field) {
                        set_dot(&mut merged, field, stored_secret.clone());
                    }
                }
            }
            merged
        })
        .collect()
}

/// Convenience guard: assert a serialized array carries NO real secret value (only
/// the sentinel or absence). Used by callers/tests to defend the leak invariant.
pub fn contains_no_unmasked_secret(items: &[Value], spec: &ArraySecretSpec) -> bool {
    items.iter().all(|item| {
        spec.secret_fields.iter().all(|field| {
            match get_dot(item, field) {
                Some(Value::String(s)) => s == MASKED,
                Some(_) => false, // a non-string secret leaf is an unmasked value
                None => true,     // absent is fine
            }
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn oidc(id: &str, client_secret: Option<&str>) -> Value {
        let mut v = json!({
            "id": id,
            "provider": "generic",
            "client_id": format!("client-{id}"),
            "mapper_url": "base64://Zm9v"
        });
        if let Some(s) = client_secret {
            v["client_secret"] = json!(s);
        }
        v
    }

    #[test]
    fn mask_replaces_oidc_secrets_keeps_non_secret() {
        let items = vec![json!({
            "id": "google",
            "client_id": "public-client-id",
            "client_secret": "REAL-google-secret",
            "apple_private_key": "REAL-apple-key",
            "mapper_url": "base64://Zm9v"
        })];
        let masked = mask_array_secrets(&items, &OIDC_SPEC);
        let item = &masked[0];
        // Secrets masked...
        assert_eq!(item["client_secret"], json!(MASKED));
        assert_eq!(item["apple_private_key"], json!(MASKED));
        // ...non-secret fields untouched.
        assert_eq!(item["client_id"], json!("public-client-id"));
        assert_eq!(item["mapper_url"], json!("base64://Zm9v"));
        // No real secret value survives anywhere in the output.
        let s = serde_json::to_string(&masked).unwrap();
        assert!(!s.contains("REAL-google-secret"), "client_secret leaked: {s}");
        assert!(!s.contains("REAL-apple-key"), "apple_private_key leaked: {s}");
        assert!(contains_no_unmasked_secret(&masked, &OIDC_SPEC));
    }

    #[test]
    fn mask_handles_absent_secret_gracefully() {
        // A provider with no client_secret/apple_private_key present -> masking is
        // a no-op for those fields (no invented keys, no panic).
        let items = vec![oidc("github", None)];
        let masked = mask_array_secrets(&items, &OIDC_SPEC);
        assert!(masked[0].get("client_secret").is_none(), "absent secret stays absent");
        assert!(masked[0].get("apple_private_key").is_none());
        assert_eq!(masked[0]["client_id"], json!("client-github"));
    }

    #[test]
    fn merge_preserves_stored_secret_when_incoming_is_masked() {
        // Operator edited the label but left client_secret masked -> the stored
        // real secret is preserved (Pitfall 3 — never clobbered with the mask).
        let stored = vec![oidc("google", Some("REAL-google-secret"))];
        let mut incoming_item = oidc("google", Some(MASKED));
        incoming_item["client_id"] = json!("edited-client-id"); // a non-secret edit
        let incoming = vec![incoming_item];

        let merged = merge_array_by_id(&stored, &incoming, &OIDC_SPEC);
        assert_eq!(
            merged[0]["client_secret"],
            json!("REAL-google-secret"),
            "a masked incoming secret must inherit the stored real value"
        );
        // The non-secret edit is kept.
        assert_eq!(merged[0]["client_id"], json!("edited-client-id"));
    }

    #[test]
    fn merge_preserves_stored_secret_when_incoming_absent() {
        // The incoming item omits client_secret entirely -> still preserve stored.
        let stored = vec![oidc("google", Some("REAL-google-secret"))];
        let incoming = vec![oidc("google", None)];
        let merged = merge_array_by_id(&stored, &incoming, &OIDC_SPEC);
        assert_eq!(merged[0]["client_secret"], json!("REAL-google-secret"));
    }

    #[test]
    fn merge_overwrites_when_incoming_has_real_secret() {
        // The operator retyped the secret -> it replaces the stored value.
        let stored = vec![oidc("google", Some("OLD-secret"))];
        let incoming = vec![oidc("google", Some("NEW-typed-secret"))];
        let merged = merge_array_by_id(&stored, &incoming, &OIDC_SPEC);
        assert_eq!(merged[0]["client_secret"], json!("NEW-typed-secret"));
    }

    #[test]
    fn merge_keeps_new_provider_with_real_secret() {
        // A brand-new id has no stored match -> kept verbatim, real secret intact.
        let stored = vec![oidc("google", Some("REAL-google-secret"))];
        let incoming = vec![
            oidc("google", Some(MASKED)),
            oidc("github", Some("brand-new-github-secret")),
        ];
        let merged = merge_array_by_id(&stored, &incoming, &OIDC_SPEC);
        assert_eq!(merged.len(), 2, "both incoming items kept (incoming order)");
        assert_eq!(merged[0]["id"], json!("google"));
        assert_eq!(merged[0]["client_secret"], json!("REAL-google-secret"));
        assert_eq!(merged[1]["id"], json!("github"));
        assert_eq!(merged[1]["client_secret"], json!("brand-new-github-secret"));
    }

    #[test]
    fn merge_drops_removed_id() {
        // An id present only in stored (not in incoming) is dropped (removal).
        let stored = vec![
            oidc("google", Some("REAL-google-secret")),
            oidc("github", Some("REAL-github-secret")),
        ];
        let incoming = vec![oidc("google", Some(MASKED))];
        let merged = merge_array_by_id(&stored, &incoming, &OIDC_SPEC);
        assert_eq!(merged.len(), 1, "removed id is dropped");
        assert_eq!(merged[0]["id"], json!("google"));
        assert_eq!(merged[0]["client_secret"], json!("REAL-google-secret"));
    }

    #[test]
    fn merge_preserves_nested_sms_secret() {
        // SMS channel: nested request_config.auth.config.password preserved when
        // masked, with the rest of request_config edited.
        let stored = vec![json!({
            "id": "sms",
            "type": "sms",
            "request_config": {
                "url": "https://sms.example/send",
                "method": "POST",
                "auth": { "type": "basic_auth", "config": { "user": "u", "password": "REAL-sms-pass" } }
            }
        })];
        let incoming = vec![json!({
            "id": "sms",
            "type": "sms",
            "request_config": {
                "url": "https://sms.example/v2/send",
                "method": "POST",
                "auth": { "type": "basic_auth", "config": { "user": "u", "password": MASKED } }
            }
        })];
        let merged = merge_array_by_id(&stored, &incoming, &SMS_SPEC);
        assert_eq!(
            merged[0]["request_config"]["auth"]["config"]["password"],
            json!("REAL-sms-pass"),
            "masked nested SMS password must inherit the stored value"
        );
        // The non-secret nested edit is kept.
        assert_eq!(
            merged[0]["request_config"]["url"],
            json!("https://sms.example/v2/send")
        );
    }

    #[test]
    fn mask_nested_webhook_secret() {
        // web_hook config.auth.config.password masked; keyed by url.
        let items = vec![json!({
            "hook": "web_hook",
            "config": {
                "url": "https://hook.example/event",
                "method": "POST",
                "body": "base64://Zm9v",
                "auth": { "type": "api_key", "config": { "value": "REAL-webhook-token", "in": "header", "name": "X-Api" } }
            }
        })];
        // For the WEBHOOK_SPEC the id is `url` — but it lives under config.url for
        // a web_hook item shape. The spec keys on top-level `url`; this test only
        // checks masking (id-independent), so it exercises the nested secret path.
        let masked = mask_array_secrets(&items, &WEBHOOK_SPEC);
        assert_eq!(
            masked[0]["config"]["auth"]["config"]["value"],
            json!(MASKED),
            "nested webhook auth value must be masked"
        );
        let s = serde_json::to_string(&masked).unwrap();
        assert!(!s.contains("REAL-webhook-token"), "webhook token leaked: {s}");
    }

    #[test]
    fn merge_item_without_id_kept_verbatim() {
        // An incoming item with no id cannot match -> kept as-is (real secret too).
        let stored = vec![oidc("google", Some("REAL"))];
        let incoming = vec![json!({ "provider": "noid", "client_secret": "x" })];
        let merged = merge_array_by_id(&stored, &incoming, &OIDC_SPEC);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0]["client_secret"], json!("x"));
    }
}
