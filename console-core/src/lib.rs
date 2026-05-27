//! Shared wire DTOs for the Ory Self-Hosted Console.
//!
//! This crate is the SINGLE SOURCE OF TRUTH for the request/response bodies the
//! optional operator CLI (Phase 19) constructs and the Salvo backend
//! deserializes. The backend currently deserializes its OWN inline structs in
//! the route handlers; these types are defined here with field names that are
//! **byte-identical** to those structs so the CLI and server cannot drift. The
//! serialization unit tests below assert the exact JSON field names the backend
//! expects — if a backend route body changes, those tests are the early-warning
//! tripwire.
//!
//! It is deliberately PURE SERDE — no salvo, no sqlx, no reqwest — so depending
//! on it from the backend cannot enlarge the backend's dependency graph (the
//! image-leanness constraint, Task 2).

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// API-key auth header convention (the single source of truth).
//
// The Phase-19 api-key authenticator (backend hoop, Plan 02) and the CLI HTTP
// client (Plan 03) BOTH reference these so the `Authorization: Api-Key <raw>`
// scheme is defined in exactly one place. `API_KEY_HEADER` is the HTTP header
// name; `API_KEY_SCHEME` is the auth-scheme token that prefixes the raw key:
//
//     Authorization: Api-Key <raw-key>
//
// (Header names are case-insensitive per RFC 7230; the backend matches the
// `authorization` header and strips the `Api-Key ` scheme prefix.)
// ---------------------------------------------------------------------------

/// The HTTP header carrying the console API key (RFC 7235 `Authorization`).
pub const API_KEY_HEADER: &str = "authorization";

/// The auth-scheme token prefixing the raw key in the `Authorization` header
/// (`Authorization: Api-Key <raw>`).
pub const API_KEY_SCHEME: &str = "Api-Key";

// ---------------------------------------------------------------------------
// Feature-toggle DTOs (CLI-03).
// ---------------------------------------------------------------------------

/// Body for `PUT /api/console/features/{key}`.
///
/// Mirrors the backend's inline `SetBody { enabled: bool }`
/// (`backend/src/features/routes.rs`). Used by `feature enable|disable` and
/// `observability on|off`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToggleRequest {
    pub enabled: bool,
}

// ---------------------------------------------------------------------------
// Organization DTOs (CLI-05).
// ---------------------------------------------------------------------------

/// Body for `POST /api/organizations`.
///
/// Mirrors the backend's inline `CreateOrgBody`
/// (`backend/src/organizations/routes.rs`): `label`, `domains` (defaulted), and
/// the optional linked SSO connection tenant (omitted from the wire when
/// `None`). `domains` are normalized server-side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateOrgBody {
    pub label: String,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sso_connection_tenant: Option<String>,
}

// ---------------------------------------------------------------------------
// SSO connection DTOs (CLI-05).
// ---------------------------------------------------------------------------

/// Body for `POST /api/sso/connections`.
///
/// Mirrors the backend's inline `CreateBody` (`backend/src/sso/routes.rs`).
/// Exactly ONE metadata source must be set: `metadata_xml` (preferred, no fetch
/// / no SSRF surface) OR `metadata_url`. `default_redirect_url` and
/// `redirect_url` are required; `name` is an optional human label. Optional
/// fields are omitted from the wire when `None`/absent so the byte shape matches
/// what an operator would send.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SsoCreateBody {
    pub tenant: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_xml: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_url: Option<String>,
    pub default_redirect_url: String,
    pub redirect_url: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn api_key_constants_define_the_scheme() {
        // The backend hoop strips this exact scheme prefix from the
        // `authorization` header; the CLI emits `"<scheme> <raw>"`.
        assert_eq!(API_KEY_HEADER, "authorization");
        assert_eq!(API_KEY_SCHEME, "Api-Key");
        // The composed header value the CLI sends.
        let header = format!("{API_KEY_SCHEME} raw-key-123");
        assert_eq!(header, "Api-Key raw-key-123");
    }

    #[test]
    fn toggle_request_serializes_to_enabled_key() {
        let v = serde_json::to_value(ToggleRequest { enabled: true }).unwrap();
        assert_eq!(v, json!({ "enabled": true }));
        // Backend `SetBody` deserialization round-trips.
        let back: ToggleRequest = serde_json::from_value(json!({ "enabled": false })).unwrap();
        assert_eq!(back, ToggleRequest { enabled: false });
    }

    #[test]
    fn create_org_body_full_shape() {
        let v = serde_json::to_value(CreateOrgBody {
            label: "Acme".into(),
            domains: vec!["acme.test".into(), "acme.example".into()],
            sso_connection_tenant: Some("acme-tenant".into()),
        })
        .unwrap();
        assert_eq!(
            v,
            json!({
                "label": "Acme",
                "domains": ["acme.test", "acme.example"],
                "sso_connection_tenant": "acme-tenant"
            })
        );
    }

    #[test]
    fn create_org_body_omits_none_tenant() {
        // `skip_serializing_if` keeps the absent tenant OFF the wire — matching
        // an operator-authored body without the optional field.
        let v = serde_json::to_value(CreateOrgBody {
            label: "Acme".into(),
            domains: vec![],
            sso_connection_tenant: None,
        })
        .unwrap();
        assert_eq!(v, json!({ "label": "Acme", "domains": [] }));
        assert!(v.get("sso_connection_tenant").is_none());
    }

    #[test]
    fn create_org_body_defaults_domains_on_deserialize() {
        // `#[serde(default)]` mirrors the backend's tolerance of a missing
        // `domains` array.
        let back: CreateOrgBody = serde_json::from_value(json!({ "label": "Acme" })).unwrap();
        assert_eq!(back.label, "Acme");
        assert!(back.domains.is_empty());
        assert!(back.sso_connection_tenant.is_none());
    }

    #[test]
    fn sso_create_body_xml_source_shape() {
        let v = serde_json::to_value(SsoCreateBody {
            tenant: "t1".into(),
            metadata_xml: Some("<EntityDescriptor/>".into()),
            metadata_url: None,
            default_redirect_url: "https://console.test/cb".into(),
            redirect_url: vec!["https://console.test/cb".into()],
            name: Some("Okta".into()),
        })
        .unwrap();
        assert_eq!(
            v,
            json!({
                "tenant": "t1",
                "metadata_xml": "<EntityDescriptor/>",
                "default_redirect_url": "https://console.test/cb",
                "redirect_url": ["https://console.test/cb"],
                "name": "Okta"
            })
        );
        // metadata_url omitted when None.
        assert!(v.get("metadata_url").is_none());
    }

    #[test]
    fn sso_create_body_url_source_minimal_shape() {
        let v = serde_json::to_value(SsoCreateBody {
            tenant: "t2".into(),
            metadata_xml: None,
            metadata_url: Some("https://idp.test/metadata".into()),
            default_redirect_url: "https://console.test/cb".into(),
            redirect_url: vec!["https://console.test/cb".into()],
            name: None,
        })
        .unwrap();
        assert_eq!(
            v,
            json!({
                "tenant": "t2",
                "metadata_url": "https://idp.test/metadata",
                "default_redirect_url": "https://console.test/cb",
                "redirect_url": ["https://console.test/cb"]
            })
        );
        assert!(v.get("metadata_xml").is_none());
        assert!(v.get("name").is_none());
    }
}
