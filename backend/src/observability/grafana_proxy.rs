//! Authenticated Grafana reverse-proxy (OBS-05).
//!
//! Grafana is reachable ONLY through this route — it is NEVER host-published and
//! NEVER reached by the browser directly (BACK-01 / INFRA-05). The proxy:
//!
//!   - injects `X-WEBAUTH-USER: <operator>` from the Depot `Session` (the header
//!     Grafana's `GF_AUTH_PROXY_HEADER_NAME` expects) — the operator identity is
//!     the authenticated `admin_id`, NEVER client input (T-16-10);
//!   - STRIPS any client-supplied `X-WEBAUTH-*` header before forwarding so a
//!     caller cannot spoof a different Grafana user (T-16-10);
//!   - appends the `{**path}` to the FIXED `Config` `grafana_url` (no
//!     client-controlled host — no SSRF), after path-NORMALIZING it and rejecting
//!     any `..`/absolute component so it cannot escape the Grafana origin
//!     (T-16-11);
//!   - on a transport failure probes the profile and returns the tolerant
//!     `profile_not_running` state, NEVER a raw 502 (FLAG-04).
//!
//! Mounted behind `FeatureFlagHoop::new("observability")` inside the protected
//! subtree, so it inherits auth_guard (401), csrf_guard (403 on mutating
//! methods), and the observability gate (404 when OFF).

use salvo::http::{Method, StatusCode};
use salvo::prelude::*;

use crate::config::Config;
use crate::db::models::Session;
use crate::error::AppError;
use crate::observability::probe::probe_profile;

/// Short timeout so a stuck Grafana resolves to profile_not_running quickly.
const PROXY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Normalize + validate the wildcard `{**path}` so it can NEVER escape the
/// Grafana origin (T-16-11).
///
/// Rejects (returns `None`):
///   - any segment equal to `..` (parent traversal),
///   - a scheme/authority component (`://` or a leading `//`) that would make
///     reqwest treat the value as an ABSOLUTE URL to an attacker host,
///   - a backslash (Windows-style traversal) or a NUL byte.
///
/// Leading slashes are trimmed (the base already ends at the origin); empty/`.`
/// segments are dropped. The result is a clean relative path safe to append to
/// the fixed base URL.
fn safe_subpath(raw: &str) -> Option<String> {
    // An absolute-URL or protocol-relative value must never be forwarded as-is.
    if raw.contains("://") || raw.starts_with("//") {
        return None;
    }
    if raw.contains('\\') || raw.contains('\0') {
        return None;
    }
    let mut clean: Vec<&str> = Vec::new();
    for seg in raw.split('/') {
        match seg {
            "" | "." => continue,     // collapse empty + current-dir segments
            ".." => return None,       // any parent traversal is rejected outright
            s => clean.push(s),
        }
    }
    Some(clean.join("/"))
}

/// `ANY /api/console/grafana/{**path}` — the authenticated Grafana reverse-proxy.
///
/// Forwards the request to `{grafana_url}/grafana/{path}` over the reqwest-0.13
/// transport, injecting `X-WEBAUTH-USER` from the session and stripping any
/// client-supplied auth-proxy header. The response status/content-type/body are
/// forwarded back. A transport failure → `profile_not_running` (never a 502).
#[handler]
pub async fn grafana_proxy(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
) -> Result<(), AppError> {
    let cfg = obtain_cfg(depot)?;

    // The operator identity for X-WEBAUTH-USER comes ONLY from the auth_guard-
    // injected Session (never a client header). Its absence means the chain is
    // misordered — fail closed as unauthorized.
    let operator = match depot.obtain::<Session>() {
        Ok(s) => s.admin_id.to_string(),
        Err(_) => return Err(AppError::Unauthorized),
    };

    // The wildcard path segment (Salvo `{**path}` is retrieved by the NAME
    // `path` — the `**` is matcher syntax, not part of the key); normalize +
    // reject traversal.
    let raw_path = req.param::<String>("path").unwrap_or_default();
    let sub = safe_subpath(&raw_path)
        .ok_or_else(|| AppError::BadRequest("invalid grafana proxy path".into()))?;

    // Build the FIXED target: {grafana_url}/grafana/{sub}. The host is never
    // client-controlled (no SSRF); `sub` is the normalized relative path.
    let base = cfg.grafana_url.trim_end_matches('/');
    let target = if sub.is_empty() {
        format!("{base}/grafana/")
    } else {
        format!("{base}/grafana/{sub}")
    };

    // Preserve the original query string (Grafana's SPA/back-end needs it). The
    // query is opaque to us and goes to a FIXED host, so it carries no SSRF risk.
    let target = match req.uri().query() {
        Some(q) if !q.is_empty() => format!("{target}?{q}"),
        _ => target,
    };

    let method = req.method().clone();
    let body_bytes = read_body(req, &method).await?;

    let client = reqwest::Client::builder()
        .timeout(PROXY_TIMEOUT)
        // Do NOT auto-follow redirects: a Grafana 3xx should reach the browser as
        // a 3xx (relative Location under /grafana), not be chased server-side.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| AppError::Internal(format!("build grafana proxy client: {e}")))?;

    let mut outbound = client.request(to_reqwest_method(&method), &target);

    // Forward a SAFE subset of inbound headers, EXPLICITLY stripping any
    // client-supplied X-WEBAUTH-* (anti-spoof, T-16-10) and hop-by-hop headers.
    for (name, value) in req.headers().iter() {
        let n = name.as_str().to_ascii_lowercase();
        if n.starts_with("x-webauth")
            || n == "host"
            || n == "cookie"
            || n == "connection"
            || n == "content-length"
            || n == "x-csrf-token"
        {
            continue;
        }
        if let Ok(v) = value.to_str() {
            outbound = outbound.header(name.as_str(), v);
        }
    }

    // Inject the authenticated operator (the ONLY X-WEBAUTH-USER that reaches
    // Grafana). This is the header GF_AUTH_PROXY_HEADER_NAME consumes.
    outbound = outbound.header("X-WEBAUTH-USER", &operator);

    if let Some(bytes) = body_bytes {
        outbound = outbound.body(bytes);
    }

    let upstream = match outbound.send().await {
        Ok(r) => r,
        Err(e) => {
            // Transport failure → tolerant profile_not_running (FLAG-04), never 502.
            tracing::warn!(error = %e, "grafana proxy transport error");
            let state = probe_profile(&cfg).await;
            res.status_code(StatusCode::OK);
            res.render(Json(serde_json::json!({
                "state": state.state,
                "services": state.services,
            })));
            return Ok(());
        }
    };

    // Forward status, content-type, and body back to the browser.
    let status = StatusCode::from_u16(upstream.status().as_u16())
        .unwrap_or(StatusCode::BAD_GATEWAY);
    let content_type = upstream
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let location = upstream
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let bytes = upstream
        .bytes()
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "grafana proxy body read error");
            AppError::Upstream("grafana body error".into())
        })?;

    res.status_code(status);
    if let Some(ct) = content_type {
        let _ = res.add_header(salvo::http::header::CONTENT_TYPE, ct, true);
    }
    if let Some(loc) = location {
        let _ = res.add_header(salvo::http::header::LOCATION, loc, true);
    }
    res.write_body(bytes.to_vec()).ok();
    Ok(())
}

/// Read the request body for body-bearing methods (POST/PUT/PATCH). GET/HEAD/
/// DELETE forward no body. Returns `None` when there is no body to forward.
async fn read_body(req: &mut Request, method: &Method) -> Result<Option<Vec<u8>>, AppError> {
    if matches!(*method, Method::POST | Method::PUT | Method::PATCH) {
        let bytes = req
            .payload()
            .await
            .map_err(|e| AppError::BadRequest(format!("read proxy body: {e}")))?;
        Ok(Some(bytes.to_vec()))
    } else {
        Ok(None)
    }
}

/// Map the Salvo/http `Method` to the reqwest method (same `http` crate type).
fn to_reqwest_method(method: &Method) -> reqwest::Method {
    reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET)
}

/// Obtain the injected [`Config`] from the Depot (cloned).
fn obtain_cfg(depot: &mut Depot) -> Result<Config, AppError> {
    Ok(depot
        .obtain::<Config>()
        .map_err(|_| AppError::Internal("config missing from depot".into()))?
        .clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A clean relative path is normalized (leading slash + empty/dot segments
    /// dropped) and accepted.
    #[test]
    fn safe_subpath_accepts_clean_relative() {
        assert_eq!(safe_subpath("d/abc123").unwrap(), "d/abc123");
        assert_eq!(safe_subpath("/public/build/app.js").unwrap(), "public/build/app.js");
        assert_eq!(safe_subpath("").unwrap(), "");
        assert_eq!(safe_subpath("./api/dashboards").unwrap(), "api/dashboards");
    }

    /// Any `..` traversal component is rejected (T-16-11) — the proxy can never
    /// escape the Grafana origin.
    #[test]
    fn safe_subpath_rejects_parent_traversal() {
        assert!(safe_subpath("../etc/passwd").is_none());
        assert!(safe_subpath("a/../../b").is_none());
        assert!(safe_subpath("public/../../secret").is_none());
    }

    /// An absolute-URL or protocol-relative path is rejected so reqwest cannot be
    /// redirected to an attacker host (SSRF defense, T-16-11).
    #[test]
    fn safe_subpath_rejects_absolute_and_protocol_relative() {
        assert!(safe_subpath("http://evil.example/x").is_none());
        assert!(safe_subpath("https://evil.example").is_none());
        assert!(safe_subpath("//evil.example/x").is_none());
        // Backslash + NUL traversal variants.
        assert!(safe_subpath("..\\windows").is_none());
        assert!(safe_subpath("a\0b").is_none());
    }
}
