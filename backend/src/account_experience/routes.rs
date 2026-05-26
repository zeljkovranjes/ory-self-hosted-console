//! GET/PUT handlers for the Account Experience theming + localization override
//! files (AX-02 / AX-03).
//!
//! All four handlers obtain the injected [`Config`] from the depot (clone before
//! any await, mirroring `branding`/`config_edit`) and delegate to the file-store
//! functions in the parent module. They are mounted on the PROTECTED subtree and
//! gated by `FeatureFlagHoop::new("account_experience")` in `routes/mod.rs`, so:
//!   - unauthenticated → 401 (auth_guard);
//!   - flag OFF → 404 past a valid session + CSRF (FeatureFlagHoop, FLAG-01);
//!   - state-changing PUT without `X-CSRF-Token` → 403 (csrf_guard);
//!   - GET is csrf-exempt.

use salvo::prelude::*;
use serde::Deserialize;
use serde_json::json;

use crate::config::Config;
use crate::error::AppError;

/// Obtain the injected [`Config`] clone from the depot (CLONE before any await,
/// mirroring the `config_from`/`ory_clients` pattern).
fn config_from(depot: &Depot) -> Result<Config, AppError> {
    depot
        .obtain::<Config>()
        .cloned()
        .map_err(|_| AppError::Internal("config missing from depot".into()))
}

/// PUT body for the theming override: the raw CSS-variable source text.
#[derive(Debug, Deserialize)]
struct ThemeBody {
    source: String,
}

/// `GET /api/account-experience/theme` — return the current theming override
/// source (empty string when no file yet). 200. csrf-exempt.
#[handler]
pub async fn get_theme(depot: &mut Depot, res: &mut Response) -> Result<(), AppError> {
    let cfg = config_from(depot)?;
    let source = crate::account_experience::read_theme(&cfg.config_dir)?;
    res.render(Json(json!({ "source": source })));
    Ok(())
}

/// `PUT /api/account-experience/theme` — atomic-write the theming override
/// (CSRF-guarded). Stores the raw CSS-variable source verbatim; binary content
/// → 400. Returns `{status:"saved"}` so the editor can confirm. Note: applies on
/// the next AX restart (the AX re-reads the file at boot — A3).
#[handler]
pub async fn put_theme(req: &mut Request, depot: &mut Depot, res: &mut Response) -> Result<(), AppError> {
    let cfg = config_from(depot)?;
    let body = req
        .parse_json::<ThemeBody>()
        .await
        .map_err(|_| AppError::BadRequest("expected a JSON body with a 'source' string".into()))?;
    crate::account_experience::write_theme(&cfg.config_dir, &body.source)?;
    tracing::info!("account-experience: theme override saved");
    res.status_code(StatusCode::OK);
    res.render(Json(json!({ "status": "saved" })));
    Ok(())
}

/// `GET /api/account-experience/translations` — return the current
/// customTranslations catalog (the empty object `{}` when none). 200.
/// csrf-exempt. The catalog is returned under `translations`.
#[handler]
pub async fn get_translations(depot: &mut Depot, res: &mut Response) -> Result<(), AppError> {
    let cfg = config_from(depot)?;
    let translations = crate::account_experience::read_translations(&cfg.config_dir)?;
    res.render(Json(json!({ "translations": translations })));
    Ok(())
}

/// `PUT /api/account-experience/translations` — atomic-write the
/// customTranslations catalog (CSRF-guarded). The body is parsed as JSON and
/// REJECTED with 422 (NO disk write) when malformed or not a JSON object
/// (T-15-08). Stores canonical pretty JSON. Applies on the next AX restart (A3).
///
/// The body is read as RAW text (not deserialized) so the JSON-parse + 422 is
/// authoritative here — a malformed body never reaches a serde struct boundary
/// that would 400 with a different shape.
#[handler]
pub async fn put_translations(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
) -> Result<(), AppError> {
    let cfg = config_from(depot)?;
    let raw = req
        .payload()
        .await
        .map_err(|_| AppError::BadRequest("expected a JSON request body".into()))?;
    let body = std::str::from_utf8(raw.as_ref())
        .map_err(|_| AppError::BadRequest("request body must be valid UTF-8".into()))?;
    let stored = crate::account_experience::write_translations(&cfg.config_dir, body)?;
    tracing::info!("account-experience: translations override saved");
    res.status_code(StatusCode::OK);
    res.render(Json(json!({ "status": "saved", "translations": stored })));
    Ok(())
}

/// PUT body for the AX-04 reachability check: the operator-supplied URL to probe.
#[derive(Debug, Deserialize)]
struct ReachabilityBody {
    url: String,
}

/// `POST /api/account-experience/reachability` — SSRF-guarded reachability probe
/// of an operator-supplied custom-domain URL (AX-04 / T-15-11). CSRF-guarded (it
/// performs a server-side fetch, so it is treated as state-changing for CSRF).
///
/// The HOOK-02 SSRF guard runs INSIDE `check_reachability` BEFORE any fetch: an
/// internal/loopback/credentialed/metadata/non-http(s) target is REJECTED as a
/// 4xx (`AppError::BadRequest` → 400) — NEVER collapsed into a `reachable:false`
/// 200 (anti-false-green, T-15-15). A public target that passes the guard is
/// fetched with the pinned, redirects-off client; a transport failure to that
/// public host is a legitimate `{reachable:false}`.
#[handler]
pub async fn reachability(req: &mut Request, res: &mut Response) -> Result<(), AppError> {
    let body = req
        .parse_json::<ReachabilityBody>()
        .await
        .map_err(|_| AppError::BadRequest("expected a JSON body with a 'url' string".into()))?;
    // The guard (and thus a 4xx on an internal/credentialed target) is enforced
    // inside check_reachability — the rejection propagates as the guard's error.
    let result = crate::account_experience::check_reachability(&body.url).await?;
    res.status_code(StatusCode::OK);
    res.render(Json(result));
    Ok(())
}

/// `GET /api/account-experience/reverse-proxy-snippet?host=<axhost>` — generate a
/// reverse-proxy GUIDANCE snippet (nginx/Caddy/Traefik) mapping the operator's AX
/// origin to the Account Experience service + Kratos public path (AX-04). PURE
/// string output: NO fetch, NO file write, NO TLS/DNS provisioning. csrf-exempt
/// (read-only). A missing `host` falls back to a safe placeholder in the snippet.
#[handler]
pub async fn reverse_proxy_snippet(
    req: &mut Request,
    res: &mut Response,
) -> Result<(), AppError> {
    let host = req.query::<String>("host").unwrap_or_default();
    let snippet = crate::account_experience::reverse_proxy_snippet(&host);
    res.status_code(StatusCode::OK);
    res.render(Json(json!({ "snippet": snippet })));
    Ok(())
}
