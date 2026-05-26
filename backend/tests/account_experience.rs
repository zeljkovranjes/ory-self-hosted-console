//! Integration tests for the Phase-15 Account Experience theming + localization
//! override-file routes (AX-02 / AX-03 / FLAG-01 / T-15-06/07/08).
//!
//! `#[sqlx::test]` provisions an isolated DB + runs the embedded migrations
//! (incl. `0007`, which seeds `account_experience=OFF`). Salvo's in-process
//! `TestClient` drives the SAME router the binary serves. The router is built
//! with a TEMP `config_dir` (a `ConfigFixture`-style dir) so the override writes
//! hit a throwaway location, never the live `/etc/config` mount.
//!
//! The four route behaviors proven here:
//!   - GET/PUT theme + GET/PUT translations round-trip when the flag is ON;
//!   - a MALFORMED translations PUT → 422 with NO disk write (file unchanged);
//!   - FLAG-01: with `account_experience` OFF, GET + PUT on BOTH routes → 404
//!     even with a valid session + matching CSRF token (the gate beats both
//!     guards because the FeatureFlagHoop sits AFTER auth_guard/csrf_guard);
//!   - unauthenticated → 401; a state-changing PUT with no CSRF token → 403.

mod common;

use salvo::prelude::*;
use salvo::test::{ResponseExt, TestClient};
use sqlx::PgPool;

/// A throwaway config-dir for the AX override files. Removed on drop so each
/// `#[sqlx::test]` gets an isolated, deterministic location.
struct AxFixture {
    root: std::path::PathBuf,
}

impl AxFixture {
    fn new() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("ory-ax-test-{}-{}", std::process::id(), nanos));
        std::fs::create_dir_all(&root).expect("create temp ax config dir");
        Self { root }
    }

    fn config_dir(&self) -> String {
        self.root.to_string_lossy().into_owned()
    }

    fn theme_file(&self) -> std::path::PathBuf {
        self.root.join("account-experience").join("theme.css")
    }

    fn translations_file(&self) -> std::path::PathBuf {
        self.root
            .join("account-experience")
            .join("translations.json")
    }
}

impl Drop for AxFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Log in the seeded admin and return (raw session token, matching csrf token).
async fn login_and_get_session(service: &Service, pool: &PgPool) -> (String, String) {
    let resp = TestClient::post("http://127.0.0.1:8080/login")
        .json(&serde_json::json!({
            "email": "owner@example.com",
            "password": "a-very-long-password"
        }))
        .send(service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::OK), "login should succeed");
    let raw = common::obtain_session_cookie(&resp).expect("session cookie");
    let csrf = common::csrf_for_raw_token(pool, &raw).await;
    (raw, csrf)
}

/// Toggle `account_experience` ON through the management PUT (refreshes the same
/// in-process flag cache the AX route's FeatureFlagHoop reads).
async fn enable_account_experience(service: &Service, raw: &str, csrf: &str) {
    let put = TestClient::put("http://127.0.0.1:8080/api/console/features/account_experience")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .add_header("X-CSRF-Token", csrf.to_string(), true)
        .json(&serde_json::json!({ "enabled": true }))
        .send(service)
        .await;
    assert_eq!(
        put.status_code,
        Some(StatusCode::OK),
        "toggle account_experience ON"
    );
}

/// Build the test router with the AX temp config-dir on the Config.
fn router_with_ax_dir(pool: PgPool, fixture: &AxFixture) -> Router {
    let cfg = common::cfg_with_config_dir(fixture.config_dir());
    common::build_test_router_cfg(pool, cfg)
}

// --- AX-02/AX-03: round-trip when the flag is ON --------------------------------

/// Theme + translations GET default empty, PUT writes, re-GET returns the written
/// content. Proves the console-owned files round-trip on the mounted volume.
#[sqlx::test(migrations = "./migrations")]
async fn theme_and_translations_round_trip_when_enabled(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let fixture = AxFixture::new();
    let service = Service::new(router_with_ax_dir(pool.clone(), &fixture));
    let (raw, csrf) = login_and_get_session(&service, &pool).await;
    enable_account_experience(&service, &raw, &csrf).await;

    // --- theme: GET empty -> PUT -> GET written ---
    let mut get0 = TestClient::get("http://127.0.0.1:8080/api/account-experience/theme")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .send(&service)
        .await;
    assert_eq!(get0.status_code, Some(StatusCode::OK));
    let body0: serde_json::Value = get0.take_json().await.expect("theme json");
    assert_eq!(body0["source"], "", "no theme file yet -> empty source");

    let css = ":root{--ui-brand:#0a0;--button-primary-bg:#0a0}";
    let put = TestClient::put("http://127.0.0.1:8080/api/account-experience/theme")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .add_header("X-CSRF-Token", csrf.clone(), true)
        .json(&serde_json::json!({ "source": css }))
        .send(&service)
        .await;
    assert_eq!(put.status_code, Some(StatusCode::OK), "theme PUT saves");
    assert!(fixture.theme_file().is_file(), "theme.css was written to the volume");

    let mut get1 = TestClient::get("http://127.0.0.1:8080/api/account-experience/theme")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .send(&service)
        .await;
    let body1: serde_json::Value = get1.take_json().await.expect("theme json");
    assert_eq!(body1["source"], css, "re-GET returns the written theme");

    // --- translations: GET {} -> PUT -> GET written ---
    let mut gt0 = TestClient::get("http://127.0.0.1:8080/api/account-experience/translations")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .send(&service)
        .await;
    assert_eq!(gt0.status_code, Some(StatusCode::OK));
    let tb0: serde_json::Value = gt0.take_json().await.expect("translations json");
    assert_eq!(tb0["translations"], serde_json::json!({}), "default empty object");

    let catalog = serde_json::json!({ "en": { "identities.messages.1040001": "Welcome back" } });
    let putt = TestClient::put("http://127.0.0.1:8080/api/account-experience/translations")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .add_header("X-CSRF-Token", csrf.clone(), true)
        .json(&catalog)
        .send(&service)
        .await;
    assert_eq!(putt.status_code, Some(StatusCode::OK), "translations PUT saves");
    assert!(
        fixture.translations_file().is_file(),
        "translations.json was written to the volume"
    );

    let mut gt1 = TestClient::get("http://127.0.0.1:8080/api/account-experience/translations")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .send(&service)
        .await;
    let tb1: serde_json::Value = gt1.take_json().await.expect("translations json");
    assert_eq!(
        tb1["translations"]["en"]["identities.messages.1040001"], "Welcome back",
        "re-GET returns the written catalog"
    );
}

// --- T-15-08: malformed translations JSON -> 422, NO disk write -----------------

/// A malformed translations PUT returns 422 and leaves the prior file UNCHANGED
/// (no torn/partial write corrupting AX boot).
#[sqlx::test(migrations = "./migrations")]
async fn malformed_translations_is_422_with_no_write(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let fixture = AxFixture::new();
    let service = Service::new(router_with_ax_dir(pool.clone(), &fixture));
    let (raw, csrf) = login_and_get_session(&service, &pool).await;
    enable_account_experience(&service, &raw, &csrf).await;

    // Seed a known-good catalog first.
    let good = serde_json::json!({ "en": { "k": "v" } });
    let seed = TestClient::put("http://127.0.0.1:8080/api/account-experience/translations")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .add_header("X-CSRF-Token", csrf.clone(), true)
        .json(&good)
        .send(&service)
        .await;
    assert_eq!(seed.status_code, Some(StatusCode::OK));
    let before = std::fs::read_to_string(fixture.translations_file()).expect("seed file");

    // Malformed JSON body (raw text, not a serde_json::Value) -> 422, no write.
    let bad = TestClient::put("http://127.0.0.1:8080/api/account-experience/translations")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .add_header("X-CSRF-Token", csrf.clone(), true)
        .add_header("Content-Type", "application/json", true)
        .body("{ this is : not json ]")
        .send(&service)
        .await;
    assert_eq!(
        bad.status_code,
        Some(StatusCode::UNPROCESSABLE_ENTITY),
        "malformed translations JSON must be 422 (T-15-08)"
    );
    let after = std::fs::read_to_string(fixture.translations_file()).expect("file still present");
    assert_eq!(after, before, "the prior file must be untouched after a malformed PUT");
}

// --- FLAG-01: account_experience OFF -> 404 past a valid session + CSRF ----------

/// The keystone for this phase: with `account_experience` seeded OFF, GET + PUT
/// on BOTH editor routes 404 even with a VALID session cookie AND a matching
/// X-CSRF-Token — the FeatureFlagHoop sits after auth_guard/csrf_guard, so a
/// flag-OFF request never reaches the handler (FLAG-01 / T-15-07).
#[sqlx::test(migrations = "./migrations")]
async fn flag_off_returns_404_with_valid_session_and_csrf(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let fixture = AxFixture::new();
    let service = Service::new(router_with_ax_dir(pool.clone(), &fixture));
    let (raw, csrf) = login_and_get_session(&service, &pool).await;
    // NOTE: account_experience is NOT toggled ON — it stays seeded OFF.

    for path in [
        "http://127.0.0.1:8080/api/account-experience/theme",
        "http://127.0.0.1:8080/api/account-experience/translations",
    ] {
        // csrf-exempt GET (authenticated) is gated -> 404.
        let get = TestClient::get(path)
            .add_header("Cookie", format!("console_session={raw}"), true)
            .send(&service)
            .await;
        assert_eq!(
            get.status_code,
            Some(StatusCode::NOT_FOUND),
            "flag-OFF GET {path} must 404 for an authenticated request (FLAG-01)"
        );

        // state-changing PUT with a VALID session + MATCHING CSRF is STILL 404.
        let put = TestClient::put(path)
            .add_header("Cookie", format!("console_session={raw}"), true)
            .add_header("X-CSRF-Token", csrf.clone(), true)
            .json(&serde_json::json!({ "source": ":root{}" }))
            .send(&service)
            .await;
        assert_eq!(
            put.status_code,
            Some(StatusCode::NOT_FOUND),
            "flag-OFF PUT {path} must 404 past a valid session + matching CSRF (FLAG-01)"
        );
    }
}

// --- auth_guard (401) + csrf_guard (403) ---------------------------------------

/// An unauthenticated request → 401 (auth_guard, before the feature gate). A
/// state-changing PUT with a valid session but NO X-CSRF-Token → 403 (csrf_guard).
/// Both guards sit ahead of the FeatureFlagHoop, so they fire regardless of the
/// flag state — here the flag is ON so the only failures are the guards.
#[sqlx::test(migrations = "./migrations")]
async fn unauth_401_and_missing_csrf_403(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let fixture = AxFixture::new();
    let service = Service::new(router_with_ax_dir(pool.clone(), &fixture));
    let (raw, csrf) = login_and_get_session(&service, &pool).await;
    enable_account_experience(&service, &raw, &csrf).await;

    // Unauthenticated GET -> 401.
    let unauth = TestClient::get("http://127.0.0.1:8080/api/account-experience/theme")
        .send(&service)
        .await;
    assert_eq!(
        unauth.status_code,
        Some(StatusCode::UNAUTHORIZED),
        "an unauthenticated request must be 401"
    );

    // Authenticated PUT with NO X-CSRF-Token -> 403.
    let no_csrf = TestClient::put("http://127.0.0.1:8080/api/account-experience/theme")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .json(&serde_json::json!({ "source": ":root{}" }))
        .send(&service)
        .await;
    assert_eq!(
        no_csrf.status_code,
        Some(StatusCode::FORBIDDEN),
        "a state-changing PUT without X-CSRF-Token must be 403"
    );
}

// --- AX-04: SSRF-guarded reachability + reverse-proxy snippet -------------------

/// T-15-11 / T-15-15 (anti-false-green): the reachability check REFUSES an
/// internal-admin / loopback / credentialed target via the HOOK-02 SSRF guard —
/// returning a 4xx, NEVER a 200 `{reachable:false}` (which would mean the fetch
/// happened). The guard rejects BEFORE any connection, so no internal port is
/// ever touched. The flag is ON here so the only rejection is the SSRF guard.
#[sqlx::test(migrations = "./migrations")]
async fn reachability_ssrf_rejects_internal_and_credentialed_targets(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let fixture = AxFixture::new();
    let service = Service::new(router_with_ax_dir(pool.clone(), &fixture));
    let (raw, csrf) = login_and_get_session(&service, &pool).await;
    enable_account_experience(&service, &raw, &csrf).await;

    // Each of these MUST be refused by the SSRF guard (NOT a 200 reachable):
    //   - the Kratos INTERNAL ADMIN port (the INFRA-05 SSRF target, Pitfall 7);
    //   - a loopback literal;
    //   - a credentialed URL (userinfo).
    for bad in [
        "http://kratos:4434/admin/identities",
        "http://127.0.0.1/whatever",
        "http://169.254.169.254/latest/meta-data",
        "http://user:pass@example.com/",
        "ftp://example.com/",
    ] {
        let resp = TestClient::post("http://127.0.0.1:8080/api/account-experience/reachability")
            .add_header("Cookie", format!("console_session={raw}"), true)
            .add_header("X-CSRF-Token", csrf.clone(), true)
            .json(&serde_json::json!({ "url": bad }))
            .send(&service)
            .await;
        // Anti-false-green: it must be an EXPLICIT 4xx refusal, NEVER a 200.
        let code = resp.status_code.expect("status");
        assert!(
            code == StatusCode::BAD_REQUEST || code == StatusCode::UNPROCESSABLE_ENTITY,
            "SSRF target `{bad}` must be REFUSED with a 4xx (got {code:?}) — never a reachable:false 200"
        );
        assert_ne!(
            code,
            StatusCode::OK,
            "SSRF target `{bad}` must NEVER return a 200 (no fetch may happen)"
        );
    }
}

/// The reverse-proxy snippet route returns a generated guidance string mapping the
/// operator host to the AX service + Kratos public path — pure string output, no
/// fetch, no write. csrf-exempt (GET).
#[sqlx::test(migrations = "./migrations")]
async fn reverse_proxy_snippet_generates_guidance(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let fixture = AxFixture::new();
    let service = Service::new(router_with_ax_dir(pool.clone(), &fixture));
    let (raw, csrf) = login_and_get_session(&service, &pool).await;
    enable_account_experience(&service, &raw, &csrf).await;

    let mut resp =
        TestClient::get("http://127.0.0.1:8080/api/account-experience/reverse-proxy-snippet?host=accounts.example.com")
            .add_header("Cookie", format!("console_session={raw}"), true)
            .send(&service)
            .await;
    assert_eq!(resp.status_code, Some(StatusCode::OK), "snippet GET -> 200");
    let body: serde_json::Value = resp.take_json().await.expect("snippet json");
    let snippet = body["snippet"].as_str().expect("snippet string");
    assert!(snippet.contains("accounts.example.com"), "snippet carries the host");
    assert!(snippet.contains("account-experience:3000"), "maps the AX service");
    assert!(snippet.contains("kratos:4433"), "maps the Kratos public path");
    assert!(
        snippet.to_lowercase().contains("tls and dns are owned by your"),
        "snippet states the operator owns TLS/DNS (no provisioning)"
    );
}

/// FLAG-01 (T-15-13): with `account_experience` seeded OFF, BOTH AX-04 routes 404
/// even with a valid session + matching CSRF — the FeatureFlagHoop sits after
/// auth_guard/csrf_guard, so a flag-OFF request never reaches the handler.
#[sqlx::test(migrations = "./migrations")]
async fn ax04_routes_404_when_flag_off(pool: PgPool) {
    common::seed_admin(&pool, "owner@example.com", "a-very-long-password").await;
    let fixture = AxFixture::new();
    let service = Service::new(router_with_ax_dir(pool.clone(), &fixture));
    let (raw, csrf) = login_and_get_session(&service, &pool).await;
    // account_experience is NOT toggled ON — it stays seeded OFF.

    // reachability POST (valid session + matching CSRF) -> 404 (gate beats both).
    let reach = TestClient::post("http://127.0.0.1:8080/api/account-experience/reachability")
        .add_header("Cookie", format!("console_session={raw}"), true)
        .add_header("X-CSRF-Token", csrf.clone(), true)
        .json(&serde_json::json!({ "url": "https://example.com/" }))
        .send(&service)
        .await;
    assert_eq!(
        reach.status_code,
        Some(StatusCode::NOT_FOUND),
        "flag-OFF reachability POST must 404 past a valid session + CSRF (FLAG-01)"
    );

    // snippet GET (authenticated) -> 404.
    let snip =
        TestClient::get("http://127.0.0.1:8080/api/account-experience/reverse-proxy-snippet?host=x.example")
            .add_header("Cookie", format!("console_session={raw}"), true)
            .send(&service)
            .await;
    assert_eq!(
        snip.status_code,
        Some(StatusCode::NOT_FOUND),
        "flag-OFF snippet GET must 404 for an authenticated request (FLAG-01)"
    );
}
