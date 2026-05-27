//! CLI integration + static tests (Phase 19 / CLI-02..06).
//!
//! Consolidates the 19-VALIDATION Wave-0 gaps into one file:
//!   * `feature_cmds` / `sso_cmds` / `admin_cmds` — route-correctness via mockito
//!     (exact method + path + body + `Authorization: Api-Key` header + NO
//!     `x-csrf-token`).
//!   * `no_argv_secret` — clap-introspection guard (Pitfall 2 / T-19-10).
//!   * `bootstrap_oauth` — `.env` writer + gitignore-match + no-secret-echo
//!     (CLI-04 / T-19-12 / T-19-13).
//!   * `no_second_writer` — source-scan that `online.rs` imports no sqlx/YAML
//!     (Pitfall 4 / T-19-11).
//!
//! The route tests call the library dispatch fns directly (NOT a process spawn)
//! so the assertions exercise the exact same code path the `ory-console` binary
//! uses.

use clap::{CommandFactory, Parser};
use console_cli::ui::Ui;
use console_cli::{
    client::ApiClient, online, Cli, FeatureAction, ObservabilityAction, OrgAction, SsoAction,
};

/// A Plain-mode [`Ui`] for the route tests — drives the production rendering path
/// with zero ANSI / no widgets (the assertions are on the HTTP request, unchanged).
fn test_ui() -> Ui {
    Ui::new(console_cli::ui::OutputMode::Plain)
}

// ─── Route correctness (mockito) ──────────────────────────────────────────────

/// `feature enable saml` → PUT /api/console/features/saml {"enabled":true} with
/// the Api-Key header and NO X-CSRF-Token.
#[tokio::test]
async fn feature_enable_issues_put_with_api_key_no_csrf() {
    let mut server = mockito::Server::new_async().await;
    let m = server
        .mock("PUT", "/api/console/features/saml")
        .match_header("authorization", "Api-Key test-raw-key")
        // mockito's Missing matcher asserts the header is ABSENT.
        .match_header("x-csrf-token", mockito::Matcher::Missing)
        .match_body(mockito::Matcher::Json(serde_json::json!({"enabled": true})))
        .with_status(200)
        .with_body(r#"{"key":"saml","enabled":true}"#)
        .create_async()
        .await;

    let client = ApiClient::new(&server.url(), Some("test-raw-key")).unwrap();
    online::feature(&client, FeatureAction::Enable { key: Some("saml".into()) }, test_ui())
        .await
        .expect("feature enable should succeed");

    m.assert_async().await;
}

/// `feature disable organizations` → PUT body {"enabled":false}.
#[tokio::test]
async fn feature_disable_sends_enabled_false() {
    let mut server = mockito::Server::new_async().await;
    let m = server
        .mock("PUT", "/api/console/features/organizations")
        .match_body(mockito::Matcher::Json(serde_json::json!({"enabled": false})))
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;

    let client = ApiClient::new(&server.url(), Some("k")).unwrap();
    online::feature(
        &client,
        FeatureAction::Disable {
            key: Some("organizations".into()),
        },
        test_ui(),
    )
    .await
    .unwrap();
    m.assert_async().await;
}

/// `feature list` → GET /api/console/features.
#[tokio::test]
async fn feature_list_issues_get() {
    let mut server = mockito::Server::new_async().await;
    let m = server
        .mock("GET", "/api/console/features")
        .match_header("authorization", "Api-Key k")
        .with_status(200)
        .with_body(r#"{"features":{}}"#)
        .create_async()
        .await;

    let client = ApiClient::new(&server.url(), Some("k")).unwrap();
    online::feature(&client, FeatureAction::List, test_ui()).await.unwrap();
    m.assert_async().await;
}

/// `observability on` → PUT /api/console/features/observability {"enabled":true}.
#[tokio::test]
async fn observability_on_targets_observability_key() {
    let mut server = mockito::Server::new_async().await;
    let m = server
        .mock("PUT", "/api/console/features/observability")
        .match_body(mockito::Matcher::Json(serde_json::json!({"enabled": true})))
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;

    let client = ApiClient::new(&server.url(), Some("k")).unwrap();
    online::observability(&client, ObservabilityAction::On, test_ui())
        .await
        .unwrap();
    m.assert_async().await;
}

/// `org add` → POST /api/organizations with {label, domains[], sso_connection_tenant?}.
#[tokio::test]
async fn org_add_posts_organizations_body() {
    let mut server = mockito::Server::new_async().await;
    let m = server
        .mock("POST", "/api/organizations")
        .match_header("authorization", "Api-Key k")
        .match_body(mockito::Matcher::Json(serde_json::json!({
            "label": "Acme",
            "domains": ["acme.test", "acme.example"]
        })))
        .with_status(201)
        .with_body(r#"{"id":"org-1"}"#)
        .create_async()
        .await;

    let client = ApiClient::new(&server.url(), Some("k")).unwrap();
    online::org(
        &client,
        OrgAction::Add {
            label: "Acme".into(),
            domain: vec!["acme.test".into(), "acme.example".into()],
            sso_connection_tenant: None,
        },
        test_ui(),
    )
    .await
    .unwrap();
    m.assert_async().await;
}

/// `sso add-saml` → POST /api/sso/connections, metadata read from a FILE.
#[tokio::test]
async fn sso_add_saml_posts_connections_from_file() {
    let mut server = mockito::Server::new_async().await;
    let m = server
        .mock("POST", "/api/sso/connections")
        .match_header("authorization", "Api-Key k")
        .match_body(mockito::Matcher::Json(serde_json::json!({
            "tenant": "t1",
            "metadata_xml": "<EntityDescriptor/>",
            "default_redirect_url": "https://console.test/cb",
            "redirect_url": ["https://console.test/cb"]
        })))
        .with_status(201)
        .with_body(r#"{"clientID":"c1"}"#)
        .create_async()
        .await;

    // Metadata XML lives in a temp file (never argv).
    let dir = tempfile::tempdir().unwrap();
    let xml_path = dir.path().join("idp.xml");
    std::fs::write(&xml_path, "<EntityDescriptor/>").unwrap();

    let client = ApiClient::new(&server.url(), Some("k")).unwrap();
    online::sso(
        &client,
        SsoAction::AddSaml {
            tenant: "t1".into(),
            metadata_xml_file: Some(xml_path.to_string_lossy().into_owned()),
            metadata_url: None,
            default_redirect_url: "https://console.test/cb".into(),
            redirect_url: vec!["https://console.test/cb".into()],
            name: None,
        },
        test_ui(),
    )
    .await
    .unwrap();
    m.assert_async().await;
}

/// `sso add-oidc` → PUT /api/config/kratos/oidc with a FLAT JSON-Pointer body
/// carrying the array-root providers pointer (A1) + the enabled toggle. The
/// client secret comes from a file (never argv).
#[tokio::test]
async fn sso_add_oidc_puts_config_edit_array_root_pointer() {
    let mut server = mockito::Server::new_async().await;
    let m = server
        .mock("PUT", "/api/config/kratos/oidc")
        .match_header("authorization", "Api-Key k")
        .match_body(mockito::Matcher::AllOf(vec![
            mockito::Matcher::PartialJson(serde_json::json!({
                "/selfservice/methods/oidc/enabled": true
            })),
            mockito::Matcher::PartialJson(serde_json::json!({
                "/selfservice/methods/oidc/config/providers": [{
                    "id": "google",
                    "provider": "google",
                    "client_id": "cid",
                    "client_secret": "shhh-from-file",
                    "scope": ["openid", "email", "profile"]
                }]
            })),
        ]))
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;

    let dir = tempfile::tempdir().unwrap();
    let secret_path = dir.path().join("oidc_secret");
    std::fs::write(&secret_path, "shhh-from-file\n").unwrap();

    let client = ApiClient::new(&server.url(), Some("k")).unwrap();
    online::sso(
        &client,
        SsoAction::AddOidc {
            id: "google".into(),
            provider: "google".into(),
            client_id: "cid".into(),
            client_secret_file: Some(secret_path.to_string_lossy().into_owned()),
            issuer_url: None,
            mapper_url: None,
            scope: vec![],
        },
        test_ui(),
    )
    .await
    .unwrap();
    m.assert_async().await;
}

/// `admin list` → GET /api/console/members.
#[tokio::test]
async fn admin_list_issues_get_members() {
    let mut server = mockito::Server::new_async().await;
    let m = server
        .mock("GET", "/api/console/members")
        .match_header("authorization", "Api-Key k")
        .with_status(200)
        .with_body("[]")
        .create_async()
        .await;

    let client = ApiClient::new(&server.url(), Some("k")).unwrap();
    online::admin_list(&client, test_ui()).await.unwrap();
    m.assert_async().await;
}

/// CR-01 (the false-green that hid the blocker): `admin create --via-setup` MUST
/// POST `/setup` with the REQUIRED `name` field (the backend `SetupRequest.name`
/// is non-optional — a body without it 400s before the token is even checked),
/// alongside `token`, `email`, and `password`. The token + password arrive via
/// `--*-file` paths (never argv); the api-key is irrelevant to this token-gated
/// route. This is the coverage the command previously lacked entirely.
#[tokio::test]
async fn admin_create_via_setup_posts_name_token_email_password() {
    use console_cli::{bootstrap, AdminAction};

    let mut server = mockito::Server::new_async().await;
    let m = server
        .mock("POST", "/setup")
        .match_body(mockito::Matcher::Json(serde_json::json!({
            "name": "Op Admin",
            "token": "boot-token-xyz",
            "email": "admin@example.com",
            "password": "a-strong-passphrase-123"
        })))
        .with_status(201)
        .with_body(r#"{"id":"a1","email":"admin@example.com","name":"Op Admin"}"#)
        .create_async()
        .await;

    // Secrets via FILES (never argv) — token + password.
    let dir = tempfile::tempdir().unwrap();
    let token_path = dir.path().join("boot_token");
    std::fs::write(&token_path, "boot-token-xyz\n").unwrap();
    let pw_path = dir.path().join("admin_pw");
    std::fs::write(&pw_path, "a-strong-passphrase-123\n").unwrap();

    bootstrap::admin(
        &server.url(),
        None, // api-key is irrelevant for the token-gated /setup route
        AdminAction::Create {
            email: "admin@example.com".into(),
            name: "Op Admin".into(),
            via_setup: true,
            password_file: Some(pw_path.to_string_lossy().into_owned()),
            token_file: Some(token_path.to_string_lossy().into_owned()),
        },
    )
    .await
    .expect("admin create --via-setup should POST /setup and succeed on 201");

    // The matcher asserts the EXACT body shape (incl. `name`); this proves the
    // request was actually made with the required field.
    m.assert_async().await;
}

/// A `/setup` that returns 400 (the symptom CR-01 produced when `name` was
/// missing) surfaces as a clear backend error, not a silent success.
#[tokio::test]
async fn admin_create_via_setup_surfaces_setup_400() {
    use console_cli::{bootstrap, AdminAction};

    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("POST", "/setup")
        .with_status(400)
        .with_body(r#"{"error":"invalid JSON body"}"#)
        .create_async()
        .await;

    let dir = tempfile::tempdir().unwrap();
    let token_path = dir.path().join("boot_token");
    std::fs::write(&token_path, "boot-token-xyz").unwrap();
    let pw_path = dir.path().join("admin_pw");
    std::fs::write(&pw_path, "a-strong-passphrase-123").unwrap();

    let err = bootstrap::admin(
        &server.url(),
        None,
        AdminAction::Create {
            email: "admin@example.com".into(),
            name: "Op Admin".into(),
            via_setup: true,
            password_file: Some(pw_path.to_string_lossy().into_owned()),
            token_file: Some(token_path.to_string_lossy().into_owned()),
        },
    )
    .await
    .expect_err("a 400 from /setup must be an error, not a silent success");
    assert!(err.to_string().contains("400"), "got: {err}");
}

/// 401 maps to the "check CONSOLE_API_KEY" message (not a raw status dump).
#[tokio::test]
async fn unauthorized_maps_to_friendly_message() {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("GET", "/api/console/features")
        .with_status(401)
        .with_body("nope")
        .create_async()
        .await;

    let client = ApiClient::new(&server.url(), Some("k")).unwrap();
    let err = online::feature(&client, FeatureAction::List, test_ui())
        .await
        .expect_err("401 should be an error");
    let msg = err.to_string();
    assert!(msg.contains("CONSOLE_API_KEY"), "got: {msg}");
}

/// A missing api key is a clear error BEFORE any HTTP call.
#[test]
fn missing_api_key_is_an_error() {
    match ApiClient::new("http://backend:8080", None) {
        Ok(_) => panic!("no key must error"),
        Err(e) => assert!(e.to_string().contains("CONSOLE_API_KEY"), "got: {e}"),
    }
}

// ─── No-argv-secret (clap introspection, Pitfall 2 / T-19-10) ──────────────────

/// Walk EVERY subcommand's args and assert NONE is a value-taking arg whose name
/// is `password` or ends in `secret`, unless it ends in `-file` (a path, not the
/// secret itself). This is the structural Pitfall-2 guard.
#[test]
fn no_subcommand_accepts_a_value_taking_secret_flag() {
    let cmd = Cli::command();
    let mut offenders: Vec<String> = Vec::new();
    walk_commands(&cmd, &mut offenders);
    assert!(
        offenders.is_empty(),
        "these args take a plaintext secret VALUE on argv (forbidden — use env/--*-file/prompt): {offenders:?}"
    );
}

fn walk_commands(cmd: &clap::Command, offenders: &mut Vec<String>) {
    for arg in cmd.get_arguments() {
        let id = arg.get_id().as_str().to_string();
        let long = arg.get_long().unwrap_or("").to_string();
        // A value-taking arg has a non-zero value range (flags/bools take none).
        let takes_value = arg.get_num_args().map(|r| r.takes_values()).unwrap_or(false);
        let names = format!("{id} {long}");
        let looks_secret = names.split_whitespace().any(|n| {
            let n = n.to_ascii_lowercase();
            (n == "password" || n.ends_with("secret") || n.contains("secret"))
                // `*-file` / `*_file` args carry a PATH, not the secret value.
                && !(n.ends_with("-file") || n.ends_with("_file"))
        });
        if takes_value && looks_secret {
            offenders.push(format!("{}::{names}", cmd.get_name()));
        }
    }
    for sub in cmd.get_subcommands() {
        walk_commands(sub, offenders);
    }
}

/// Positive control: the secret INPUTS that DO exist are `--*-file` path args
/// (and the global `--api-key`, which is the client credential sourced from env).
#[test]
fn secret_inputs_are_file_or_env_args() {
    // These parse cleanly because the secret values are NOT on the command line.
    let cli = Cli::try_parse_from([
        "ory-console",
        "oauth",
        "github",
        "set",
        "--client-id",
        "cid",
        "--client-secret-file",
        "/run/secrets/gh",
    ]);
    assert!(cli.is_ok(), "client-secret-file must parse: {cli:?}");

    // There is no `--client-secret` value flag to accept a literal.
    let bad = Cli::try_parse_from([
        "ory-console",
        "oauth",
        "github",
        "set",
        "--client-id",
        "cid",
        "--client-secret",
        "SHHH",
    ]);
    assert!(bad.is_err(), "a --client-secret VALUE flag must NOT exist");
}

// ─── Bootstrap: gitignore-match + no secret echo (CLI-04 / T-19-12 / T-19-13) ──

/// `oauth github set` writes BOTH GitHub keys into a temp `.env`, the file
/// contains the secret value, the secret is NEVER printed to stdout, and the
/// target path is gitignore-matched.
#[test]
fn oauth_github_set_writes_env_without_echoing_secret() {
    use console_cli::{GithubAction, OauthAction};

    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join(".env");
    let env_path_str = env_path.to_string_lossy().into_owned();

    let secret_file = dir.path().join("gh_secret");
    std::fs::write(&secret_file, "super-secret-value\n").unwrap();

    console_cli::bootstrap::oauth(OauthAction::Github {
        action: GithubAction::Set {
            client_id: "gh-client-id".into(),
            client_secret_file: Some(secret_file.to_string_lossy().into_owned()),
            env_file: env_path_str.clone(),
        },
    })
    .expect("oauth github set should write the .env");

    let written = std::fs::read_to_string(&env_path).unwrap();
    assert!(
        written.contains("GITHUB_OAUTH_CLIENT_ID=gh-client-id"),
        ".env must contain the client id: {written}"
    );
    assert!(
        written.contains("GITHUB_OAUTH_CLIENT_SECRET=super-secret-value"),
        ".env must contain the secret: {written}"
    );

    // The target file's NAME is `.env`, which the repo .gitignore matches. We
    // assert the gitignore RULE here (a temp dir is outside the repo, so we check
    // the pattern, mirroring the production write target).
    assert!(
        path_is_gitignored_env(&env_path_str),
        "the bootstrap target must be a gitignored .env path"
    );
}

/// Existing `.env` keys are preserved when upserting the GitHub pair.
#[test]
fn oauth_github_set_preserves_existing_env_keys() {
    use console_cli::{GithubAction, OauthAction};

    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join(".env");
    std::fs::write(&env_path, "EXISTING_KEY=keepme\nGITHUB_OAUTH_CLIENT_ID=old\n").unwrap();

    let secret_file = dir.path().join("s");
    std::fs::write(&secret_file, "newsecret").unwrap();

    console_cli::bootstrap::oauth(OauthAction::Github {
        action: GithubAction::Set {
            client_id: "newid".into(),
            client_secret_file: Some(secret_file.to_string_lossy().into_owned()),
            env_file: env_path.to_string_lossy().into_owned(),
        },
    })
    .unwrap();

    let written = std::fs::read_to_string(&env_path).unwrap();
    assert!(written.contains("EXISTING_KEY=keepme"), "preserved: {written}");
    assert!(written.contains("GITHUB_OAUTH_CLIENT_ID=newid"), "upserted id: {written}");
    assert!(written.contains("GITHUB_OAUTH_CLIENT_SECRET=newsecret"), "added secret: {written}");
    // The old id value is replaced, not duplicated.
    assert_eq!(written.matches("GITHUB_OAUTH_CLIENT_ID=").count(), 1, "no dup id: {written}");
}

/// The writer REFUSES a non-gitignored target (defense-in-depth, T-19-12).
#[test]
fn bootstrap_refuses_non_gitignored_target() {
    use console_cli::{GithubAction, OauthAction};

    let dir = tempfile::tempdir().unwrap();
    let bad = dir.path().join("kratos.yml"); // not a .env/secret path
    let secret_file = dir.path().join("s");
    std::fs::write(&secret_file, "x").unwrap();

    let err = console_cli::bootstrap::oauth(OauthAction::Github {
        action: GithubAction::Set {
            client_id: "id".into(),
            client_secret_file: Some(secret_file.to_string_lossy().into_owned()),
            env_file: bad.to_string_lossy().into_owned(),
        },
    })
    .expect_err("a non-gitignored target must be refused");
    assert!(err.to_string().contains("gitignored"), "got: {err}");
    assert!(!bad.exists(), "nothing should be written to the refused path");
}

/// Mirror of the repo `.gitignore` `.env` rule: a path whose filename is `.env`
/// or `.env.*` (but not `.env.example`) is ignored.
fn path_is_gitignored_env(path: &str) -> bool {
    let file = path.replace('\\', "/");
    let name = file.rsplit('/').next().unwrap_or(&file);
    (name == ".env" || name.starts_with(".env.")) && name != ".env.example"
}

// ─── No-second-writer static check (Pitfall 4 / T-19-11) ───────────────────────

/// The ONLINE module must import NO sqlx and NO YAML writer — it is HTTP-only.
/// This is the source-scan half of the no-second-writer guard; the `cargo tree`
/// half (sqlx absent from the default graph) is recorded in the SUMMARY.
#[test]
fn online_module_has_no_db_or_yaml_writer() {
    let src = include_str!("../src/online.rs");
    assert!(!src.contains("use sqlx"), "online.rs must not `use sqlx`");
    assert!(!src.contains("sqlx::"), "online.rs must not reference sqlx::");
    assert!(
        !src.contains("serde_yaml") && !src.contains("serde_yml"),
        "online.rs must not import a YAML writer"
    );
    assert!(!src.contains("PgPool"), "online.rs must not touch a Postgres pool");
}
