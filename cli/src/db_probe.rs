//! The REAL Postgres `SELECT 1` connection check (CLI-builder BYO / IUX-BYO-PG-03).
//!
//! Before bringing the stack up (BYO postgres) or right after (in-stack postgres),
//! the builder opens a genuine TCP/TLS connection to the target Postgres, runs
//! `SELECT 1` with the supplied per-service role credential, and surfaces a clear,
//! SECRET-FREE diagnostic on failure — a real verify, not a TCP poke.
//!
//! TLS: when `sslmode` is `disable`/empty we use `NoTls`; otherwise we build a
//! rustls `MakeRustlsConnect` (the SAME rustls 0.23 + aws-lc-rs provider reqwest
//! already pulls — no second crypto backend) so `sslmode=require` works. The
//! connection future is spawned per the tokio-postgres pattern.
//!
//! SECURITY:
//!   * T-BYO-01 (Information Disclosure): the password is NEVER placed in any
//!     diagnostic. `DbCheckResult.detail` is built from `host:port/db` + the error
//!     Display only; a unit test asserts a known password substring is absent.
//!   * T-BYO-03 (argv leakage): the password reaches this module via
//!     `bootstrap::read_secret` (env / `--*-file` / prompt) — NEVER argv. This
//!     module takes it as an owned `String` and never logs it.
//!   * NO sqlx, NO argon2: pure tokio-postgres + tokio-postgres-rustls.
//!
//! The block-on-fail / `--skip-checks` policy is REUSED from [`crate::probe`] by
//! mapping a [`DbCheckResult`] into a [`crate::probe::ProbeResult`], so the
//! diagnostic + override behavior is identical to the HTTP readiness probes.

use std::time::Duration;

use crate::config_model::{ConsoleConfig, PostgresMode, PostgresConfig};
use crate::probe::ProbeResult;

/// The default DB connection-check timeout (a reachable DB answers `SELECT 1`
/// promptly; a hang is treated as unreachable).
pub const DEFAULT_DB_TIMEOUT: Duration = Duration::from_secs(5);

/// A resolved Postgres connection target. Built either from a BYO [`PostgresConfig`]
/// (+ the per-service role + `POSTGRES_PASSWORD` via `read_secret`) or from the
/// in-stack defaults (`postgres` / `5432` / per-service db+role), so the SAME check
/// works for both modes.
#[derive(Debug, Clone)]
pub struct DbCheckTarget {
    pub host: String,
    pub port: u16,
    pub db: String,
    pub user: String,
    /// `disable` / `` → NoTls; anything else (`require`, `verify-full`, …) → rustls.
    pub sslmode: String,
    /// The role password. SECRET — never placed in any diagnostic / never logged.
    pub password: String,
}

impl DbCheckTarget {
    /// Build a target from the effective config + a resolved role/db/password.
    /// For BYO postgres the host/port/sslmode come from the [`PostgresConfig`]
    /// (falling back to the in-stack defaults for any unset field); for in-stack
    /// they are the bundled-DB defaults. The caller supplies the per-service
    /// `user`/`db` (e.g. `kratos`/`kratos`) and the password from `read_secret`.
    pub fn from_config(
        config: &ConsoleConfig,
        user: &str,
        db: &str,
        password: String,
    ) -> Self {
        let pg: Option<&PostgresConfig> = config.postgres.as_ref();
        let (host, port, sslmode) = match config.postgres_mode() {
            PostgresMode::Byo => (
                pg.and_then(|p| p.host.clone()).unwrap_or_else(|| "postgres".to_string()),
                pg.and_then(|p| p.port.clone())
                    .and_then(|s| s.parse::<u16>().ok())
                    .unwrap_or(5432),
                pg.and_then(|p| p.sslmode.clone()).unwrap_or_else(|| "require".to_string()),
            ),
            PostgresMode::InStack => ("postgres".to_string(), 5432, "disable".to_string()),
        };
        DbCheckTarget {
            host,
            port,
            db: db.to_string(),
            user: user.to_string(),
            sslmode,
            password,
        }
    }

    /// A SECRET-FREE display of the target: `user@host:port/db (sslmode=…)`. Never
    /// includes the password.
    pub fn display(&self) -> String {
        format!(
            "{}@{}:{}/{} (sslmode={})",
            self.user, self.host, self.port, self.db, self.sslmode
        )
    }
}

/// The outcome of one DB connection check. Mirrors [`ProbeResult`] so the existing
/// block-on-fail policy applies unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbCheckResult {
    /// True iff the TCP/TLS connect succeeded AND `SELECT 1` returned.
    pub ok: bool,
    /// A SECRET-FREE target display (`user@host:port/db (sslmode=…)`) — NO password.
    pub target_display: String,
    /// On success a short ok note; on failure the host:port/db + transport/auth
    /// reason. ALWAYS secret-free.
    pub detail: String,
}

/// Whether a sslmode value selects TLS. `disable` / empty → NoTls; everything else
/// (require / prefer / verify-ca / verify-full) → rustls. Pure (testable without a
/// live connect).
pub fn uses_tls(sslmode: &str) -> bool {
    !matches!(sslmode.trim().to_ascii_lowercase().as_str(), "" | "disable")
}

/// Run the REAL connection check: connect (NoTls or rustls per sslmode), spawn the
/// connection future, and run `SELECT 1`. Maps success → ok; ANY error → a
/// secret-free `detail`. Never panics; never logs the password.
pub async fn check(target: &DbCheckTarget, timeout: Duration) -> DbCheckResult {
    let display = target.display();
    match tokio::time::timeout(timeout, connect_and_select(target)).await {
        Ok(Ok(())) => DbCheckResult {
            ok: true,
            target_display: display.clone(),
            detail: format!("SELECT 1 ok at {display}"),
        },
        Ok(Err(e)) => DbCheckResult {
            ok: false,
            target_display: display.clone(),
            // `e` is a tokio_postgres::Error / rustls error — its Display is the
            // transport/auth reason and carries NO password (we never put the
            // password in the connection-config Display path).
            detail: format!("connection to {display} FAILED: {e}"),
        },
        Err(_elapsed) => DbCheckResult {
            ok: false,
            target_display: display.clone(),
            detail: format!("connection to {display} timed out after {timeout:?}"),
        },
    }
}

/// Build the tokio-postgres `Config`, connect (NoTls / rustls per sslmode), spawn
/// the connection driver, and run `SELECT 1`. The password is set on the Config
/// object only (never formatted into a string).
async fn connect_and_select(target: &DbCheckTarget) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut cfg = tokio_postgres::Config::new();
    cfg.host(&target.host)
        .port(target.port)
        .dbname(&target.db)
        .user(&target.user)
        .password(&target.password)
        .connect_timeout(Duration::from_secs(5));

    if uses_tls(&target.sslmode) {
        let tls = make_rustls();
        let (client, connection) = cfg.connect(tls).await?;
        // Drive the connection in the background; drop the handle on return.
        let handle = tokio::spawn(async move {
            let _ = connection.await;
        });
        let r = client.query_one("SELECT 1", &[]).await;
        handle.abort();
        r?;
    } else {
        let (client, connection) = cfg.connect(tokio_postgres::NoTls).await?;
        let handle = tokio::spawn(async move {
            let _ = connection.await;
        });
        let r = client.query_one("SELECT 1", &[]).await;
        handle.abort();
        r?;
    }
    Ok(())
}

/// A rustls `MakeRustlsConnect` using the Mozilla webpki-roots + the aws-lc-rs
/// provider (the SAME crypto backend reqwest pulls — no second provider). For
/// `sslmode=require`. `with_webpki_roots()` relies on the process-default crypto
/// provider, so we install aws-lc-rs as the default exactly once first.
fn make_rustls() -> tokio_postgres_rustls::MakeRustlsConnect {
    use std::sync::Once;
    static INSTALL_PROVIDER: Once = Once::new();
    INSTALL_PROVIDER.call_once(|| {
        // Idempotent: install aws-lc-rs as the process-default crypto provider.
        // Ignore the Err if one is already installed (e.g. reqwest set it).
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
    tokio_postgres_rustls::MakeRustlsConnect::with_webpki_roots()
}

/// Map a [`DbCheckResult`] into a [`ProbeResult`] so the existing
/// [`crate::probe::should_block`] policy (block-on-fail + `--skip-checks`) applies
/// IDENTICALLY to the DB check. `phase` labels the synthetic service name.
pub fn as_probe_result(result: &DbCheckResult, phase: &str) -> ProbeResult {
    ProbeResult {
        service: format!("postgres ({phase})"),
        url: result.target_display.clone(),
        ok: result.ok,
        status_or_error: result.detail.clone(),
        hint: if result.ok {
            String::new()
        } else {
            "verify the Postgres host/port/sslmode and that the per-service role + \
             POSTGRES_PASSWORD match a pre-provisioned database/role (pass --skip-checks \
             to proceed anyway)"
                .to_string()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_selector_picks_notls_for_disable_and_rustls_for_require() {
        assert!(!uses_tls("disable"), "disable → NoTls");
        assert!(!uses_tls(""), "empty → NoTls");
        assert!(!uses_tls("  DISABLE "), "case/space-insensitive disable → NoTls");
        assert!(uses_tls("require"), "require → rustls");
        assert!(uses_tls("verify-full"), "verify-full → rustls");
        assert!(uses_tls("prefer"), "prefer → rustls");
    }

    #[test]
    fn target_display_and_detail_are_secret_free() {
        let target = DbCheckTarget {
            host: "db.ext.example".into(),
            port: 6543,
            db: "kratos".into(),
            user: "kratos".into(),
            sslmode: "require".into(),
            password: "SUPER_SECRET_PW_12345".into(),
        };
        // The secret-free display never contains the password.
        let display = target.display();
        assert!(!display.contains("SUPER_SECRET_PW_12345"), "display leaks password: {display}");
        assert!(display.contains("kratos@db.ext.example:6543/kratos"), "{display}");
        assert!(display.contains("sslmode=require"), "{display}");

        // A failure result's detail (constructed the same way as check()'s error
        // arm, from display + an error string) is also password-free.
        let res = DbCheckResult {
            ok: false,
            target_display: display.clone(),
            detail: format!("connection to {display} FAILED: authentication failed"),
        };
        assert!(!res.detail.contains("SUPER_SECRET_PW_12345"), "detail leaks password: {}", res.detail);
        // And the mapped ProbeResult is secret-free too.
        let pr = as_probe_result(&res, "pre-boot");
        assert!(!pr.status_or_error.contains("SUPER_SECRET_PW_12345"));
        assert!(!pr.url.contains("SUPER_SECRET_PW_12345"));
        assert!(!pr.hint.is_empty(), "a failure carries a hint");
    }

    #[test]
    fn should_block_policy_applies_to_db_check_results() {
        use crate::probe::should_block;
        let bad = DbCheckResult {
            ok: false,
            target_display: "kratos@db.ext:5432/kratos (sslmode=require)".into(),
            detail: "connection FAILED: refused".into(),
        };
        let ok = DbCheckResult {
            ok: true,
            target_display: "kratos@postgres:5432/kratos (sslmode=disable)".into(),
            detail: "SELECT 1 ok".into(),
        };
        let bad_pr = as_probe_result(&bad, "pre-boot");
        let ok_pr = as_probe_result(&ok, "post-boot");
        // failure + not skipping → block.
        assert!(should_block(std::slice::from_ref(&bad_pr), false).is_some());
        // failure + skip → proceed.
        assert!(should_block(std::slice::from_ref(&bad_pr), true).is_none());
        // all ok → proceed.
        assert!(should_block(std::slice::from_ref(&ok_pr), false).is_none());
    }

    #[test]
    fn target_from_config_in_stack_uses_bundled_defaults() {
        let cfg = ConsoleConfig::all_in_stack_default();
        let t = DbCheckTarget::from_config(&cfg, "kratos", "kratos", "pw".into());
        assert_eq!(t.host, "postgres");
        assert_eq!(t.port, 5432);
        assert_eq!(t.sslmode, "disable");
        assert!(!uses_tls(&t.sslmode), "in-stack default → NoTls");
    }

    /// LIVE back-to-back check (IUX-BYO-PG verification). Gated on env so it only
    /// runs inside the compose internal network where `postgres:5432` resolves;
    /// it issues `SELECT 1` ONLY (non-destructive — no writes, no schema changes).
    ///   IUX_LIVE_PG_HOST / _PORT / _USER / _PASSWORD / _DB describe the reachable
    ///   target. PASS = SELECT 1 ok; FAIL = a bad password yields ok=false with a
    ///   secret-free detail; SKIP semantics are exercised by the orchestrate policy
    ///   tests (should_block + --skip-checks) above.
    #[tokio::test]
    async fn live_select_1_pass_and_fail_against_reachable_postgres() {
        let host = match std::env::var("IUX_LIVE_PG_HOST") {
            Ok(h) if !h.is_empty() => h,
            _ => {
                eprintln!("SKIP live DB check: IUX_LIVE_PG_HOST unset");
                return;
            }
        };
        let port: u16 = std::env::var("IUX_LIVE_PG_PORT").ok()
            .and_then(|s| s.parse().ok()).unwrap_or(5432);
        let user = std::env::var("IUX_LIVE_PG_USER").unwrap_or_else(|_| "kratos".into());
        let db = std::env::var("IUX_LIVE_PG_DB").unwrap_or_else(|_| "kratos".into());
        let password = std::env::var("IUX_LIVE_PG_PASSWORD").unwrap_or_default();
        let sslmode = std::env::var("IUX_LIVE_PG_SSLMODE").unwrap_or_else(|_| "disable".into());

        // (a) PASS — correct credentials → SELECT 1 ok.
        let ok_target = DbCheckTarget {
            host: host.clone(), port, db: db.clone(), user: user.clone(),
            sslmode: sslmode.clone(), password: password.clone(),
        };
        let ok = check(&ok_target, DEFAULT_DB_TIMEOUT).await;
        println!("LIVE PASS: ok={} detail={}", ok.ok, ok.detail);
        assert!(ok.ok, "SELECT 1 must succeed against the reachable postgres: {}", ok.detail);

        // (b) FAIL — wrong password → ok=false, secret-free diagnostic.
        let bad_target = DbCheckTarget {
            host, port, db, user,
            sslmode, password: "DEFINITELY_WRONG_PW_zzz".into(),
        };
        let bad = check(&bad_target, DEFAULT_DB_TIMEOUT).await;
        println!("LIVE FAIL: ok={} detail={}", bad.ok, bad.detail);
        assert!(!bad.ok, "a wrong password must fail");
        assert!(!bad.detail.contains("DEFINITELY_WRONG_PW_zzz"), "detail must be secret-free: {}", bad.detail);
        assert!(!bad.target_display.contains("DEFINITELY_WRONG_PW_zzz"));
    }

    #[test]
    fn target_from_config_byo_uses_overrides() {
        let cfg = crate::config_model::parse_config(
            r#"
[postgres]
mode = "byo"
host = "db.ext.example"
port = "6543"
sslmode = "require"
"#,
        )
        .unwrap();
        let t = DbCheckTarget::from_config(&cfg, "kratos", "kratos", "pw".into());
        assert_eq!(t.host, "db.ext.example");
        assert_eq!(t.port, 6543);
        assert_eq!(t.sslmode, "require");
        assert!(uses_tls(&t.sslmode), "byo require → rustls");
    }
}
