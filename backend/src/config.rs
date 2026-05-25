//! Environment-parsed runtime configuration.
//!
//! BACK-07: the DSN and GitHub client secret are secrets. `Config` implements a
//! REDACTING `Debug` so an accidental `{:?}` (or a tracing `?config`) never
//! prints the DSN or the OAuth secret. The DSN is read from the env single
//! source of truth (`DATABASE_URL`, injected by docker-compose) — never
//! hardcoded.

use std::env;
use std::fmt;

use crate::error::AppError;

/// Default bind address — listens on all interfaces so the container is
/// reachable from both the edge (host-published) and internal networks.
const DEFAULT_BIND_ADDR: &str = "0.0.0.0:8080";

/// 7 days, in seconds — default sliding idle window for a session.
const DEFAULT_SESSION_IDLE_SECS: i64 = 604_800;
/// 30 days, in seconds — default absolute session lifetime cap.
const DEFAULT_SESSION_ABSOLUTE_SECS: i64 = 2_592_000;

/// Optional GitHub OAuth configuration. Present ONLY when both the client id
/// and secret are set in the environment (CAUTH-04 env-gating).
#[derive(Clone)]
pub struct GithubCfg {
    pub client_id: String,
    pub client_secret: String,
    /// Optional explicit redirect URL; defaults are applied by the OAuth layer.
    pub redirect_url: Option<String>,
}

impl fmt::Debug for GithubCfg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the client secret. client_id is low-sensitivity but we
        // still redact it to keep the whole struct log-safe.
        f.debug_struct("GithubCfg")
            .field("client_id", &"<redacted>")
            .field("client_secret", &"<redacted>")
            .field("redirect_url", &self.redirect_url)
            .finish()
    }
}

/// Runtime configuration assembled from the environment at boot.
#[derive(Clone)]
pub struct Config {
    /// Console-DB connection string (env `DATABASE_URL`). SECRET — redacted.
    pub console_database_url: String,
    /// TCP bind address (env `BACKEND_BIND_ADDR`, default `0.0.0.0:8080`).
    pub bind_addr: String,
    /// Sliding idle window in seconds (env `SESSION_IDLE_SECS`, default 7d).
    pub session_idle_secs: i64,
    /// Absolute session lifetime cap in seconds (env `SESSION_ABSOLUTE_SECS`, default 30d).
    pub session_absolute_secs: i64,
    /// Dev escape hatch (env `CONSOLE_INSECURE_COOKIES`, default false): drop the
    /// `__Host-` prefix + Secure so cookies work over plain-HTTP localhost (Pitfall 6).
    pub insecure_cookies: bool,
    /// GitHub OAuth config — `Some` only when both id+secret env vars are set.
    pub github: Option<GithubCfg>,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redact the DSN (carries the DB password). Everything else is non-secret.
        f.debug_struct("Config")
            .field("console_database_url", &"<redacted>")
            .field("bind_addr", &self.bind_addr)
            .field("session_idle_secs", &self.session_idle_secs)
            .field("session_absolute_secs", &self.session_absolute_secs)
            .field("insecure_cookies", &self.insecure_cookies)
            .field("github", &self.github)
            .finish()
    }
}

impl Config {
    /// Parse `Config` from the environment. The console DSN is mandatory; all
    /// other fields fall back to hardened defaults. Returns `AppError::Config`
    /// (mapped to 500) on a missing/invalid required value — the message is
    /// operator-facing and contains NO secret value.
    pub fn from_env() -> Result<Config, AppError> {
        let console_database_url = env::var("DATABASE_URL").map_err(|_| {
            AppError::Config("DATABASE_URL is not set (console DB DSN is required)".into())
        })?;

        let bind_addr =
            env::var("BACKEND_BIND_ADDR").unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_string());

        let session_idle_secs = parse_secs("SESSION_IDLE_SECS", DEFAULT_SESSION_IDLE_SECS)?;
        let session_absolute_secs =
            parse_secs("SESSION_ABSOLUTE_SECS", DEFAULT_SESSION_ABSOLUTE_SECS)?;

        let insecure_cookies = parse_bool("CONSOLE_INSECURE_COOKIES", false);

        // GitHub OAuth is mounted ONLY when both id and secret are present.
        let github = match (
            env::var("GITHUB_OAUTH_CLIENT_ID").ok(),
            env::var("GITHUB_OAUTH_CLIENT_SECRET").ok(),
        ) {
            (Some(client_id), Some(client_secret))
                if !client_id.is_empty() && !client_secret.is_empty() =>
            {
                Some(GithubCfg {
                    client_id,
                    client_secret,
                    redirect_url: env::var("GITHUB_OAUTH_REDIRECT_URL").ok(),
                })
            }
            _ => None,
        };

        Ok(Config {
            console_database_url,
            bind_addr,
            session_idle_secs,
            session_absolute_secs,
            insecure_cookies,
            github,
        })
    }

    /// Whether GitHub OAuth is enabled (for `GET /api/console/state`).
    pub fn github_oauth_enabled(&self) -> bool {
        self.github.is_some()
    }
}

/// Parse a non-negative i64 seconds env var, falling back to `default`.
fn parse_secs(key: &str, default: i64) -> Result<i64, AppError> {
    match env::var(key) {
        Ok(v) => v
            .parse::<i64>()
            .map_err(|_| AppError::Config(format!("{key} must be an integer (seconds)")))
            .and_then(|n| {
                if n < 0 {
                    Err(AppError::Config(format!("{key} must be >= 0")))
                } else {
                    Ok(n)
                }
            }),
        Err(_) => Ok(default),
    }
}

/// Parse a permissive boolean env var ("1"/"true"/"yes" => true), else `default`.
fn parse_bool(key: &str, default: bool) -> bool {
    match env::var(key) {
        Ok(v) => matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"),
        Err(_) => default,
    }
}
