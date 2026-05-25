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

/// Internal-network defaults for the five Ory Admin base URLs (Phase 3,
/// BACK-02 / INFRA-05). These are the Docker service-key DNS names on the
/// `internal` network; the admin ports are NEVER host-published. base_path is
/// bare `scheme://host:port` with NO `/admin` suffix (RESEARCH Pitfall 2 — the
/// generated crate path templates already prepend the route).
const DEFAULT_KRATOS_ADMIN_URL: &str = "http://kratos:4434";
const DEFAULT_HYDRA_ADMIN_URL: &str = "http://hydra:4445";
const DEFAULT_KETO_READ_URL: &str = "http://keto:4466";
const DEFAULT_KETO_WRITE_URL: &str = "http://keto:4467";
const DEFAULT_OATHKEEPER_API_URL: &str = "http://oathkeeper:4456";

/// Internal-network default for the Phase-1 restart broker (`wollomatic`
/// socket-proxy). Phase 4 (BACK-05): the backend holds NO docker socket — it
/// triggers a single-container restart by POSTing to this scoped broker over the
/// internal network. NON-SECRET (carries no credential) — cleartext in `Debug`.
const DEFAULT_RESTART_BROKER_URL: &str = "http://restart-broker:2375";

/// Default base directory of the mounted service-config tree. Phase 1 INFRA-07
/// bind-mounts `./config` into the backend at `/etc/config` (`:rw`). The
/// per-service YAML lives at `<config_dir>/<service>/<file>`. NON-SECRET — it is
/// a fixed internal filesystem path, never client-supplied.
const DEFAULT_CONFIG_DIR: &str = "/etc/config";

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
    /// Allowlist of acceptable `Origin` values for pre-session state-changing
    /// endpoints (`POST /setup`, `/login`, `/auth/github/callback`). Sourced from
    /// `CONSOLE_ALLOWED_ORIGINS` (comma-separated). EMPTY = allow any origin
    /// (the pre-session origin check is then a no-op — documented dev posture).
    /// Plan-checker Warning 2: defends the two pre-session endpoints against
    /// cross-site form posts before a per-session CSRF token can exist.
    pub allowed_origins: Vec<String>,
    /// GitHub OAuth config — `Some` only when both id+secret env vars are set.
    pub github: Option<GithubCfg>,

    // --- Phase 3 (BACK-02): internal Ory Admin base URLs ---------------------
    // NON-SECRET (they carry no credential) but INFRA-05-sensitive: they live
    // ONLY in backend env/Config and must NEVER be serialised into any
    // frontend-facing response. They appear in CLEARTEXT in the `Debug` impl
    // (unlike the DSN) so config stays log-useful.
    /// Kratos Admin base URL (env `KRATOS_ADMIN_URL`, default `http://kratos:4434`).
    pub kratos_admin_url: String,
    /// Hydra Admin base URL (env `HYDRA_ADMIN_URL`, default `http://hydra:4445`).
    pub hydra_admin_url: String,
    /// Keto READ base URL (env `KETO_READ_URL`, default `http://keto:4466`).
    pub keto_read_url: String,
    /// Keto WRITE base URL (env `KETO_WRITE_URL`, default `http://keto:4467`).
    pub keto_write_url: String,
    /// Oathkeeper API base URL (env `OATHKEEPER_API_URL`, default `http://oathkeeper:4456`).
    pub oathkeeper_api_url: String,

    // --- Phase 4 (BACK-04 / BACK-05): config-edit subsystem -----------------
    /// Restart broker base URL (env `RESTART_BROKER_URL`, default
    /// `http://restart-broker:2375`). The scoped Phase-1 socket-proxy the backend
    /// POSTs a single-container restart to (BACK-05 — backend holds no socket).
    /// NON-SECRET: cleartext in the redacting `Debug`.
    pub restart_broker_url: String,
    /// Base directory of the mounted service-config tree (env `CONFIG_DIR`,
    /// default `/etc/config`). The per-service YAML resolves to
    /// `<config_dir>/<service>/<file>`. NON-SECRET fixed path; never client input.
    pub config_dir: String,
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
            .field("allowed_origins", &self.allowed_origins)
            .field("github", &self.github)
            // Admin URLs are non-secret: print in cleartext (log-useful).
            .field("kratos_admin_url", &self.kratos_admin_url)
            .field("hydra_admin_url", &self.hydra_admin_url)
            .field("keto_read_url", &self.keto_read_url)
            .field("keto_write_url", &self.keto_write_url)
            .field("oathkeeper_api_url", &self.oathkeeper_api_url)
            // Config-edit subsystem URLs/paths are non-secret: print in cleartext.
            .field("restart_broker_url", &self.restart_broker_url)
            .field("config_dir", &self.config_dir)
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

        // CR-02: validate the session-lifespan relationship at startup so a
        // degenerate config can never silently produce an instant-expiry auth
        // outage or an idle window with no protective value. `parse_secs` already
        // rejects negatives; here we reject zero and a contradictory idle>absolute.
        if session_absolute_secs == 0 {
            return Err(AppError::Config(
                "SESSION_ABSOLUTE_SECS must be > 0".into(),
            ));
        }
        if session_idle_secs == 0 {
            return Err(AppError::Config("SESSION_IDLE_SECS must be > 0".into()));
        }
        if session_idle_secs > session_absolute_secs {
            return Err(AppError::Config(
                "SESSION_IDLE_SECS must be <= SESSION_ABSOLUTE_SECS".into(),
            ));
        }

        let insecure_cookies = parse_bool("CONSOLE_INSECURE_COOKIES", false);

        // Pre-session Origin allowlist (Plan-checker Warning 2). Comma-separated;
        // each entry is trimmed and compared case-insensitively (scheme+host+port)
        // against the request `Origin` (or `Referer` origin fallback). Empty list
        // means the pre-session origin check is skipped (dev posture).
        let allowed_origins = env::var("CONSOLE_ALLOWED_ORIGINS")
            .ok()
            .map(|raw| {
                raw.split(',')
                    .map(|s| s.trim().trim_end_matches('/').to_ascii_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

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

        // Phase 3 (BACK-02): the five internal Ory Admin base URLs. Each falls
        // back to its internal-network default; no value is required (they are
        // not secrets and resolve only on the internal Docker network).
        let kratos_admin_url =
            env::var("KRATOS_ADMIN_URL").unwrap_or_else(|_| DEFAULT_KRATOS_ADMIN_URL.to_string());
        let hydra_admin_url =
            env::var("HYDRA_ADMIN_URL").unwrap_or_else(|_| DEFAULT_HYDRA_ADMIN_URL.to_string());
        let keto_read_url =
            env::var("KETO_READ_URL").unwrap_or_else(|_| DEFAULT_KETO_READ_URL.to_string());
        let keto_write_url =
            env::var("KETO_WRITE_URL").unwrap_or_else(|_| DEFAULT_KETO_WRITE_URL.to_string());
        let oathkeeper_api_url = env::var("OATHKEEPER_API_URL")
            .unwrap_or_else(|_| DEFAULT_OATHKEEPER_API_URL.to_string());

        // Phase 4 (BACK-04 / BACK-05): the restart broker base URL + the mounted
        // config-tree directory. Both fall back to their internal-network /
        // bind-mount defaults; neither is a secret and neither is client-derived.
        let restart_broker_url = env::var("RESTART_BROKER_URL")
            .unwrap_or_else(|_| DEFAULT_RESTART_BROKER_URL.to_string());
        let config_dir =
            env::var("CONFIG_DIR").unwrap_or_else(|_| DEFAULT_CONFIG_DIR.to_string());

        Ok(Config {
            console_database_url,
            bind_addr,
            session_idle_secs,
            session_absolute_secs,
            insecure_cookies,
            allowed_origins,
            github,
            kratos_admin_url,
            hydra_admin_url,
            keto_read_url,
            keto_write_url,
            oathkeeper_api_url,
            restart_broker_url,
            config_dir,
        })
    }

    /// Whether `origin` (already normalized: lowercase, no trailing slash) is in
    /// the configured allowlist.
    ///
    /// IN-04 (secure-by-default): an empty allowlist no longer blanket-allows.
    /// In the production posture (`insecure_cookies == false`) an empty allowlist
    /// rejects EVERY presented cross-site `Origin` — the operator must set
    /// `CONSOLE_ALLOWED_ORIGINS` to permit a browser origin. Only the explicit dev
    /// escape hatch (`CONSOLE_INSECURE_COOKIES=1`) relaxes this to allow-any so
    /// plain-HTTP localhost development is not blocked. The `origin_guard` hoop
    /// still treats an ABSENT Origin (API client / same-origin post that omits it)
    /// as allowed; this method only judges a PRESENT origin value.
    pub fn origin_allowed(&self, origin: &str) -> bool {
        if self.allowed_origins.is_empty() {
            // Dev escape hatch: allow any origin only when cookies are insecure.
            // Otherwise fail closed — a present cross-site Origin is rejected.
            return self.insecure_cookies;
        }
        let norm = origin.trim().trim_end_matches('/').to_ascii_lowercase();
        self.allowed_origins.iter().any(|o| o == &norm)
    }

    /// Whether the pre-session Origin check is fully disabled (dev posture):
    /// only when the allowlist is empty AND the dev insecure-cookie escape hatch
    /// is on. In the secure-by-default production posture this is `false`, so the
    /// `origin_guard` enforces a present Origin against the allowlist.
    pub fn origin_check_disabled(&self) -> bool {
        self.allowed_origins.is_empty() && self.insecure_cookies
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // `from_env` reads process-global env; serialize the env-mutating tests so
    // they cannot interleave and observe each other's vars.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Run `f` with the given session-lifespan env vars set, restoring prior
    /// state afterward. `DATABASE_URL` is set so `from_env` reaches the
    /// validation block (the DSN is the only other required var).
    fn with_session_env(idle: Option<&str>, absolute: Option<&str>) -> Result<Config, AppError> {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Snapshot + clear the vars we touch.
        let prev_dsn = env::var("DATABASE_URL").ok();
        let prev_idle = env::var("SESSION_IDLE_SECS").ok();
        let prev_abs = env::var("SESSION_ABSOLUTE_SECS").ok();

        env::set_var("DATABASE_URL", "postgres://u:p@localhost/console");
        match idle {
            Some(v) => env::set_var("SESSION_IDLE_SECS", v),
            None => env::remove_var("SESSION_IDLE_SECS"),
        }
        match absolute {
            Some(v) => env::set_var("SESSION_ABSOLUTE_SECS", v),
            None => env::remove_var("SESSION_ABSOLUTE_SECS"),
        }

        let result = Config::from_env();

        // Restore.
        match prev_dsn {
            Some(v) => env::set_var("DATABASE_URL", v),
            None => env::remove_var("DATABASE_URL"),
        }
        match prev_idle {
            Some(v) => env::set_var("SESSION_IDLE_SECS", v),
            None => env::remove_var("SESSION_IDLE_SECS"),
        }
        match prev_abs {
            Some(v) => env::set_var("SESSION_ABSOLUTE_SECS", v),
            None => env::remove_var("SESSION_ABSOLUTE_SECS"),
        }
        result
    }

    #[test]
    fn rejects_zero_absolute_session() {
        let err = with_session_env(Some("60"), Some("0")).unwrap_err();
        assert!(matches!(err, AppError::Config(_)), "got {err:?}");
    }

    #[test]
    fn rejects_zero_idle_session() {
        let err = with_session_env(Some("0"), Some("60")).unwrap_err();
        assert!(matches!(err, AppError::Config(_)), "got {err:?}");
    }

    #[test]
    fn rejects_idle_greater_than_absolute() {
        let err = with_session_env(Some("120"), Some("60")).unwrap_err();
        assert!(matches!(err, AppError::Config(_)), "got {err:?}");
    }

    #[test]
    fn accepts_idle_equal_to_absolute() {
        let cfg = with_session_env(Some("60"), Some("60")).expect("equal idle/absolute is valid");
        assert_eq!(cfg.session_idle_secs, 60);
        assert_eq!(cfg.session_absolute_secs, 60);
    }

    #[test]
    fn accepts_default_lifespans() {
        let cfg = with_session_env(None, None).expect("defaults are valid");
        assert_eq!(cfg.session_idle_secs, DEFAULT_SESSION_IDLE_SECS);
        assert_eq!(cfg.session_absolute_secs, DEFAULT_SESSION_ABSOLUTE_SECS);
    }
}
