//! The optional Ory Self-Hosted Console operator CLI (Phase 19 / CLI-02..06).
//!
//! Two NON-OVERLAPPING modes resolve the "optional setup helper" vs "never a
//! second writer of runtime config" tension cleanly:
//!
//!   * ONLINE  ([`online`]) — an authenticated HTTP client of the EXISTING
//!     backend routes. It presents `Authorization: Api-Key <raw>` (the
//!     [`console_core::API_KEY_SCHEME`] convention) and NEVER writes YAML or the
//!     console DB directly. Every online write reuses a route that already
//!     enforces atomic-write / validation / allowlist / restart / audit. The
//!     online module imports NEITHER `sqlx` NOR a YAML writer (T-19-11 /
//!     Pitfall 4 — asserted by a source-scan test).
//!   * BOOTSTRAP ([`bootstrap`]) — pre-boot filesystem writes of ALREADY
//!     gitignored `.env`/secret paths only. No HTTP. The backend reads these at
//!     boot via `Config::from_env`. Writers never echo the secret they wrote
//!     (BACK-07) and refuse any non-gitignored target (T-19-12 / Pitfall 3).
//!
//! Secrets (`--client-secret`, admin password, rotated values) are accepted ONLY
//! via an env var, a `--*-file <path>`, or an interactive hidden prompt — NEVER
//! an argv flag value (T-19-10 / Pitfall 2). A clap-introspection test enforces
//! that no value-taking `--password`/`--*-secret` argv flag exists.
//!
//! The library exposes the clap [`Cli`] type + the async [`run`] dispatcher so
//! the integration tests can drive the exact same dispatch the `ory-console`
//! binary uses, WITHOUT spawning a subprocess.

pub mod bootstrap;
pub mod client;
pub mod config_model;
pub mod emit;
pub mod online;
pub mod orchestrate;
pub mod probe;
pub mod wizard;

use clap::{Args, Parser, Subcommand};

/// The optional operator CLI.
///
/// Global `--api-url` / `--api-key` are read from env in NORMAL use (clap's
/// `env =` fallback) so the key is never a typed-out argv literal in a shell
/// history / process list. Passing `--api-key <literal>` is DISCOURAGED (the
/// README documents the `CONSOLE_API_KEY` env form); it exists only so the value
/// has somewhere to land — it is NOT a secret-bearing arg in the no-argv-secret
/// sense (the api key is the CLIENT credential, analogous to an SSH key path, and
/// the documented + tested ingress is the env var).
#[derive(Parser, Debug)]
#[command(
    name = "ory-console",
    about = "Optional operator CLI for the Ory self-hosted console",
    long_about = "Two modes: ONLINE (authenticated HTTP client of the backend routes — Authorization: Api-Key) and BOOTSTRAP (pre-boot .env/secret writes). Secrets via env/file/prompt, never argv."
)]
pub struct Cli {
    /// Backend base URL (ONLINE mode). Defaults to the internal compose DNS name.
    #[arg(long, env = "CONSOLE_API_URL", default_value = "http://backend:8080")]
    pub api_url: String,

    /// Console API key (ONLINE mode). Read from `CONSOLE_API_KEY` in normal use;
    /// NEVER logged. ONLINE subcommands error clearly if it is unset.
    #[arg(long, env = "CONSOLE_API_KEY", hide_env_values = true)]
    pub api_key: Option<String>,

    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// First-run BUILDER wizard (CLI-builder Wave 3 / WIZARD, HYBRID). Resolves a
    /// `console.config.toml` three ways — `--defaults` (all-in-stack-on, no
    /// prompts), `--config <file>` (re-apply a saved config), or interactive
    /// prompts — then writes the config + `.env`, generates any missing required
    /// secrets, and (on a Docker host) orchestrates `docker compose up` +
    /// post-boot feature apply + first-run admin. With NO Docker socket it
    /// degrades to config-only and prints the day-2 ONLINE command sequence.
    ///
    /// Carries ONLY non-secret flags (see [`InitArgs`]); every secret stays on
    /// env / `--*-file` / prompt (the no-argv-secret guard holds).
    Init(InitArgs),
    /// Feature flags (CLI-03, ONLINE) — GET/PUT /api/console/features.
    Feature {
        #[command(subcommand)]
        action: FeatureAction,
    },
    /// Observability flag (CLI-03, ONLINE) — PUT /api/console/features/observability.
    Observability {
        #[command(subcommand)]
        action: ObservabilityAction,
    },
    /// SSO connections (CLI-05, ONLINE) — POST /api/sso/connections, PUT config-edit.
    Sso {
        #[command(subcommand)]
        action: SsoAction,
    },
    /// Organizations (CLI-05, ONLINE) — POST /api/organizations.
    Org {
        #[command(subcommand)]
        action: OrgAction,
    },
    /// Admin members (CLI-06) — `list` is ONLINE (GET /api/console/members);
    /// `create`/`reset-password` are BOOTSTRAP/offline (no runtime route).
    Admin {
        #[command(subcommand)]
        action: AdminAction,
    },
    /// Console-login OAuth setup (CLI-04, BOOTSTRAP) — writes .env, no HTTP.
    Oauth {
        #[command(subcommand)]
        action: OauthAction,
    },
    /// First-run bootstrap helpers (CLI-06, BOOTSTRAP) — token + secret rotation.
    Bootstrap {
        #[command(subcommand)]
        action: BootstrapAction,
    },
}

/// Flags for the `init` builder wizard.
///
/// SECURITY (T-CB-C03 / Pitfall 2): this carries ONLY non-secret flags. No
/// value-taking secret flag exists here — the admin password, POLIS_API_KEY,
/// SMTP/SMS/OAuth secrets are ALL read via `bootstrap::read_secret` (env /
/// `--*-file` / interactive prompt), never argv. The clap-introspection guard
/// `no_subcommand_accepts_a_value_taking_secret_flag` enforces this structurally.
#[derive(Args, Debug, Default, Clone)]
pub struct InitArgs {
    /// Fast path: apply the LOCKED defaults (all five Ory services in-stack ON;
    /// advanced features saml/organizations/observability/event_streams OFF; the
    /// rest ON) with NO prompts. Mutually exclusive with `--config`.
    #[arg(long, conflicts_with = "config")]
    pub defaults: bool,

    /// Re-apply a saved `console.config.toml` non-interactively (the `--config`
    /// round-trip contract). Mutually exclusive with `--defaults`.
    #[arg(long, value_name = "PATH")]
    pub config: Option<String>,

    /// Proceed even when a readiness/connection check fails (the explicit override
    /// to the default BLOCK-on-failure policy). The choice is surfaced in output.
    #[arg(long)]
    pub skip_checks: bool,

    /// Target `.env` file the wizard writes (CONSOLE_SERVICE_*, byo URLs,
    /// COMPOSE_PROFILES, generated secrets). Must be a gitignored path.
    #[arg(long, value_name = "PATH", default_value = ".env")]
    pub env_file: String,

    /// Where to write the reproducible `console.config.toml` (secrets excluded).
    #[arg(long, value_name = "PATH", default_value = "console.config.toml")]
    pub config_out: String,

    /// Force config-only mode (skip the host `docker compose up` + post-boot
    /// in-stack steps) even when a Docker daemon IS reachable. The in-container
    /// CLI (INFRA-05, no socket) degrades automatically; this is the manual lever.
    #[arg(long)]
    pub no_docker: bool,
}

#[derive(Subcommand, Debug)]
pub enum FeatureAction {
    /// Enable a feature flag (PUT /api/console/features/{key} {"enabled":true}).
    Enable {
        /// The feature key (e.g. `saml`, `organizations`).
        key: String,
    },
    /// Disable a feature flag (PUT /api/console/features/{key} {"enabled":false}).
    Disable {
        /// The feature key.
        key: String,
    },
    /// List all feature flags (GET /api/console/features).
    List,
}

#[derive(Subcommand, Debug)]
pub enum ObservabilityAction {
    /// Turn observability ON (PUT /api/console/features/observability {"enabled":true}).
    On,
    /// Turn observability OFF (PUT /api/console/features/observability {"enabled":false}).
    Off,
}

#[derive(Subcommand, Debug)]
pub enum SsoAction {
    /// Add a SAML connection (POST /api/sso/connections). Metadata XML is read
    /// from a FILE (never argv): `--metadata-xml-file` OR `--metadata-url`.
    AddSaml {
        /// Connection tenant (becomes the Polis tenant + `saml-<tenant>` provider id).
        #[arg(long)]
        tenant: String,
        /// Path to a file containing the operator-uploaded IdP metadata XML
        /// (PREFERRED — no fetch / no SSRF surface). NEVER the XML on argv.
        #[arg(long, conflicts_with = "metadata_url")]
        metadata_xml_file: Option<String>,
        /// An IdP metadataUrl (SSRF-guarded server-side). Used only when no
        /// `--metadata-xml-file` is given.
        #[arg(long)]
        metadata_url: Option<String>,
        /// Post-login default redirect (the AX/console callback). Required.
        #[arg(long)]
        default_redirect_url: String,
        /// Allowed redirect URL(s) (repeatable). At least one required.
        #[arg(long = "redirect-url", required = true)]
        redirect_url: Vec<String>,
        /// Optional human label.
        #[arg(long)]
        name: Option<String>,
    },
    /// Add an OIDC social provider (PUT /api/config/kratos/oidc, array-root
    /// pointer `/selfservice/methods/oidc/config/providers`). The client secret
    /// is read from env/`--client-secret-file`/prompt — NEVER argv.
    AddOidc {
        /// Stable provider id (e.g. `google`, `github`).
        #[arg(long)]
        id: String,
        /// OIDC provider type (Kratos `provider` value, e.g. `google`, `generic`).
        #[arg(long, default_value = "generic")]
        provider: String,
        /// OAuth2 client id (low sensitivity).
        #[arg(long)]
        client_id: String,
        /// Path to a file holding the OAuth2 client secret. The secret is read
        /// from this file, or `OIDC_CLIENT_SECRET` env, or a hidden prompt —
        /// NEVER an argv value (Pitfall 2).
        #[arg(long)]
        client_secret_file: Option<String>,
        /// Optional issuer URL (for `generic`/`auto-discovery` providers).
        #[arg(long)]
        issuer_url: Option<String>,
        /// Mapper URL (Jsonnet) — defaults to the Kratos sample mapper.
        #[arg(long)]
        mapper_url: Option<String>,
        /// Requested scopes (repeatable). Defaults to openid/email/profile.
        #[arg(long = "scope")]
        scope: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum OrgAction {
    /// Create an organization (POST /api/organizations).
    Add {
        /// Organization label.
        #[arg(long)]
        label: String,
        /// A verified domain (repeatable).
        #[arg(long = "domain")]
        domain: Vec<String>,
        /// Optional linked SSO connection tenant.
        #[arg(long)]
        sso_connection_tenant: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum AdminAction {
    /// List console members (GET /api/console/members — ONLINE, secret-free).
    List,
    /// Create the FIRST-RUN admin. Drives `POST /setup` with the boot-time
    /// bootstrap token (read from `CONSOLE_BOOTSTRAP_TOKEN` env / `--token-file` /
    /// prompt) when `--via-setup` (the single-writer path); the offline DB-direct
    /// fallback requires the `offline-admin` build feature. Password via
    /// env/`--password-file`/prompt — NEVER argv.
    Create {
        /// Admin email / username.
        #[arg(long)]
        email: String,
        /// Admin display name. REQUIRED by the backend `/setup` contract
        /// (`SetupRequest.name` is non-optional); a body without it 400s before
        /// the token is even checked. Also used by the offline DB-direct path.
        #[arg(long)]
        name: String,
        /// Drive the first-run `POST /setup` route (keeps the backend the single
        /// writer). When absent, an offline DB-direct insert is attempted (needs
        /// the `offline-admin` feature).
        #[arg(long)]
        via_setup: bool,
        /// Path to a file holding the new admin password (alternative to the
        /// `CONSOLE_ADMIN_PASSWORD` env var or an interactive prompt).
        #[arg(long)]
        password_file: Option<String>,
        /// Path to a file holding the first-run bootstrap token (alternative to
        /// the `CONSOLE_BOOTSTRAP_TOKEN` env var or a prompt). Used with `--via-setup`.
        #[arg(long)]
        token_file: Option<String>,
    },
    /// Reset an admin password (offline DB-direct; requires the `offline-admin`
    /// feature). Password via env/`--password-file`/prompt — NEVER argv.
    ResetPassword {
        /// Admin email / username whose password is reset.
        #[arg(long)]
        email: String,
        /// Path to a file holding the new password (alternative to the
        /// `CONSOLE_ADMIN_PASSWORD` env var or an interactive prompt).
        #[arg(long)]
        password_file: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum OauthAction {
    /// Configure GitHub login OAuth for the console `/login` page (BOOTSTRAP).
    ///
    /// Upserts `GITHUB_OAUTH_CLIENT_ID` and `GITHUB_OAUTH_CLIENT_SECRET` into
    /// `./.env` (already gitignored). The client SECRET comes from
    /// `GITHUB_OAUTH_CLIENT_SECRET` env, `--client-secret-file`, or a hidden
    /// prompt — NEVER an argv value (Pitfall 2). The secret is never echoed.
    Github {
        #[command(subcommand)]
        action: GithubAction,
    },
}

#[derive(Subcommand, Debug)]
pub enum GithubAction {
    /// Write the GitHub OAuth client id + secret into `./.env`.
    Set {
        /// The GitHub OAuth client id (low sensitivity — may also come from env).
        #[arg(long, env = "GITHUB_OAUTH_CLIENT_ID")]
        client_id: String,
        /// Path to a file holding the GitHub OAuth client secret (alternative to
        /// the `GITHUB_OAUTH_CLIENT_SECRET` env var or an interactive prompt).
        #[arg(long)]
        client_secret_file: Option<String>,
        /// Target `.env` file (default `./.env`). Must be a gitignored path.
        #[arg(long, default_value = ".env")]
        env_file: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum BootstrapAction {
    /// Regenerate + print a NEW first-run bootstrap token (the stored value is a
    /// one-way SHA-256 hash and is UNRECOVERABLE — "reprint" therefore mints a
    /// new token; Pitfall 5). Offline path requires the `offline-admin` feature;
    /// otherwise prints guidance to use the boot-time stdout token.
    Token,
    /// Rotate `.env`/secret-file secrets (DB password / session secret / GitHub
    /// secret) as `.env` upserts. Values via env/`--*-file`/prompt — NEVER argv.
    /// A service restart is the operator's documented follow-up.
    RotateSecrets {
        /// Which secret to rotate (`db-password` or `github-secret`). NOTE:
        /// `session-secret` is NOT rotatable — console sessions are opaque tokens
        /// hashed in the DB, not signed with an env secret; to invalidate sessions
        /// clear the `sessions` table instead.
        #[arg(long)]
        which: String,
        /// Path to a file holding the new secret value (alternative to the
        /// matching env var or an interactive prompt).
        #[arg(long)]
        value_file: Option<String>,
        /// Target `.env` file (default `./.env`). Must be a gitignored path.
        #[arg(long, default_value = ".env")]
        env_file: String,
    },
}

/// Dispatch a parsed [`Cli`] to the ONLINE or BOOTSTRAP handlers.
///
/// ONLINE subcommands build a [`client::ApiClient`] (requiring the api key) and
/// issue exactly the documented HTTP request. BOOTSTRAP subcommands never touch
/// the network — they write only gitignored `.env`/secret paths.
pub async fn run(cli: Cli) -> Result<(), CliError> {
    match cli.cmd {
        // The builder wizard owns its own config/secret/orchestration flow; it
        // reuses the global --api-url/--api-key for the post-boot ONLINE steps.
        Cmd::Init(args) => wizard::run_init(args, &cli.api_url, cli.api_key.as_deref()).await,
        Cmd::Feature { action } => {
            let client = client::ApiClient::new(&cli.api_url, cli.api_key.as_deref())?;
            online::feature(&client, action).await
        }
        Cmd::Observability { action } => {
            let client = client::ApiClient::new(&cli.api_url, cli.api_key.as_deref())?;
            online::observability(&client, action).await
        }
        Cmd::Sso { action } => {
            let client = client::ApiClient::new(&cli.api_url, cli.api_key.as_deref())?;
            online::sso(&client, action).await
        }
        Cmd::Org { action } => {
            let client = client::ApiClient::new(&cli.api_url, cli.api_key.as_deref())?;
            online::org(&client, action).await
        }
        Cmd::Admin { action } => match action {
            // `admin list` is ONLINE; create/reset-password are BOOTSTRAP/offline.
            AdminAction::List => {
                let client = client::ApiClient::new(&cli.api_url, cli.api_key.as_deref())?;
                online::admin_list(&client).await
            }
            other => bootstrap::admin(&cli.api_url, cli.api_key.as_deref(), other).await,
        },
        Cmd::Oauth { action } => bootstrap::oauth(action),
        Cmd::Bootstrap { action } => bootstrap::bootstrap(action),
    }
}

/// A flat, operator-facing CLI error. `Display` is the message printed to stderr;
/// it NEVER contains a secret value.
#[derive(Debug)]
pub enum CliError {
    /// The api key was required for an ONLINE call but was not provided.
    MissingApiKey,
    /// A transport / build error from the HTTP client.
    Http(String),
    /// A non-2xx backend response, already mapped to an operator-safe message.
    Backend(String),
    /// A filesystem / bootstrap error.
    Io(String),
    /// The command is not available in this build (e.g. needs `offline-admin`).
    Unsupported(String),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::MissingApiKey => write!(
                f,
                "no console API key provided — set CONSOLE_API_KEY (an ONLINE command needs it)"
            ),
            CliError::Http(m) => write!(f, "http error: {m}"),
            CliError::Backend(m) => write!(f, "{m}"),
            CliError::Io(m) => write!(f, "io error: {m}"),
            CliError::Unsupported(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for CliError {}
