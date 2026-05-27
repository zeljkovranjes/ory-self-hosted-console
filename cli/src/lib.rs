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
pub mod check;
pub mod client;
pub mod config_model;
pub mod db_probe;
pub mod edit;
pub mod emit;
pub mod online;
pub mod orchestrate;
pub mod probe;
pub mod ui;
pub mod wizard;

use clap::{Args, CommandFactory, Parser, Subcommand};

use crate::ui::{OutputMode, Ui};

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

    /// Force PLAIN output (CLI-07e): no color, no box-drawing tables, no spinners,
    /// no interactive widgets — line-based prompts only, ZERO ANSI escape bytes.
    /// A non-secret bool (the no-argv-secret guard ignores it). Output is ALSO
    /// forced plain automatically on a non-TTY / under `NO_COLOR` (see
    /// [`ui::resolve_mode`]); this is the explicit operator lever for the same.
    #[arg(long, global = true)]
    pub text: bool,

    /// The subcommand to run. OPTIONAL so a bare `ory-console` (no subcommand)
    /// parses — on a TTY it launches the guided home menu, on a non-TTY it prints
    /// usage and exits code 2 (it never hangs). See [`run`].
    #[command(subcommand)]
    pub cmd: Option<Cmd>,
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
    /// READ-ONLY inspection (CLI-08) — stack health, configured modes, config
    /// validity, effective feature flags. `check` writes NOTHING (no `.env` /
    /// `console.config.toml` / DB / YAML mutation — T-20-WRITE) and its exit code
    /// reflects health (`0` = all selected healthy, non-zero otherwise; CLI-08b).
    /// The module bodies land in a later Wave 3; the variant is scaffolded HERE so
    /// lib.rs stays single-writer for the command tree.
    Check {
        #[command(subcommand)]
        action: CheckAction,
    },
    /// GUIDED editing (CLI-09) — interactive `[x]`/`[ ]` feature toggles, per-service
    /// mode re-pick, and `console.config.toml` re-edit. `edit` mutates ONLY through
    /// the EXISTING backend feature route + the EXISTING config/`.env` writers — it
    /// is never a second writer of the console DB or service YAML. Module bodies
    /// land in a later Wave 3; the variant is scaffolded HERE.
    Edit {
        #[command(subcommand)]
        action: EditAction,
    },
}

/// READ-ONLY `check` subcommands (CLI-08). The LOCKED variant set; the per-command
/// logic lands in [`check`] (Wave 3). NONE carries a value-taking secret flag.
#[derive(Subcommand, Debug)]
pub enum CheckAction {
    /// Per-service health/mode table + an overall verdict; exit code reflects
    /// health (CLI-08b).
    Status,
    /// Configured mode (in-stack/byo/off) + reachability per service.
    Services,
    /// Validate `console.config.toml` shape + `.env` presence/required-key shape.
    /// Writes nothing; prints no secret values.
    Config {
        /// Path to the `console.config.toml` to validate (default handled in the
        /// module). A PLAIN path — not a secret.
        #[arg(long, value_name = "PATH")]
        config: Option<String>,
    },
    /// Current effective feature flags as a table.
    Features,
}

/// GUIDED `edit` subcommands (CLI-09). The LOCKED variant set; the per-command
/// logic lands in [`edit`] (Wave 3). NONE carries a value-taking secret flag.
#[derive(Subcommand, Debug)]
pub enum EditAction {
    /// The `[x]`/`[ ]` checkbox feature toggle list, pre-checked to current state;
    /// applies changed keys via the EXISTING PUT `/api/console/features/{key}` route.
    Features,
    /// Re-pick per-service mode + BYO URLs via select prompts; re-emit config + `.env`
    /// through the EXISTING writers.
    Services {
        /// Path to the `console.config.toml` to load/edit/re-write (default handled
        /// in the module). A PLAIN path — not a secret.
        #[arg(long, value_name = "PATH")]
        config: Option<String>,
    },
    /// Load an existing `console.config.toml`, edit it interactively, re-write it
    /// through the EXISTING writers.
    Config {
        /// Path to the `console.config.toml` to load/edit/re-write (default handled
        /// in the module). A PLAIN path — not a secret.
        #[arg(long, value_name = "PATH")]
        config: Option<String>,
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
        /// The feature key (e.g. `saml`, `organizations`). OPTIONAL: when omitted
        /// on a Rich TTY the CLI offers an interactive `Select` of the valid keys
        /// (CLI-07 omitted-positional picker) instead of a clap usage error; on a
        /// non-TTY it errors clearly. A PLAIN key — not a secret.
        key: Option<String>,
    },
    /// Disable a feature flag (PUT /api/console/features/{key} {"enabled":false}).
    Disable {
        /// The feature key. OPTIONAL — same omitted-positional picker as `enable`.
        /// A PLAIN key — not a secret.
        key: Option<String>,
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
    // Resolve the output mode ONCE (the `ui` authority): `--text` / non-TTY /
    // NO_COLOR all force Plain. EVERY downstream widget + table + status line
    // branches on this; a `dialoguer` widget is never constructed off a Rich path.
    let ui = Ui::from_flag(cli.text);
    dispatch(cli, ui).await
}

/// The mode-aware dispatch core (split out of [`run`] so the resolved [`Ui`] is
/// passed explicitly to every handler).
async fn dispatch(cli: Cli, ui: Ui) -> Result<(), CliError> {
    let cmd = match cli.cmd {
        Some(c) => c,
        // BARE invocation (no subcommand): a guided home menu on a Rich TTY, a
        // usage dump + exit-2 sentinel on a Plain/non-TTY path (never a hang —
        // `home_menu_or_usage` only constructs a widget when `ui.mode == Rich`).
        None => return home_menu_or_usage(ui, &cli.api_url, cli.api_key.as_deref()).await,
    };
    match cmd {
        // The builder wizard owns its own config/secret/orchestration flow; it
        // reuses the global --api-url/--api-key for the post-boot ONLINE steps.
        Cmd::Init(args) => wizard::run_init(args, &cli.api_url, cli.api_key.as_deref()).await,
        Cmd::Feature { action } => {
            let client = client::ApiClient::new(&cli.api_url, cli.api_key.as_deref())?;
            online::feature(&client, action, ui).await
        }
        Cmd::Observability { action } => {
            let client = client::ApiClient::new(&cli.api_url, cli.api_key.as_deref())?;
            online::observability(&client, action, ui).await
        }
        Cmd::Sso { action } => {
            let client = client::ApiClient::new(&cli.api_url, cli.api_key.as_deref())?;
            online::sso(&client, action, ui).await
        }
        Cmd::Org { action } => {
            let client = client::ApiClient::new(&cli.api_url, cli.api_key.as_deref())?;
            online::org(&client, action, ui).await
        }
        Cmd::Admin { action } => match action {
            // `admin list` is ONLINE; create/reset-password are BOOTSTRAP/offline.
            AdminAction::List => {
                let client = client::ApiClient::new(&cli.api_url, cli.api_key.as_deref())?;
                online::admin_list(&client, ui).await
            }
            other => bootstrap::admin(&cli.api_url, cli.api_key.as_deref(), other).await,
        },
        Cmd::Oauth { action } => bootstrap::oauth(action),
        Cmd::Bootstrap { action } => bootstrap::bootstrap(action),
        Cmd::Check { action } => check::run_check(action, &cli.api_url, cli.api_key.as_deref(), ui).await,
        Cmd::Edit { action } => edit::run_edit(action, &cli.api_url, cli.api_key.as_deref(), ui).await,
    }
}

/// Bare-invocation entry: a guided home menu on a Rich TTY, usage + exit-2 on a
/// Plain/non-TTY path.
///
/// In [`OutputMode::Plain`] we NEVER construct an interactive widget (a non-TTY
/// caller would block forever) — we print the clap long help to stderr and return
/// [`CliError::Usage`], which `main` maps to the LOCKED bare-non-TTY exit code `2`
/// (the `non_tty_never_hangs` contract). In [`OutputMode::Rich`] we present a
/// `Select` home menu routing into the command groups.
async fn home_menu_or_usage(
    ui: Ui,
    api_url: &str,
    api_key: Option<&str>,
) -> Result<(), CliError> {
    if ui.mode == OutputMode::Plain {
        // Usage to STDERR; the exit code (2) is the operator signal, not stdout.
        let mut cmd = Cli::command();
        let help = cmd.render_long_help();
        eprintln!("{help}");
        return Err(CliError::Usage);
    }

    // Rich TTY: a guided home menu. Re-dispatch the chosen group through `run`-style
    // construction so each group's own interactive form drives the rest.
    let prompter = ui.prompter();
    let items = [
        "Build / Init  — first-run setup wizard",
        "Check         — read-only stack/config/feature inspection",
        "Edit          — guided feature/service/config editing",
        "Day-2         — feature/observability/sso/org/admin commands",
        "Quit",
    ];
    loop {
        let choice = prompter.select("What would you like to do?", &items, 0)?;
        match choice {
            // Build → the interactive init wizard (default args = the prompt path).
            0 => return wizard::run_init(InitArgs::default(), api_url, api_key).await,
            // Check → sub-Select of the check actions.
            1 => {
                let actions = ["status", "services", "config", "features"];
                let a = prompter.select("check —", &actions, 0)?;
                let action = match a {
                    0 => CheckAction::Status,
                    1 => CheckAction::Services,
                    2 => CheckAction::Config { config: None },
                    _ => CheckAction::Features,
                };
                return check::run_check(action, api_url, api_key, ui).await;
            }
            // Edit → sub-Select of the edit actions.
            2 => {
                let actions = ["features", "services", "config"];
                let a = prompter.select("edit —", &actions, 0)?;
                let action = match a {
                    0 => EditAction::Features,
                    1 => EditAction::Services { config: None },
                    _ => EditAction::Config { config: None },
                };
                return edit::run_edit(action, api_url, api_key, ui).await;
            }
            // Day-2 → point the operator at the day-2 verbs (these take args, so we
            // surface the help rather than guess; an unguided list keeps it simple).
            3 => {
                ui.heading("Day-2 commands");
                ui.hint(
                    "feature <enable|disable|list> · observability <on|off> · \
                     sso <add-saml|add-oidc> · org add · admin list · oauth github set · \
                     bootstrap <token|rotate-secrets>",
                );
                return Ok(());
            }
            // Quit.
            _ => return Ok(()),
        }
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
    /// A bare invocation on a non-TTY: usage was printed; `main` maps this to the
    /// LOCKED exit code `2` (the `non_tty_never_hangs` contract). Carries no
    /// message of its own (the rendered help is the operator-facing output).
    Usage,
    /// A read-only `check` verdict that found an UNHEALTHY result (a selected
    /// service unreachable or config invalid; CLI-08b). The handler already
    /// rendered the per-service table + the failing-verdict line; this carries the
    /// non-zero process exit code `main` maps verbatim. It is NOT an internal
    /// failure — it is the SCRIPTABLE health signal. Display is a terse fallback.
    CheckFailed(i32),
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
            // The rendered long help (printed by `home_menu_or_usage`) IS the
            // operator output; this Display is a terse fallback only.
            CliError::Usage => write!(f, "no subcommand given (run with --help)"),
            // The check handler already printed the per-service table + verdict;
            // this Display is a terse fallback only.
            CliError::CheckFailed(code) => {
                write!(f, "check failed (exit {code}): one or more selected checks were unhealthy")
            }
        }
    }
}

impl std::error::Error for CliError {}
