//! The declarative `console.config.toml` model (CLI-builder Wave 2 / CONFIG-TOML,
//! SVC-SELECT, BYO) + its DETERMINISTIC mapping to the artifacts Wave 1 consumes.
//!
//! An operator describes the whole stack in ONE file: which of the five Ory
//! services run `in-stack`, which are `byo` (bring-your-own external instance),
//! which are `off`, plus the per-feature enable set. This module parses that file
//! and emits — by pure functions, no I/O — the three Wave-1 artifacts:
//!
//!   * `to_env_pairs()`        → the `.env` lines: a `CONSOLE_SERVICE_<SVC>` line
//!                               for EVERY service, plus the admin-URL override
//!                               keys for `byo` services ONLY (in-stack uses the
//!                               compose default; off emits no URL).
//!   * `to_compose_profiles()` → the `svc-*` profile names for the `in-stack`
//!                               services ONLY (byo/off have no in-stack container).
//!   * `to_service_seed()`     → the service→mode map the backend reconcile reads.
//!
//! SECURITY (T-CB-B02): this model has NO secret fields. POLIS_API_KEY (the one
//! BYO-Polis secret) is read separately via `bootstrap::read_secret` (env / file /
//! prompt — never argv, never this file). The serialized form therefore can never
//! carry a secret; a round-trip test asserts the absence.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::CliError;

/// The five selectable Ory services, in a stable order (drives the deterministic
/// output ordering of every mapping method).
pub const SERVICES: [&str; 5] = ["kratos", "hydra", "keto", "oathkeeper", "polis"];

/// The per-service selection mode. Serialized to the kebab strings the Wave-1
/// `CONSOLE_SERVICE_*` contract uses (`in-stack` / `byo` / `off`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceMode {
    /// Run the service's container in THIS compose stack (the default). Emits the
    /// `svc-<svc>` profile; no URL override (the compose default is used).
    InStack,
    /// Bring-your-own: do NOT run the in-stack container; point the backend admin
    /// URL(s) at an EXTERNAL instance. Emits the `*_URL` override key(s); no profile.
    Byo,
    /// The service is absent: no container, no URL — the backend cascade-disables
    /// its console feature.
    Off,
}

impl ServiceMode {
    /// The `CONSOLE_SERVICE_*` wire value for this mode.
    fn as_wire(self) -> &'static str {
        match self {
            ServiceMode::InStack => "in-stack",
            ServiceMode::Byo => "byo",
            ServiceMode::Off => "off",
        }
    }
}

/// One service's selection: its `mode` plus the OPTIONAL external URL overrides
/// used in `byo` mode. Every URL field is optional so `in-stack`/`off` entries are
/// `{ mode = "..." }` with nothing else.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub mode: Option<ServiceModeField>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub write_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_url: Option<String>,
}

/// A thin newtype around `ServiceMode` so an UNKNOWN mode string yields a CLEAR
/// parse error (`toml`'s default enum error is opaque) rather than a silent
/// default. Defaults to `in-stack` when the `mode` key is absent entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ServiceModeField(pub ServiceMode);

impl TryFrom<String> for ServiceModeField {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.as_str() {
            "in-stack" => Ok(ServiceModeField(ServiceMode::InStack)),
            "byo" => Ok(ServiceModeField(ServiceMode::Byo)),
            "off" => Ok(ServiceModeField(ServiceMode::Off)),
            other => Err(format!(
                "unknown service mode `{other}` (expected one of: in-stack, byo, off)"
            )),
        }
    }
}

impl From<ServiceModeField> for String {
    fn from(f: ServiceModeField) -> String {
        f.0.as_wire().to_string()
    }
}

/// The `[services]` table — each of the five services, all optional (an absent
/// service defaults to `in-stack`, matching the Wave-1 `CONSOLE_SERVICE_*` unset
/// behavior).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Services {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kratos: Option<ServiceConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hydra: Option<ServiceConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keto: Option<ServiceConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oathkeeper: Option<ServiceConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub polis: Option<ServiceConfig>,
}

impl Services {
    /// The config for one service by canonical name, if present.
    fn get(&self, service: &str) -> Option<&ServiceConfig> {
        match service {
            "kratos" => self.kratos.as_ref(),
            "hydra" => self.hydra.as_ref(),
            "keto" => self.keto.as_ref(),
            "oathkeeper" => self.oathkeeper.as_ref(),
            "polis" => self.polis.as_ref(),
            _ => None,
        }
    }

    /// The effective mode for a service: its declared mode, or `in-stack` when the
    /// service (or its `mode` key) is absent (matches the Wave-1 unset default).
    fn mode_of(&self, service: &str) -> ServiceMode {
        self.get(service)
            .and_then(|c| c.mode)
            .map(|m| m.0)
            .unwrap_or(ServiceMode::InStack)
    }

    /// Set one service's config by canonical name (used by the interactive wizard
    /// to assemble a `ConsoleConfig` from the operator's per-service answers). An
    /// unknown name is a no-op (the SERVICES list is the only caller).
    pub fn set(&mut self, service: &str, cfg: ServiceConfig) {
        match service {
            "kratos" => self.kratos = Some(cfg),
            "hydra" => self.hydra = Some(cfg),
            "keto" => self.keto = Some(cfg),
            "oathkeeper" => self.oathkeeper = Some(cfg),
            "polis" => self.polis = Some(cfg),
            _ => {}
        }
    }
}

/// The always-required Postgres backing store (CLI-builder BYO / IUX-BYO-PG-04).
///
/// Postgres is NOT a member of [`SERVICES`] — it is ALWAYS required (the backend +
/// every Ory service needs a DB), so it is modeled directly on [`ConsoleConfig`]
/// rather than as one of the optional five. Only two modes are valid:
///   * `in-stack` — run the bundled `postgres` container (the `svc-postgres`
///     compose profile); emit NO `POSTGRES_*` override (the compose DSN defaults
///     `@postgres:5432/<db>?sslmode=disable` apply, byte-identical to today).
///   * `byo`      — point every DSN at an EXTERNAL Postgres via `POSTGRES_HOST` /
///     `POSTGRES_PORT` / `POSTGRES_SSLMODE`; the bundled container does NOT run.
///
/// `off` is INVALID for postgres (the stack cannot run without a DB) — it parses
/// to a CLEAR error rather than silently degrading.
///
/// SECURITY (T-BYO-02): this struct has NO `password` field. The DB password stays
/// `POSTGRES_PASSWORD` (generated / read via `read_secret`) + the per-service
/// `*_DB_PASSWORD` in `.env`, NEVER in this TOML. A round-trip test asserts no
/// `password` key ever appears in the serialized form.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostgresConfig {
    /// `in-stack` (default when absent) or `byo`. `off` is rejected at parse time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<PostgresModeField>,
    /// BYO external host (interpolated into `POSTGRES_HOST`). Unset → no override.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// BYO external port (`POSTGRES_PORT`). Unset → the `5432` compose default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<String>,
    /// Reserved per-DB override (the compose DSNs hardcode `/kratos`,`/hydra`,…
    /// paths; `db` is unused unless set, kept for forward-compat). Not emitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub db: Option<String>,
    /// BYO sslmode (`POSTGRES_SSLMODE`, e.g. `require`). Unset → `disable` default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sslmode: Option<String>,
    /// An OPTIONAL full connection string the DB probe may use directly (NEVER
    /// emitted to `.env`; carries no password — operators pass a passwordless URL
    /// or rely on `POSTGRES_PASSWORD`). For probe convenience only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// A newtype around the postgres mode so an UNKNOWN/`off` mode string yields a
/// CLEAR parse error (postgres is mandatory — `off` is not a valid choice).
/// Defaults to `in-stack` when the `mode` key is absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PostgresModeField(pub PostgresMode);

/// The two valid postgres modes (NO `off` — the stack cannot run without a DB).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostgresMode {
    /// The bundled in-stack `postgres` container (svc-postgres profile).
    InStack,
    /// An external/managed Postgres (POSTGRES_HOST/PORT/SSLMODE overrides).
    Byo,
}

impl TryFrom<String> for PostgresModeField {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.as_str() {
            "in-stack" => Ok(PostgresModeField(PostgresMode::InStack)),
            "byo" => Ok(PostgresModeField(PostgresMode::Byo)),
            "off" => Err(
                "postgres mode `off` is invalid — Postgres is always required \
                 (choose `in-stack` for the bundled DB or `byo` for an external one)"
                    .to_string(),
            ),
            other => Err(format!(
                "unknown postgres mode `{other}` (expected one of: in-stack, byo)"
            )),
        }
    }
}

impl From<PostgresModeField> for String {
    fn from(f: PostgresModeField) -> String {
        match f.0 {
            PostgresMode::InStack => "in-stack".to_string(),
            PostgresMode::Byo => "byo".to_string(),
        }
    }
}

/// The `svc-postgres` compose profile name (prepended for in-stack postgres).
pub const SVC_POSTGRES_PROFILE: &str = "svc-postgres";

/// The opt-in `observability` compose profile name (Prometheus + Grafana + Loki +
/// Alloy). Appended to COMPOSE_PROFILES ONLY for `in-stack` observability — NEVER
/// for `byo` (external backends, no in-stack containers) or `off` (the default).
pub const OBSERVABILITY_PROFILE: &str = "observability";

/// The bring-your-own / external observability backing store
/// (quick-260527-k0j). Mirrors the BYO-Postgres / BYO-Ory-service pattern but is
/// NOT a member of [`SERVICES`] (those are the five Ory services). Three modes:
///   * `off`      — the DEFAULT (matches today's opt-in-profile-default-OFF). No
///                  compose profile, no `*_URL`, the `observability` FEATURE OFF.
///                  Emits NOTHING, so a plain `docker compose config` /
///                  `init --defaults` stays byte-identical to today.
///   * `in-stack` — run the bundled Prometheus/Grafana/Loki/Alloy via the
///                  `observability` compose profile (still opt-in) + the
///                  `observability` FEATURE ON.
///   * `byo`      — point the backend at EXTERNAL Prometheus/Loki/Grafana via
///                  `PROMETHEUS_URL`/`LOKI_URL`/`GRAFANA_URL`; do NOT add the
///                  compose profile; the `observability` FEATURE is ON so the
///                  console surfaces work against the external backends.
///
/// SECURITY: this struct has NO secret fields. Prometheus/Loki query endpoints are
/// URL-only (PromQL/LogQL); Grafana auth is its OWN concern (see the byo-Grafana
/// caveat documented in the wizard/orchestrate code comments + the SUMMARY). A
/// round-trip test asserts no secret key ever appears in the serialized form.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    /// `off` (default when absent) / `in-stack` / `byo`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<ObservabilityModeField>,
    /// BYO external Prometheus base URL (`PROMETHEUS_URL`). byo-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prometheus_url: Option<String>,
    /// BYO external Loki base URL (`LOKI_URL`). byo-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loki_url: Option<String>,
    /// BYO external Grafana base URL (`GRAFANA_URL`). byo-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grafana_url: Option<String>,
}

/// A newtype around the observability mode so an UNKNOWN mode string yields a
/// CLEAR parse error. Defaults to `off` when the `mode` key is absent (the locked
/// opt-in-OFF default).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ObservabilityModeField(pub ObservabilityMode);

/// The three valid observability modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservabilityMode {
    /// External Prometheus/Loki/Grafana (PROMETHEUS_URL/LOKI_URL/GRAFANA_URL).
    Byo,
    /// The bundled `observability` compose profile (opt-in).
    InStack,
    /// Absent — the DEFAULT. No profile, no URLs, the feature OFF.
    Off,
}

impl ObservabilityMode {
    /// The wire string for this mode.
    fn as_wire(self) -> &'static str {
        match self {
            ObservabilityMode::Byo => "byo",
            ObservabilityMode::InStack => "in-stack",
            ObservabilityMode::Off => "off",
        }
    }
}

impl TryFrom<String> for ObservabilityModeField {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.as_str() {
            "in-stack" => Ok(ObservabilityModeField(ObservabilityMode::InStack)),
            "byo" => Ok(ObservabilityModeField(ObservabilityMode::Byo)),
            "off" => Ok(ObservabilityModeField(ObservabilityMode::Off)),
            other => Err(format!(
                "unknown observability mode `{other}` (expected one of: in-stack, byo, off)"
            )),
        }
    }
}

impl From<ObservabilityModeField> for String {
    fn from(f: ObservabilityModeField) -> String {
        f.0.as_wire().to_string()
    }
}

/// The `[features]` table — feature key → enabled bool. Stored as a sorted map so
/// the serialized form (and any iteration) is deterministic. An absent `[features]`
/// table yields the locked default set (see [`Features::with_defaults`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Features(pub BTreeMap<String, bool>);

impl Features {
    /// The locked CONTEXT.md default feature set (ON by default vs opt-in OFF).
    /// Applied when `[features]` is absent OR to fill any unspecified keys.
    pub fn with_defaults() -> Self {
        let mut m = BTreeMap::new();
        // ON by default (CONTEXT.md defaults).
        for k in [
            "identities",
            "oauth2",
            "permissions",
            "auth_config",
            "sessions",
            "courier",
            "audit",
            "api_keys",
            "feature_toggles",
            "account_experience",
        ] {
            m.insert(k.to_string(), true);
        }
        // OFF / opt-in by default.
        for k in ["saml", "organizations", "observability", "event_streams"] {
            m.insert(k.to_string(), false);
        }
        Features(m)
    }

    /// Merge: start from the defaults, then apply every explicitly-set key from
    /// `self` (an operator override wins; unspecified keys keep their default).
    fn merged_with_defaults(&self) -> Features {
        let mut base = Features::with_defaults();
        for (k, v) in &self.0 {
            base.0.insert(k.clone(), *v);
        }
        base
    }
}

/// The whole `console.config.toml` document.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsoleConfig {
    #[serde(default)]
    pub services: Services,
    /// The always-required Postgres backing store. Absent → in-stack (the bundled
    /// container), matching the byte-identical compose default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub postgres: Option<PostgresConfig>,
    /// The OPTIONAL observability backing store (Prometheus/Grafana/Loki). Absent →
    /// `off` (the locked opt-in-OFF default), so a plain compose / `--defaults`
    /// emit stays byte-identical to today.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observability: Option<ObservabilityConfig>,
    /// Absent in the file → `None`; `effective_features()` applies the defaults.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub features: Option<Features>,
}

impl ConsoleConfig {
    /// The LOCKED CONTEXT default (the `--defaults` fast path): every one of the
    /// five Ory services `in-stack`, and the locked default feature set (10 ON /
    /// 4 advanced OFF). Each service is written EXPLICITLY (`mode = "in-stack"`)
    /// so the emitted `console.config.toml` is self-documenting + reproducible
    /// (re-applying it is byte-identical), rather than relying on the absent →
    /// in-stack fallback.
    pub fn all_in_stack_default() -> Self {
        let in_stack = || {
            Some(ServiceConfig {
                mode: Some(ServiceModeField(ServiceMode::InStack)),
                ..Default::default()
            })
        };
        ConsoleConfig {
            services: Services {
                kratos: in_stack(),
                hydra: in_stack(),
                keto: in_stack(),
                oathkeeper: in_stack(),
                polis: in_stack(),
            },
            // Postgres explicitly in-stack (the bundled DB; svc-postgres profile).
            postgres: Some(PostgresConfig {
                mode: Some(PostgresModeField(PostgresMode::InStack)),
                ..Default::default()
            }),
            // Observability explicitly OFF — the LOCKED default (opt-in profile,
            // default-OFF). `--defaults` keeps it off so the emit (no profile, no
            // URLs, observability FEATURE off) is byte-identical to today.
            observability: Some(ObservabilityConfig {
                mode: Some(ObservabilityModeField(ObservabilityMode::Off)),
                ..Default::default()
            }),
            features: Some(Features::with_defaults()),
        }
    }

    /// The effective observability mode: the declared mode, or `off` when the
    /// `[observability]` table (or its `mode` key) is absent (the locked
    /// opt-in-OFF default).
    pub fn observability_mode(&self) -> ObservabilityMode {
        self.observability
            .as_ref()
            .and_then(|o| o.mode)
            .map(|m| m.0)
            .unwrap_or(ObservabilityMode::Off)
    }

    /// The effective Postgres mode: the declared mode, or `in-stack` when the
    /// `[postgres]` table (or its `mode` key) is absent (the byte-identical
    /// bundled-DB default).
    pub fn postgres_mode(&self) -> PostgresMode {
        self.postgres
            .as_ref()
            .and_then(|p| p.mode)
            .map(|m| m.0)
            .unwrap_or(PostgresMode::InStack)
    }

    /// The effective mode for one service (public accessor over the internal
    /// `Services::mode_of`) — used by the wizard to interactively pre-fill the
    /// current choice and by orchestration to decide in-stack vs byo handling.
    pub fn mode_of(&self, service: &str) -> ServiceMode {
        self.services.mode_of(service)
    }

    /// The effective feature set: the operator's `[features]` merged onto the
    /// locked defaults, or the bare defaults when `[features]` is absent.
    ///
    /// The `observability` FEATURE flag is DERIVED from the `[observability]` mode
    /// (NOT independently set): `in-stack`/`byo` force it ON (so the console
    /// surfaces work against the bundled or external backends), `off` forces it OFF
    /// — overriding any stale `[features].observability` value so the feature can
    /// never contradict the chosen mode. The default `off` mode keeps the feature
    /// OFF, byte-identical to today.
    pub fn effective_features(&self) -> Features {
        let mut feats = match &self.features {
            Some(f) => f.merged_with_defaults(),
            None => Features::with_defaults(),
        };
        let observability_on =
            !matches!(self.observability_mode(), ObservabilityMode::Off);
        feats.0.insert("observability".to_string(), observability_on);
        feats
    }

    /// The deterministic `(KEY, value)` `.env` list:
    ///   * `CONSOLE_SERVICE_<SVC>=<mode>` for EVERY service (stable SERVICES order);
    ///   * the admin-URL override key(s) for `byo` services ONLY (in-stack uses the
    ///     compose default; off emits no URL).
    /// NEVER emits a secret (POLIS_API_KEY is read separately via read_secret).
    pub fn to_env_pairs(&self) -> Vec<(String, String)> {
        let mut pairs: Vec<(String, String)> = Vec::new();
        // 1. CONSOLE_SERVICE_<SVC> for every service.
        for svc in SERVICES {
            let mode = self.services.mode_of(svc);
            pairs.push((
                format!("CONSOLE_SERVICE_{}", svc.to_ascii_uppercase()),
                mode.as_wire().to_string(),
            ));
        }
        // 2. byo URL overrides only (after all CONSOLE_SERVICE_* for stable layout).
        for svc in SERVICES {
            if self.services.mode_of(svc) != ServiceMode::Byo {
                continue;
            }
            let cfg = self.services.get(svc);
            for (key, val) in byo_url_pairs(svc, cfg) {
                if let Some(v) = val {
                    pairs.push((key.to_string(), v));
                }
            }
        }
        // 3. BYO-Postgres overrides — emit POSTGRES_HOST/PORT/SSLMODE ONLY when
        //    postgres mode is byo AND the field is present (mirrors the byo-URL-
        //    only discipline above). In-stack postgres emits NO override, so the
        //    compose ${VAR:-default} fallbacks render byte-identical to today.
        if self.postgres_mode() == PostgresMode::Byo {
            if let Some(pg) = &self.postgres {
                if let Some(host) = &pg.host {
                    pairs.push(("POSTGRES_HOST".to_string(), host.clone()));
                }
                if let Some(port) = &pg.port {
                    pairs.push(("POSTGRES_PORT".to_string(), port.clone()));
                }
                if let Some(sslmode) = &pg.sslmode {
                    pairs.push(("POSTGRES_SSLMODE".to_string(), sslmode.clone()));
                }
            }
        }
        // 4. BYO-Observability overrides — emit PROMETHEUS_URL/LOKI_URL/GRAFANA_URL
        //    ONLY when observability mode is byo AND the field is present. `in-stack`
        //    uses the compose-default internal URLs (the `observability` profile
        //    containers); `off` (the default) emits NOTHING, so the compose render
        //    is byte-identical to today. NEVER a secret (the model has none; Grafana
        //    auth is its own concern — see the byo-Grafana caveat in wizard.rs).
        if self.observability_mode() == ObservabilityMode::Byo {
            if let Some(obs) = &self.observability {
                if let Some(p) = &obs.prometheus_url {
                    pairs.push(("PROMETHEUS_URL".to_string(), p.clone()));
                }
                if let Some(l) = &obs.loki_url {
                    pairs.push(("LOKI_URL".to_string(), l.clone()));
                }
                if let Some(g) = &obs.grafana_url {
                    pairs.push(("GRAFANA_URL".to_string(), g.clone()));
                }
            }
        }
        pairs
    }

    /// The `svc-*` compose profile names for `in-stack` services ONLY (stable
    /// order). byo/off services have no in-stack container, so no profile.
    pub fn to_compose_profiles(&self) -> Vec<String> {
        let mut profiles: Vec<String> = Vec::new();
        // svc-postgres FIRST when postgres is in-stack (the bundled DB), so the
        // default emit is `svc-postgres,svc-kratos,…`. A byo postgres drops it so
        // the in-stack container + db/init never start.
        if self.postgres_mode() == PostgresMode::InStack {
            profiles.push(SVC_POSTGRES_PROFILE.to_string());
        }
        profiles.extend(
            SERVICES
                .iter()
                .filter(|svc| self.services.mode_of(svc) == ServiceMode::InStack)
                .map(|svc| format!("svc-{svc}")),
        );
        // The opt-in `observability` profile — appended ONLY for `in-stack`
        // observability (the bundled Prometheus/Grafana/Loki/Alloy). `byo` points
        // at external backends (no in-stack container → no profile); `off` (the
        // default) adds nothing, so the default COMPOSE_PROFILES is unchanged.
        if self.observability_mode() == ObservabilityMode::InStack {
            profiles.push(OBSERVABILITY_PROFILE.to_string());
        }
        profiles
    }

    /// The service→mode map the backend reconcile consumes (identical content to
    /// the `CONSOLE_SERVICE_*` pairs, surfaced as a map for tests/callers).
    pub fn to_service_seed(&self) -> BTreeMap<String, ServiceMode> {
        SERVICES
            .iter()
            .map(|svc| (svc.to_string(), self.services.mode_of(svc)))
            .collect()
    }
}

/// The admin-URL override `.env` key(s) for a `byo` service, paired with the
/// operator-supplied value (when present). Mirrors `.env.example` / the compose
/// backend.environment override keys per service.
fn byo_url_pairs<'a>(
    service: &str,
    cfg: Option<&'a ServiceConfig>,
) -> Vec<(&'static str, Option<String>)> {
    let admin = cfg.and_then(|c| c.admin_url.clone());
    let read = cfg.and_then(|c| c.read_url.clone());
    let write = cfg.and_then(|c| c.write_url.clone());
    let public = cfg.and_then(|c| c.public_url.clone());
    let external = cfg.and_then(|c| c.external_url.clone());
    match service {
        "kratos" => vec![("KRATOS_ADMIN_URL", admin)],
        // Hydra carries an optional PUBLIC URL (token revoke) alongside the admin.
        "hydra" => vec![("HYDRA_ADMIN_URL", admin), ("HYDRA_PUBLIC_URL", public)],
        // Keto needs BOTH read + write endpoints.
        "keto" => vec![("KETO_READ_URL", read), ("KETO_WRITE_URL", write)],
        "oathkeeper" => vec![("OATHKEEPER_API_URL", admin)],
        // Polis: the admin URL + the public OIDC issuer (external). The API key is
        // a SECRET — never emitted here (read_secret handles it separately).
        "polis" => vec![
            ("POLIS_ADMIN_URL", admin),
            ("POLIS_EXTERNAL_URL", external),
        ],
        _ => vec![],
    }
}

/// Parse a `console.config.toml` file into a [`ConsoleConfig`]. An unknown service
/// mode (or malformed TOML) yields a clear [`CliError::Io`] parse error.
pub fn load_config(path: &str) -> Result<ConsoleConfig, CliError> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| CliError::Io(format!("reading config {path}: {e}")))?;
    parse_config(&raw)
}

/// Parse a `console.config.toml` document from a string (the testable core of
/// [`load_config`]).
pub fn parse_config(raw: &str) -> Result<ConsoleConfig, CliError> {
    toml::from_str::<ConsoleConfig>(raw)
        .map_err(|e| CliError::Io(format!("parsing console.config.toml: {e}")))
}

/// Serialize a [`ConsoleConfig`] back to a TOML document (the `--config` re-apply /
/// round-trip contract). The output carries NO secret (the model has none).
pub fn to_toml_string(config: &ConsoleConfig) -> Result<String, CliError> {
    toml::to_string_pretty(config)
        .map_err(|e| CliError::Io(format!("serializing console.config.toml: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A representative config: kratos in-stack, hydra byo (with URLs), keto off,
    /// oathkeeper absent (→ in-stack default), polis byo (admin + external).
    fn sample_toml() -> &'static str {
        r#"
[services.kratos]
mode = "in-stack"

[services.hydra]
mode = "byo"
admin_url = "https://hydra.ext.example/admin"
public_url = "https://hydra.ext.example"

[services.keto]
mode = "off"

[services.polis]
mode = "byo"
admin_url = "https://polis.ext.example"
external_url = "https://sso.example.com"

[features]
saml = true
observability = false
"#
    }

    #[test]
    fn config_model_parses_services_and_modes() {
        let cfg = parse_config(sample_toml()).expect("sample must parse");
        assert_eq!(cfg.services.mode_of("kratos"), ServiceMode::InStack);
        assert_eq!(cfg.services.mode_of("hydra"), ServiceMode::Byo);
        assert_eq!(cfg.services.mode_of("keto"), ServiceMode::Off);
        // Absent service defaults to in-stack (matches Wave-1 unset default).
        assert_eq!(cfg.services.mode_of("oathkeeper"), ServiceMode::InStack);
        assert_eq!(cfg.services.mode_of("polis"), ServiceMode::Byo);
    }

    #[test]
    fn config_model_unknown_mode_is_a_clear_error() {
        let bad = r#"
[services.kratos]
mode = "sometimes"
"#;
        let err = parse_config(bad).expect_err("unknown mode must error");
        let msg = err.to_string();
        assert!(msg.contains("sometimes"), "msg should name the bad mode: {msg}");
        assert!(msg.contains("in-stack"), "msg should list valid modes: {msg}");
    }

    #[test]
    fn config_model_to_env_pairs_is_deterministic_and_byo_only_urls() {
        let cfg = parse_config(sample_toml()).unwrap();
        let pairs = cfg.to_env_pairs();
        let map: std::collections::HashMap<_, _> = pairs.iter().cloned().collect();

        // CONSOLE_SERVICE_* for EVERY service, with the right modes.
        assert_eq!(map.get("CONSOLE_SERVICE_KRATOS").map(String::as_str), Some("in-stack"));
        assert_eq!(map.get("CONSOLE_SERVICE_HYDRA").map(String::as_str), Some("byo"));
        assert_eq!(map.get("CONSOLE_SERVICE_KETO").map(String::as_str), Some("off"));
        assert_eq!(map.get("CONSOLE_SERVICE_OATHKEEPER").map(String::as_str), Some("in-stack"));
        assert_eq!(map.get("CONSOLE_SERVICE_POLIS").map(String::as_str), Some("byo"));

        // byo URL overrides present ONLY for byo services.
        assert_eq!(map.get("HYDRA_ADMIN_URL").map(String::as_str), Some("https://hydra.ext.example/admin"));
        assert_eq!(map.get("HYDRA_PUBLIC_URL").map(String::as_str), Some("https://hydra.ext.example"));
        assert_eq!(map.get("POLIS_ADMIN_URL").map(String::as_str), Some("https://polis.ext.example"));
        assert_eq!(map.get("POLIS_EXTERNAL_URL").map(String::as_str), Some("https://sso.example.com"));

        // in-stack (kratos) → NO admin URL override; off (keto) → NO URL.
        assert!(!map.contains_key("KRATOS_ADMIN_URL"), "in-stack must not emit a URL");
        assert!(!map.contains_key("KETO_READ_URL"), "off must not emit a URL");
        assert!(!map.contains_key("KETO_WRITE_URL"), "off must not emit a URL");
        assert!(!map.contains_key("OATHKEEPER_API_URL"), "in-stack must not emit a URL");

        // Deterministic: the first five entries are the CONSOLE_SERVICE_* lines in
        // the stable SERVICES order.
        let first_five: Vec<&str> = pairs.iter().take(5).map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            first_five,
            vec![
                "CONSOLE_SERVICE_KRATOS",
                "CONSOLE_SERVICE_HYDRA",
                "CONSOLE_SERVICE_KETO",
                "CONSOLE_SERVICE_OATHKEEPER",
                "CONSOLE_SERVICE_POLIS",
            ]
        );
        // Re-running yields an identical vector (pure function).
        assert_eq!(pairs, cfg.to_env_pairs());
    }

    #[test]
    fn config_model_to_compose_profiles_is_in_stack_only() {
        let cfg = parse_config(sample_toml()).unwrap();
        // svc-postgres FIRST (no [postgres] table → in-stack default), then kratos
        // in-stack + oathkeeper (absent → in-stack). NOT hydra/polis (byo) or keto (off).
        assert_eq!(
            cfg.to_compose_profiles(),
            vec![
                "svc-postgres".to_string(),
                "svc-kratos".to_string(),
                "svc-oathkeeper".to_string()
            ]
        );
    }

    #[test]
    fn config_model_to_service_seed_matches_console_service_pairs() {
        let cfg = parse_config(sample_toml()).unwrap();
        let seed = cfg.to_service_seed();
        assert_eq!(seed.get("kratos"), Some(&ServiceMode::InStack));
        assert_eq!(seed.get("hydra"), Some(&ServiceMode::Byo));
        assert_eq!(seed.get("keto"), Some(&ServiceMode::Off));
        assert_eq!(seed.get("oathkeeper"), Some(&ServiceMode::InStack));
        assert_eq!(seed.get("polis"), Some(&ServiceMode::Byo));
        assert_eq!(seed.len(), 5);
    }

    #[test]
    fn config_model_absent_features_applies_defaults() {
        // No [features] table at all → the locked defaults.
        let cfg = parse_config(r#"[services.kratos]
mode = "in-stack"
"#)
        .unwrap();
        let feats = cfg.effective_features();
        assert_eq!(feats.0.get("identities"), Some(&true), "ON by default");
        assert_eq!(feats.0.get("saml"), Some(&false), "OFF by default");
        assert_eq!(feats.0.get("organizations"), Some(&false), "OFF by default");
    }

    #[test]
    fn config_model_features_override_merges_onto_defaults() {
        let cfg = parse_config(sample_toml()).unwrap();
        let feats = cfg.effective_features();
        // operator turned saml ON.
        assert_eq!(feats.0.get("saml"), Some(&true));
        // observability explicitly OFF (matches default but proves the merge).
        assert_eq!(feats.0.get("observability"), Some(&false));
        // an unspecified ON-default key keeps its default.
        assert_eq!(feats.0.get("oauth2"), Some(&true));
    }

    // --- BYO-Postgres (IUX-BYO-PG-04) ---------------------------------------

    #[test]
    fn postgres_absent_defaults_in_stack_emits_no_override_and_svc_postgres_first() {
        // No [postgres] table → in-stack default.
        let cfg = parse_config(
            r#"[services.kratos]
mode = "in-stack"
"#,
        )
        .unwrap();
        assert_eq!(cfg.postgres_mode(), PostgresMode::InStack);

        let map: std::collections::HashMap<_, _> = cfg.to_env_pairs().into_iter().collect();
        assert!(!map.contains_key("POSTGRES_HOST"), "in-stack → no POSTGRES_HOST");
        assert!(!map.contains_key("POSTGRES_PORT"), "in-stack → no POSTGRES_PORT");
        assert!(!map.contains_key("POSTGRES_SSLMODE"), "in-stack → no POSTGRES_SSLMODE");

        // svc-postgres is FIRST in the profile list.
        let profiles = cfg.to_compose_profiles();
        assert_eq!(profiles.first().map(String::as_str), Some("svc-postgres"));
    }

    #[test]
    fn postgres_byo_emits_overrides_and_drops_svc_postgres() {
        let cfg = parse_config(
            r#"
[postgres]
mode = "byo"
host = "db.ext.example.com"
port = "6543"
sslmode = "require"
"#,
        )
        .unwrap();
        assert_eq!(cfg.postgres_mode(), PostgresMode::Byo);

        let map: std::collections::HashMap<_, _> = cfg.to_env_pairs().into_iter().collect();
        assert_eq!(map.get("POSTGRES_HOST").map(String::as_str), Some("db.ext.example.com"));
        assert_eq!(map.get("POSTGRES_PORT").map(String::as_str), Some("6543"));
        assert_eq!(map.get("POSTGRES_SSLMODE").map(String::as_str), Some("require"));

        // byo → svc-postgres is NOT in the profile list.
        assert!(
            !cfg.to_compose_profiles().contains(&"svc-postgres".to_string()),
            "byo postgres drops svc-postgres"
        );
    }

    #[test]
    fn postgres_byo_omits_absent_override_fields() {
        // byo with only host set → only POSTGRES_HOST emitted (port/sslmode fall
        // back to the compose ${VAR:-default}).
        let cfg = parse_config(
            r#"
[postgres]
mode = "byo"
host = "db.ext"
"#,
        )
        .unwrap();
        let map: std::collections::HashMap<_, _> = cfg.to_env_pairs().into_iter().collect();
        assert_eq!(map.get("POSTGRES_HOST").map(String::as_str), Some("db.ext"));
        assert!(!map.contains_key("POSTGRES_PORT"), "absent port → no override");
        assert!(!map.contains_key("POSTGRES_SSLMODE"), "absent sslmode → no override");
    }

    #[test]
    fn postgres_mode_off_is_a_clear_error() {
        let err = parse_config(
            r#"
[postgres]
mode = "off"
"#,
        )
        .expect_err("postgres off must error");
        let msg = err.to_string();
        assert!(msg.contains("off"), "names the invalid mode: {msg}");
        assert!(msg.contains("always required") || msg.contains("in-stack"), "explains: {msg}");
    }

    #[test]
    fn postgres_round_trips_losslessly_with_no_password_key() {
        let cfg = parse_config(
            r#"
[postgres]
mode = "byo"
host = "db.ext"
port = "5432"
sslmode = "require"
"#,
        )
        .unwrap();
        let serialized = to_toml_string(&cfg).unwrap();
        let reparsed = parse_config(&serialized).unwrap();
        assert_eq!(cfg, reparsed, "[postgres] round-trips losslessly");
        let lower = serialized.to_ascii_lowercase();
        assert!(!lower.contains("password"), "no password key in postgres toml: {serialized}");
        assert!(!lower.contains("secret"), "no secret key in postgres toml: {serialized}");
    }

    #[test]
    fn all_in_stack_default_sets_postgres_in_stack() {
        let cfg = ConsoleConfig::all_in_stack_default();
        assert_eq!(cfg.postgres_mode(), PostgresMode::InStack);
        assert_eq!(
            cfg.to_compose_profiles().first().map(String::as_str),
            Some("svc-postgres"),
            "defaults put svc-postgres first"
        );
        // Round-trips (self-documenting reproducible default).
        let s = to_toml_string(&cfg).unwrap();
        assert_eq!(cfg, parse_config(&s).unwrap());
    }

    // --- BYO-Observability (quick-260527-k0j) -------------------------------

    #[test]
    fn observability_absent_defaults_off_emits_nothing_and_feature_off() {
        // No [observability] table → off (the locked default).
        let cfg = parse_config(
            r#"[services.kratos]
mode = "in-stack"
"#,
        )
        .unwrap();
        assert_eq!(cfg.observability_mode(), ObservabilityMode::Off);

        let map: std::collections::HashMap<_, _> = cfg.to_env_pairs().into_iter().collect();
        assert!(!map.contains_key("PROMETHEUS_URL"), "off → no PROMETHEUS_URL");
        assert!(!map.contains_key("LOKI_URL"), "off → no LOKI_URL");
        assert!(!map.contains_key("GRAFANA_URL"), "off → no GRAFANA_URL");

        // No `observability` compose profile (default-OFF, byte-identical to today).
        assert!(
            !cfg.to_compose_profiles().contains(&"observability".to_string()),
            "off → no observability profile"
        );
        // The observability FEATURE is OFF.
        assert_eq!(
            cfg.effective_features().0.get("observability"),
            Some(&false),
            "off mode → feature OFF"
        );
    }

    #[test]
    fn observability_byo_emits_urls_feature_on_no_profile() {
        let cfg = parse_config(
            r#"
[observability]
mode = "byo"
prometheus_url = "https://prom.ext.example"
loki_url = "https://loki.ext.example"
grafana_url = "https://grafana.ext.example"
"#,
        )
        .unwrap();
        assert_eq!(cfg.observability_mode(), ObservabilityMode::Byo);

        let map: std::collections::HashMap<_, _> = cfg.to_env_pairs().into_iter().collect();
        assert_eq!(map.get("PROMETHEUS_URL").map(String::as_str), Some("https://prom.ext.example"));
        assert_eq!(map.get("LOKI_URL").map(String::as_str), Some("https://loki.ext.example"));
        assert_eq!(map.get("GRAFANA_URL").map(String::as_str), Some("https://grafana.ext.example"));

        // byo → external backends, so NO in-stack observability profile.
        assert!(
            !cfg.to_compose_profiles().contains(&"observability".to_string()),
            "byo drops the observability profile"
        );
        // The observability FEATURE is ON (console surfaces work against externals).
        assert_eq!(cfg.effective_features().0.get("observability"), Some(&true));
    }

    #[test]
    fn observability_in_stack_adds_profile_feature_on_no_urls() {
        let cfg = parse_config(
            r#"
[observability]
mode = "in-stack"
"#,
        )
        .unwrap();
        assert_eq!(cfg.observability_mode(), ObservabilityMode::InStack);

        let map: std::collections::HashMap<_, _> = cfg.to_env_pairs().into_iter().collect();
        // in-stack uses the compose-default internal URLs → NO override emitted.
        assert!(!map.contains_key("PROMETHEUS_URL"), "in-stack → no URL override");
        assert!(!map.contains_key("LOKI_URL"), "in-stack → no URL override");
        assert!(!map.contains_key("GRAFANA_URL"), "in-stack → no URL override");

        // in-stack → the `observability` compose profile is appended.
        assert!(
            cfg.to_compose_profiles().contains(&"observability".to_string()),
            "in-stack adds the observability profile"
        );
        // Feature ON.
        assert_eq!(cfg.effective_features().0.get("observability"), Some(&true));
    }

    #[test]
    fn observability_unknown_mode_is_a_clear_error() {
        let err = parse_config(
            r#"
[observability]
mode = "sometimes"
"#,
        )
        .expect_err("unknown observability mode must error");
        let msg = err.to_string();
        assert!(msg.contains("sometimes"), "names the bad mode: {msg}");
        assert!(msg.contains("in-stack"), "lists valid modes: {msg}");
    }

    #[test]
    fn observability_feature_flag_is_derived_from_mode_overriding_stale_features() {
        // A stale [features].observability = true with mode off → feature forced OFF.
        let cfg_off = parse_config(
            r#"
[observability]
mode = "off"
[features]
observability = true
"#,
        )
        .unwrap();
        assert_eq!(
            cfg_off.effective_features().0.get("observability"),
            Some(&false),
            "off mode overrides a stale features.observability=true"
        );

        // A stale [features].observability = false with mode byo → feature forced ON.
        let cfg_byo = parse_config(
            r#"
[observability]
mode = "byo"
prometheus_url = "https://p.ext"
[features]
observability = false
"#,
        )
        .unwrap();
        assert_eq!(
            cfg_byo.effective_features().0.get("observability"),
            Some(&true),
            "byo mode overrides a stale features.observability=false"
        );
    }

    #[test]
    fn observability_byo_omits_absent_url_fields() {
        // byo with only prometheus set → only PROMETHEUS_URL emitted.
        let cfg = parse_config(
            r#"
[observability]
mode = "byo"
prometheus_url = "https://p.ext"
"#,
        )
        .unwrap();
        let map: std::collections::HashMap<_, _> = cfg.to_env_pairs().into_iter().collect();
        assert_eq!(map.get("PROMETHEUS_URL").map(String::as_str), Some("https://p.ext"));
        assert!(!map.contains_key("LOKI_URL"), "absent loki → no override");
        assert!(!map.contains_key("GRAFANA_URL"), "absent grafana → no override");
    }

    #[test]
    fn observability_round_trips_losslessly_with_no_secret_key() {
        let cfg = parse_config(
            r#"
[observability]
mode = "byo"
prometheus_url = "https://p.ext"
loki_url = "https://l.ext"
grafana_url = "https://g.ext"
"#,
        )
        .unwrap();
        let serialized = to_toml_string(&cfg).unwrap();
        let reparsed = parse_config(&serialized).unwrap();
        assert_eq!(cfg, reparsed, "[observability] round-trips losslessly");
        let lower = serialized.to_ascii_lowercase();
        assert!(!lower.contains("password"), "no password key: {serialized}");
        assert!(!lower.contains("secret"), "no secret key: {serialized}");
        assert!(!lower.contains("api_key"), "no api_key: {serialized}");
    }

    #[test]
    fn all_in_stack_default_keeps_observability_off() {
        // The LOCKED default keeps observability off — byte-identical to today.
        let cfg = ConsoleConfig::all_in_stack_default();
        assert_eq!(cfg.observability_mode(), ObservabilityMode::Off);
        assert!(
            !cfg.to_compose_profiles().contains(&"observability".to_string()),
            "--defaults must not add the observability profile"
        );
        let map: std::collections::HashMap<_, _> = cfg.to_env_pairs().into_iter().collect();
        assert!(!map.contains_key("PROMETHEUS_URL"), "--defaults emits no PROMETHEUS_URL");
        assert_eq!(cfg.effective_features().0.get("observability"), Some(&false));
    }

    #[test]
    fn config_model_round_trips_with_no_secret_keys() {
        let cfg = parse_config(sample_toml()).unwrap();
        let serialized = to_toml_string(&cfg).expect("serialize");
        // Round-trip equality (the --config re-apply contract).
        let reparsed = parse_config(&serialized).expect("reparse");
        assert_eq!(cfg, reparsed, "round-trip must be lossless");
        // No secret key may ever appear in the serialized form (T-CB-B02).
        let lower = serialized.to_ascii_lowercase();
        assert!(!lower.contains("api_key"), "no api_key in toml: {serialized}");
        assert!(!lower.contains("secret"), "no secret in toml: {serialized}");
        assert!(!lower.contains("password"), "no password in toml: {serialized}");
    }
}
