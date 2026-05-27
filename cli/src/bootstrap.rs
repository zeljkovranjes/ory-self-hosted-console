//! BOOTSTRAP-mode handlers (CLI-04/06) — FILESYSTEM ONLY (+ one optional
//! single-writer `/setup` HTTP call for `admin create --via-setup`).
//!
//! These run pre-/at-boot, where there is no runtime config route to go through.
//! They write ONLY ALREADY-gitignored paths (`.env`, `/secrets/*`) and NEVER echo
//! the secret they wrote (BACK-07 / T-19-13). Secrets are read from an env var, a
//! `--*-file` path, or an interactive hidden prompt — NEVER an argv value
//! (T-19-10 / Pitfall 2).
//!
//! The DEFAULT build carries NO `sqlx`: the offline DB-direct admin path
//! (`admin create` without `--via-setup`, `admin reset-password`) is gated behind
//! the OFF-by-default `offline-admin` feature so the default CLI is provably never
//! a second writer of the console DB (T-19-11 / Pitfall 4).

use std::io::IsTerminal;
use std::path::Path;

use crate::ui::Prompter;
use crate::{AdminAction, BootstrapAction, CliError, GithubAction, OauthAction};

/// Filename fragments the bootstrap writer is allowed to target. Every write
/// asserts the resolved path matches one of these gitignored patterns (T-19-12 /
/// Pitfall 3) so a stray target can never leak a secret into git.
///
/// Mirrors `.gitignore`: `.env` + `.env.*` (anywhere) and any path under a
/// `secrets/` directory. The check is intentionally conservative — a path that
/// does not look gitignored is REFUSED rather than written.
pub(crate) fn is_gitignored_secret_path(path: &str) -> bool {
    let norm = path.replace('\\', "/");
    let file = norm.rsplit('/').next().unwrap_or(&norm);
    // `.env` or `.env.<anything>` (the `.env.example` template is the only
    // tracked exception and the writer never targets it).
    let is_env = file == ".env" || file.starts_with(".env.");
    // Anything inside a `secrets/` directory.
    let in_secrets = norm.contains("/secrets/") || norm.starts_with("secrets/");
    (is_env && file != ".env.example") || in_secrets
}

/// Read a secret from (1) a `--*-file` path, (2) an env var, or (3) an
/// interactive hidden-ish prompt — in that order. NEVER from argv. The value is
/// never logged. Used by `oauth github set`, `sso add-oidc`, `rotate secrets`,
/// and the offline admin path.
pub fn read_secret(
    file: Option<&str>,
    env_var: &str,
    label: &str,
) -> Result<String, CliError> {
    if let Some(path) = file {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| CliError::Io(format!("reading {label} file {path}: {e}")))?;
        let trimmed = raw.trim_end_matches(['\r', '\n']).to_string();
        if trimmed.is_empty() {
            return Err(CliError::Io(format!("{label} file {path} is empty")));
        }
        reject_control_chars(&trimmed, label)?;
        return Ok(trimmed);
    }
    if let Ok(v) = std::env::var(env_var) {
        if !v.is_empty() {
            reject_control_chars(&v, label)?;
            return Ok(v);
        }
    }
    // Interactive fallback (Phase 20 / CLI-07 + T-20-SECRET-ECHO): on an attended
    // terminal we now use the `ui` masked Password widget, so the typed value is
    // NOT echoed. We gate on BOTH stdout+stderr being attended (the same predicate
    // `ui::resolve_mode` uses for Rich) so a piped/non-TTY caller can NEVER block on
    // the widget — it falls through to the clear "set {env}/--*-file" error below.
    // The file → env → prompt PRECEDENCE above is UNCHANGED; only the prompt UI of
    // this final branch changed (no new argv flag, no env/file behavior change).
    let attended = std::io::stdin().is_terminal()
        && console::user_attended()
        && console::user_attended_stderr();
    if attended {
        let prompter = crate::ui::DialoguerPrompter;
        let value = prompter.password(&format!("{label} (hidden)"))?;
        let trimmed = value.trim_end_matches(['\r', '\n']).to_string();
        if trimmed.is_empty() {
            return Err(CliError::Io(format!("no {label} provided")));
        }
        reject_control_chars(&trimmed, label)?;
        return Ok(trimmed);
    }
    Err(CliError::Io(format!(
        "no {label} provided — set {env_var} or pass the matching --*-file path (never an argv value)"
    )))
}

/// WR-01: reject any value carrying an embedded newline / carriage-return / NUL.
/// `upsert_env` writes `KEY=value` lines verbatim, so a value with an internal
/// `\n` (a CRLF-corrupted file, a multi-line paste) would otherwise inject
/// arbitrary additional `.env` keys (e.g. clobber `POSTGRES_PASSWORD`). We refuse
/// LOUDLY rather than silently mangle the file. (Trailing `\r`/`\n` is already
/// stripped by the trims above; this catches the INTERNAL ones.)
fn reject_control_chars(value: &str, label: &str) -> Result<(), CliError> {
    if value.contains(['\n', '\r', '\0']) {
        return Err(CliError::Io(format!(
            "{label} must not contain newlines or NUL bytes (would corrupt the .env / inject other keys)"
        )));
    }
    Ok(())
}

/// Upsert a set of `KEY=value` pairs into a `.env`-style file, preserving every
/// other line. Writes atomically (temp file + rename) into a gitignored path
/// ONLY. The secret values are never printed.
pub(crate) fn upsert_env(env_file: &str, pairs: &[(&str, &str)]) -> Result<(), CliError> {
    if !is_gitignored_secret_path(env_file) {
        return Err(CliError::Io(format!(
            "refusing to write {env_file}: not a gitignored .env/secret path"
        )));
    }

    // WR-01 (defense-in-depth): every pair value is written as a verbatim
    // `KEY=value` line, so a value (or key) carrying a newline / NUL would inject
    // unrelated env keys. Reject before touching the file — `read_secret` already
    // guards the secret-bearing values, this also covers non-secret keys/values
    // (e.g. a client id) routed straight to `upsert_env`.
    for (k, v) in pairs {
        if k.contains(['\n', '\r', '\0', '=']) {
            return Err(CliError::Io(format!(
                "refusing to write {env_file}: env key contains a newline, NUL, or '='"
            )));
        }
        if v.contains(['\n', '\r', '\0']) {
            return Err(CliError::Io(format!(
                "refusing to write {env_file}: value for {k} contains a newline or NUL (would inject other env keys)"
            )));
        }
    }

    // Read the existing file (absent = start empty).
    let existing = std::fs::read_to_string(env_file).unwrap_or_default();

    let keys: Vec<&str> = pairs.iter().map(|(k, _)| *k).collect();
    let mut out_lines: Vec<String> = Vec::new();
    let mut written = vec![false; pairs.len()];

    for line in existing.lines() {
        // Upsert: replace an existing `KEY=...` line in place; keep everything else.
        let key_of = line.split_once('=').map(|(k, _)| k.trim());
        if let Some(k) = key_of {
            if let Some(idx) = keys.iter().position(|target| *target == k) {
                out_lines.push(format!("{}={}", pairs[idx].0, pairs[idx].1));
                written[idx] = true;
                continue;
            }
        }
        out_lines.push(line.to_string());
    }
    // Append any keys not already present.
    for (idx, (k, v)) in pairs.iter().enumerate() {
        if !written[idx] {
            out_lines.push(format!("{k}={v}"));
        }
    }

    let mut content = out_lines.join("\n");
    content.push('\n');

    // Atomic-ish write: temp file in the same dir + rename.
    let target = Path::new(env_file);
    let dir = target.parent().filter(|p| !p.as_os_str().is_empty());
    let tmp = match dir {
        Some(d) => d.join(format!(
            ".{}.cli-tmp",
            target.file_name().and_then(|s| s.to_str()).unwrap_or("env")
        )),
        None => Path::new(".env.cli-tmp").to_path_buf(),
    };
    std::fs::write(&tmp, content.as_bytes())
        .map_err(|e| CliError::Io(format!("writing {}: {e}", tmp.display())))?;
    std::fs::rename(&tmp, target)
        .map_err(|e| CliError::Io(format!("renaming into {env_file}: {e}")))?;
    Ok(())
}

/// `oauth github set` (CLI-04) — write GITHUB_OAUTH_CLIENT_ID/_SECRET into `.env`.
///
/// The backend reads BOTH at boot (`config.rs`); `github` is `Some` only when
/// both are set + non-empty. The secret is read from a file/env/prompt and is
/// NEVER echoed.
pub fn oauth(action: OauthAction) -> Result<(), CliError> {
    let OauthAction::Github { action } = action;
    match action {
        GithubAction::Set {
            client_id,
            client_secret_file,
            env_file,
        } => {
            let secret = read_secret(
                client_secret_file.as_deref(),
                "GITHUB_OAUTH_CLIENT_SECRET",
                "GitHub OAuth client secret",
            )?;
            upsert_env(
                &env_file,
                &[
                    ("GITHUB_OAUTH_CLIENT_ID", &client_id),
                    ("GITHUB_OAUTH_CLIENT_SECRET", &secret),
                ],
            )?;
            // NEVER print the secret — only confirm the keys + target.
            println!(
                "wrote GITHUB_OAUTH_CLIENT_ID + GITHUB_OAUTH_CLIENT_SECRET to {env_file} (secret not echoed)"
            );
            Ok(())
        }
    }
}

/// `bootstrap token` / `bootstrap rotate-secrets` (CLI-06).
pub fn bootstrap(action: BootstrapAction) -> Result<(), CliError> {
    match action {
        BootstrapAction::Token => reprint_token(),
        BootstrapAction::RotateSecrets {
            which,
            value_file,
            env_file,
        } => rotate_secret(&which, value_file.as_deref(), &env_file),
    }
}

/// "reprint" the bootstrap token = REGENERATE (Pitfall 5: only a one-way SHA-256
/// hash is stored, so the original is unrecoverable). The offline mint-and-store
/// path needs a DB connection and is gated behind `offline-admin`; without it we
/// print clear guidance to use the boot-time stdout token.
fn reprint_token() -> Result<(), CliError> {
    #[cfg(feature = "offline-admin")]
    {
        offline::regenerate_bootstrap_token()
    }
    #[cfg(not(feature = "offline-admin"))]
    {
        Err(CliError::Unsupported(
            "the bootstrap token's stored value is a one-way SHA-256 hash and cannot be reprinted. \
             It is minted + printed once at backend boot — read it from the backend's startup logs. \
             To REGENERATE a new token offline (only valid while the console is uninitialized), \
             rebuild the CLI with `--features offline-admin` and a reachable DATABASE_URL."
                .into(),
        ))
    }
}

/// `rotate secrets` (CLI-06) — upsert a rotated secret into `.env` (A4). The new
/// value is read from a file/env/prompt; the operator restarts the affected
/// service afterwards (documented follow-up). Writes a gitignored path only.
fn rotate_secret(
    which: &str,
    value_file: Option<&str>,
    env_file: &str,
) -> Result<(), CliError> {
    // Map the logical secret name to its `.env` key + matching env var.
    //
    // WR-02: `session-secret` was previously mapped to `CONSOLE_SESSION_SECRET`,
    // but the backend (`backend/src/config.rs`) NEVER reads such a key — console
    // sessions are opaque random tokens whose SHA-256 hash lives in the `sessions`
    // table, so there is NO session-signing secret to rotate. Rotating it was a
    // silent no-op that gave false confidence. We DROP the option and tell the
    // operator the real invalidation lever (clear the `sessions` table). Only
    // `db-password` (POSTGRES_PASSWORD) and `github-secret`
    // (GITHUB_OAUTH_CLIENT_SECRET) are real backend/compose vars.
    let (env_key, src_env) = match which {
        "db-password" => ("POSTGRES_PASSWORD", "POSTGRES_PASSWORD_NEW"),
        "github-secret" => ("GITHUB_OAUTH_CLIENT_SECRET", "GITHUB_OAUTH_CLIENT_SECRET_NEW"),
        "session-secret" => {
            return Err(CliError::Unsupported(
                "there is no session-signing secret to rotate: console sessions are opaque \
                 random tokens hashed in the `sessions` table, not signed with an env secret. \
                 To invalidate all sessions (force re-login), clear the `sessions` table \
                 (e.g. `docker compose exec postgres psql -U $POSTGRES_USER -d console -c \
                 'TRUNCATE sessions;'`) — no `.env` rotation applies."
                    .into(),
            ))
        }
        other => {
            return Err(CliError::Unsupported(format!(
                "unknown secret `{other}` (expected: db-password | github-secret). \
                 `session-secret` is not rotatable — clear the `sessions` table instead."
            )))
        }
    };
    let value = read_secret(value_file, src_env, &format!("new {which}"))?;
    upsert_env(env_file, &[(env_key, &value)])?;
    println!(
        "rotated {which} ({env_key}) in {env_file} (value not echoed). Restart the affected service to apply."
    );
    Ok(())
}

/// `admin create` (non-list) / `admin reset-password` (CLI-06).
///
/// `create --via-setup` drives the first-run `POST /setup` route (the backend is
/// the single writer of the admin). The offline DB-direct path (create without
/// `--via-setup`, and reset-password) needs `offline-admin`.
pub async fn admin(
    api_url: &str,
    api_key: Option<&str>,
    action: AdminAction,
) -> Result<(), CliError> {
    match action {
        AdminAction::List => unreachable!("admin list is dispatched to online::admin_list"),
        AdminAction::Create {
            email,
            name,
            via_setup,
            password_file,
            token_file,
        } => {
            let password = read_secret(
                password_file.as_deref(),
                "CONSOLE_ADMIN_PASSWORD",
                "admin password",
            )?;
            if via_setup {
                // SINGLE-WRITER path: the backend creates the admin via /setup.
                // CR-01: forward `name` — the backend's `SetupRequest.name` is
                // non-optional, so a body without it 400s before the token check.
                return setup_via_http(
                    api_url,
                    api_key,
                    &name,
                    &email,
                    &password,
                    token_file.as_deref(),
                )
                .await;
            }
            #[cfg(feature = "offline-admin")]
            {
                offline::create_admin(&email, &name, &password).await
            }
            #[cfg(not(feature = "offline-admin"))]
            {
                let _ = (&email, &name, &password);
                Err(CliError::Unsupported(
                    "offline admin create requires the `offline-admin` build feature + a reachable \
                     DATABASE_URL. Prefer `admin create --via-setup` (drives the backend's first-run \
                     /setup route, keeping the backend the single writer)."
                        .into(),
                ))
            }
        }
        AdminAction::ResetPassword {
            email,
            password_file,
        } => {
            let password = read_secret(
                password_file.as_deref(),
                "CONSOLE_ADMIN_PASSWORD",
                "admin password",
            )?;
            #[cfg(feature = "offline-admin")]
            {
                offline::reset_password(&email, &password).await
            }
            #[cfg(not(feature = "offline-admin"))]
            {
                let _ = (&email, &password);
                Err(CliError::Unsupported(
                    "admin reset-password is an offline DB-direct operation — rebuild the CLI with \
                     `--features offline-admin` and a reachable DATABASE_URL. (No remote password-reset \
                     route exists, by design: it would add a new attack surface.)"
                        .into(),
                ))
            }
        }
    }
}

/// Drive `POST /setup` (first-run only). The bootstrap token is read from
/// env/file/prompt (never argv); the body shape mirrors `auth::setup`.
async fn setup_via_http(
    api_url: &str,
    _api_key: Option<&str>,
    name: &str,
    email: &str,
    password: &str,
    token_file: Option<&str>,
) -> Result<(), CliError> {
    let token = read_secret(token_file, "CONSOLE_BOOTSTRAP_TOKEN", "bootstrap token")?;
    let url = format!("{}/setup", api_url.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .build()
        .map_err(|e| CliError::Http(e.to_string()))?;
    let resp = client
        .post(url)
        // CR-01: `name` is REQUIRED by the backend `SetupRequest` (non-optional);
        // omitting it 400s ("invalid JSON body") before the token is verified.
        .json(&serde_json::json!({
            "name": name,
            "token": token,
            "email": email,
            "password": password,
        }))
        .send()
        .await
        .map_err(|e| CliError::Http(e.to_string()))?;
    let status = resp.status();
    if status.is_success() {
        println!("first-run admin `{email}` created via /setup (single-writer path)");
        Ok(())
    } else {
        let body = resp.text().await.unwrap_or_default();
        Err(CliError::Backend(format!(
            "/setup returned {status}: {} (the route 404s once an admin exists)",
            body.trim()
        )))
    }
}

/// The offline DB-direct admin path — compiled ONLY with `--features offline-admin`.
/// Reuses the backend's Argon2id regime so the stored hash is byte-compatible.
#[cfg(feature = "offline-admin")]
mod offline {
    use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
    use argon2::Argon2;

    use crate::CliError;

    fn database_url() -> Result<String, CliError> {
        std::env::var("DATABASE_URL").map_err(|_| {
            CliError::Io("DATABASE_URL is required for the offline-admin path".into())
        })
    }

    /// Argon2id PHC hash — the SAME algorithm/params as `auth::password::hash_password`.
    fn hash_password(password: &str) -> Result<String, CliError> {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| CliError::Io(format!("hashing password: {e}")))
    }

    /// WR-04: enforce the SAME min-password policy the backend applies on
    /// `/setup` (via the shared `console_core` constant) so an offline-created
    /// admin can never be weaker than a console-created one. Refuse BEFORE any DB
    /// connection or hashing work; never echo the password.
    fn enforce_password_policy(password: &str) -> Result<(), CliError> {
        if !console_core::password_meets_policy(password) {
            return Err(CliError::Io(format!(
                "password must be at least {} characters",
                console_core::MIN_PASSWORD_LEN
            )));
        }
        Ok(())
    }

    pub async fn create_admin(email: &str, name: &str, password: &str) -> Result<(), CliError> {
        // WR-04: policy check first (before DB / hashing), mirroring the backend.
        enforce_password_policy(password)?;
        let pool = sqlx::PgPool::connect(&database_url()?)
            .await
            .map_err(|e| CliError::Io(format!("connecting to DB: {e}")))?;
        let hash = hash_password(password)?;
        sqlx::query("INSERT INTO admins (email, name, password_hash) VALUES ($1, $2, $3)")
            .bind(email)
            .bind(name)
            .bind(&hash)
            .execute(&pool)
            .await
            .map_err(|e| CliError::Io(format!("inserting admin: {e}")))?;
        println!("offline: created admin `{email}` (password not echoed)");
        Ok(())
    }

    pub async fn reset_password(email: &str, password: &str) -> Result<(), CliError> {
        // WR-04: same policy as create / the backend.
        enforce_password_policy(password)?;
        let pool = sqlx::PgPool::connect(&database_url()?)
            .await
            .map_err(|e| CliError::Io(format!("connecting to DB: {e}")))?;
        let hash = hash_password(password)?;
        let res = sqlx::query("UPDATE admins SET password_hash = $1 WHERE email = $2")
            .bind(&hash)
            .bind(email)
            .execute(&pool)
            .await
            .map_err(|e| CliError::Io(format!("updating admin: {e}")))?;
        if res.rows_affected() == 0 {
            return Err(CliError::Io(format!("no admin with email `{email}`")));
        }
        println!("offline: reset password for `{email}` (password not echoed)");
        Ok(())
    }

    pub fn regenerate_bootstrap_token() -> Result<(), CliError> {
        // A real mint-and-store needs the console_settings schema; this offline
        // stub generates a fresh random token and prints it for the operator to
        // place. (Storing the hash is the backend's job at next boot.)
        use argon2::password_hash::rand_core::RngCore;
        let mut buf = [0u8; 32];
        OsRng.fill_bytes(&mut buf);
        let token = buf.iter().map(|b| format!("{b:02x}")).collect::<String>();
        println!("{token}");
        eprintln!("(regenerated bootstrap token — valid only while the console is uninitialized)");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gitignored_path_recognition() {
        assert!(is_gitignored_secret_path(".env"));
        assert!(is_gitignored_secret_path("./.env"));
        assert!(is_gitignored_secret_path("/app/.env"));
        assert!(is_gitignored_secret_path(".env.local"));
        assert!(is_gitignored_secret_path("secrets/grafana_admin_password"));
        assert!(is_gitignored_secret_path("/run/secrets/x"));
        // NOT gitignored — must be refused.
        assert!(!is_gitignored_secret_path(".env.example"));
        assert!(!is_gitignored_secret_path("config/kratos/kratos.yml"));
        assert!(!is_gitignored_secret_path("settings.txt"));
    }
}
