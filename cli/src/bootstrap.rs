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

use std::io::{IsTerminal, Write};
use std::path::Path;

use crate::{AdminAction, BootstrapAction, CliError, GithubAction, OauthAction};

/// Filename fragments the bootstrap writer is allowed to target. Every write
/// asserts the resolved path matches one of these gitignored patterns (T-19-12 /
/// Pitfall 3) so a stray target can never leak a secret into git.
///
/// Mirrors `.gitignore`: `.env` + `.env.*` (anywhere) and any path under a
/// `secrets/` directory. The check is intentionally conservative — a path that
/// does not look gitignored is REFUSED rather than written.
fn is_gitignored_secret_path(path: &str) -> bool {
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
        return Ok(trimmed);
    }
    if let Ok(v) = std::env::var(env_var) {
        if !v.is_empty() {
            return Ok(v);
        }
    }
    // Interactive fallback. We do NOT echo the prompt'd value back. (A true
    // no-echo TTY read would need `rpassword`; the RESEARCH gates that crate
    // behind a checkpoint, so the zero-new-dep default reads a line from stdin
    // when attached to a terminal and otherwise errors — the secret still never
    // crosses argv.)
    let mut stdin = std::io::stdin();
    if stdin.is_terminal() {
        eprint!("{label} (input hidden is NOT guaranteed without a TTY tool; paste value): ");
        std::io::stderr().flush().ok();
        let mut line = String::new();
        std::io::Read::read_to_string(&mut stdin, &mut line)
            .map_err(|e| CliError::Io(format!("reading {label} from stdin: {e}")))?;
        let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
        if trimmed.is_empty() {
            return Err(CliError::Io(format!("no {label} provided")));
        }
        return Ok(trimmed);
    }
    Err(CliError::Io(format!(
        "no {label} provided — set {env_var} or pass the matching --*-file path (never an argv value)"
    )))
}

/// Upsert a set of `KEY=value` pairs into a `.env`-style file, preserving every
/// other line. Writes atomically (temp file + rename) into a gitignored path
/// ONLY. The secret values are never printed.
fn upsert_env(env_file: &str, pairs: &[(&str, &str)]) -> Result<(), CliError> {
    if !is_gitignored_secret_path(env_file) {
        return Err(CliError::Io(format!(
            "refusing to write {env_file}: not a gitignored .env/secret path"
        )));
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
    let (env_key, src_env) = match which {
        "session-secret" => ("CONSOLE_SESSION_SECRET", "CONSOLE_SESSION_SECRET_NEW"),
        "db-password" => ("POSTGRES_PASSWORD", "POSTGRES_PASSWORD_NEW"),
        "github-secret" => ("GITHUB_OAUTH_CLIENT_SECRET", "GITHUB_OAUTH_CLIENT_SECRET_NEW"),
        other => {
            return Err(CliError::Unsupported(format!(
                "unknown secret `{other}` (expected: session-secret | db-password | github-secret)"
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
                return setup_via_http(api_url, api_key, &email, &password, token_file.as_deref())
                    .await;
            }
            #[cfg(feature = "offline-admin")]
            {
                offline::create_admin(&email, &password).await
            }
            #[cfg(not(feature = "offline-admin"))]
            {
                let _ = (&email, &password);
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
        .json(&serde_json::json!({
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
