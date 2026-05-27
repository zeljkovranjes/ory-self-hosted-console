//! READ-ONLY `check` command group (CLI-08) — SCAFFOLD.
//!
//! The clap variant + action enum ([`crate::CheckAction`]) and this dispatch
//! entry point are scaffolded in Wave 2 so `lib.rs` stays single-writer for the
//! command tree; the per-command bodies (`status`/`services`/`config`/`features`)
//! land in Wave 3. Until then [`run_check`] returns a clear "not yet implemented"
//! error — it NEVER writes anything (the read-only / no-second-writer invariant,
//! T-20-WRITE, holds trivially for a no-op stub).
//!
//! Wave 3 will additionally expose the PURE verdict core
//! `overall_exit_code(&[probe::ProbeResult]) -> i32` (`0` iff every result is ok)
//! that `check status` maps onto the process exit code (CLI-08b).

use crate::ui::Ui;
use crate::{CheckAction, CliError};

/// Dispatch a `check` action. SCAFFOLD: returns `Unsupported` until Wave 3 fills
/// the per-command bodies. Writes NOTHING.
pub async fn run_check(
    _action: CheckAction,
    _api_url: &str,
    _api_key: Option<&str>,
    _ui: Ui,
) -> Result<(), CliError> {
    Err(CliError::Unsupported(
        "`check` is not yet implemented (lands in a later wave)".into(),
    ))
}
