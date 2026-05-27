//! GUIDED `edit` command group (CLI-09) — SCAFFOLD.
//!
//! The clap variant + action enum ([`crate::EditAction`]) and this dispatch entry
//! point are scaffolded in Wave 2 so `lib.rs` stays single-writer for the command
//! tree; the per-command bodies land in Wave 3:
//!   * `edit features` — the `[x]`/`[ ]` checkbox list (Req 2), applied via the
//!     EXISTING PUT `/api/console/features/{key}` route (never a direct DB write).
//!   * `edit services` / `edit config` — re-pick / re-edit, then re-write
//!     `console.config.toml` + `.env` through the EXISTING config/emit writers.
//!
//! Until then [`run_edit`] returns a clear "not yet implemented" error — it adds
//! NO new writer (the single-writer invariant holds trivially for a no-op stub).

use crate::ui::Ui;
use crate::{CliError, EditAction};

/// Dispatch an `edit` action. SCAFFOLD: returns `Unsupported` until Wave 3 fills
/// the per-command bodies. Adds NO new writer.
pub async fn run_edit(
    _action: EditAction,
    _api_url: &str,
    _api_key: Option<&str>,
    _ui: Ui,
) -> Result<(), CliError> {
    Err(CliError::Unsupported(
        "`edit` is not yet implemented (lands in a later wave)".into(),
    ))
}
