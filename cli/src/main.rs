//! `ory-console` — the optional Ory Self-Hosted Console operator CLI binary.
//!
//! A thin entry point: parse the clap [`Cli`] tree, dispatch via [`console_cli::run`]
//! (ONLINE HTTP client of the backend routes OR BOOTSTRAP `.env`/secret writer),
//! and print an operator-safe error to stderr on failure. All real logic lives in
//! the `console_cli` library crate so the integration tests drive the exact same
//! dispatch without spawning a process.

use clap::Parser;
use console_cli::{run, Cli, CliError};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli).await {
        match e {
            // A bare invocation on a non-TTY: `home_menu_or_usage` already printed
            // the long help to stderr; the LOCKED exit code is 2 (never hang,
            // never 0). `non_tty_never_hangs` pins this.
            CliError::Usage => std::process::exit(2),
            // A read-only `check` verdict (CLI-08b): the handler already rendered
            // the per-service table + the failing-verdict line; `main` maps the
            // health verdict to the process exit code VERBATIM (0 stays Ok; a
            // non-zero code surfaces here). This is the SCRIPTABLE health signal,
            // not an error — so we do NOT print an `error:` prefix.
            CliError::CheckFailed(code) => std::process::exit(code),
            // The error Display is operator-safe and NEVER contains a secret value.
            other => {
                eprintln!("error: {other}");
                std::process::exit(1);
            }
        }
    }
}
