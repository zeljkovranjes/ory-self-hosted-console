//! `ory-console` — the optional Ory Self-Hosted Console operator CLI binary.
//!
//! A thin entry point: parse the clap [`Cli`] tree, dispatch via [`console_cli::run`]
//! (ONLINE HTTP client of the backend routes OR BOOTSTRAP `.env`/secret writer),
//! and print an operator-safe error to stderr on failure. All real logic lives in
//! the `console_cli` library crate so the integration tests drive the exact same
//! dispatch without spawning a process.

use clap::Parser;
use console_cli::{run, Cli};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli).await {
        // The error Display is operator-safe and NEVER contains a secret value.
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
