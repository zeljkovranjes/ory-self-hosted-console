//! Backend Prometheus `/metrics` exporter (Phase 16, OBS-02).
//!
//! This module installs a process-global [`metrics`] recorder backed by
//! [`metrics_exporter_prometheus`] and exposes a Salvo handler that renders the
//! Prometheus text-exposition format. Prometheus (the opt-in `observability`
//! compose profile) scrapes `GET /metrics` container-to-container on the
//! INTERNAL network — the endpoint is never host-published and is mounted on the
//! ROOT/public subtree (NO auth/CSRF/feature hoop) because a scrape carries no
//! console session. It is internal-only BY TOPOLOGY (INFRA-05), never on the edge.
//!
//! ## The no-per-identity-label rule (T-16-04, the load-bearing invariant)
//!
//! Every metric defined here is a COUNT or a BUCKET keyed ONLY on a
//! low-cardinality, NON-identifying label (e.g. a `result` of `success`/`failure`).
//! NO metric may ever carry an `email`, `identity_id`, `session_id`, `subject`,
//! or any `*_id` label: those are unbounded-cardinality PII that would (a) blow up
//! the Prometheus index and (b) leak who-did-what into a scrape surface. The
//! `backend/tests/metrics.rs` integration test greps the rendered output for those
//! forbidden label KEYS and fails the build if any appears. When adding a counter,
//! keep it aggregate.

use std::sync::OnceLock;

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use salvo::prelude::*;

/// Process-global render handle. Set ONCE by [`install_recorder`]; read by the
/// [`metrics_text`] handler to render the current text-format snapshot. A
/// `OnceLock` (not a `Mutex`) because the handle is cheap to clone and render is
/// internally synchronized by the exporter.
static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

/// Install the process-global Prometheus recorder and stash its render handle.
///
/// Idempotent + re-entrant: builds a recorder, captures the handle, and calls
/// [`metrics::set_global_recorder`]. The global recorder can be set only ONCE per
/// process — so a SECOND call (or a call after a different test already installed
/// one) is tolerated: we keep whatever handle landed in the `OnceLock` first and
/// swallow the "already set" error rather than panicking. This keeps `cargo test`
/// re-entry safe (multiple integration tests build the router in one process)
/// while the binary calls it exactly once at boot.
///
/// After installation the initial console counter families are described +
/// pre-registered (at zero) so a scrape immediately after boot — before any login
/// has happened — still renders the `# HELP`/`# TYPE` lines and a `0` series,
/// rather than an endpoint that silently exposes nothing until first traffic.
pub fn install_recorder() {
    // Build the recorder + handle. `build_recorder` constructs the recorder
    // WITHOUT spawning the exporter's optional HTTP listener / push task (we
    // render through the Salvo handler instead), so no `default-features` runtime
    // is needed.
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();

    // Set the process-global recorder. If one is already installed (a prior call,
    // or another test in the same process), `set_global_recorder` returns Err —
    // we tolerate it so installation is re-entrant. We still record OUR handle in
    // the OnceLock only if it is empty; if a prior install won the race its handle
    // is the live one and renders the same global registry, so either handle is
    // correct.
    match metrics::set_global_recorder(recorder) {
        Ok(()) => {
            // We won — our handle renders the global registry. Store it.
            let _ = HANDLE.set(handle);
        }
        Err(_) => {
            // Someone else installed first. Our `handle` is detached from the
            // live global recorder, so do NOT store it. If the OnceLock is still
            // empty (the winner was an older build that did not store its handle),
            // fall back to storing ours — it is better than an empty render — but
            // in this crate every installer stores its handle, so this is belt+
            // braces only.
            if HANDLE.get().is_none() {
                let _ = HANDLE.set(handle);
            }
        }
    }

    // Describe + pre-register the initial console counter families so a scrape
    // before any traffic still renders them at zero. Counts/buckets ONLY — no
    // per-identity label (T-16-04).
    metrics::describe_counter!(
        "console_login_attempts_total",
        "Total console-operator login attempts, labelled only by aggregate result."
    );
    // Pre-touch both result series at 0 so the family is present from boot.
    metrics::counter!("console_login_attempts_total", "result" => "success").increment(0);
    metrics::counter!("console_login_attempts_total", "result" => "failure").increment(0);

    metrics::describe_counter!(
        "console_setup_completions_total",
        "Total successful first-run console /setup completions."
    );
    metrics::counter!("console_setup_completions_total").increment(0);
}

/// Increment the console login-attempt counter for an aggregate `result`.
///
/// `result` MUST be a low-cardinality constant (`"success"` / `"failure"`) — never
/// an email, identity id, or any per-user value (T-16-04). Callers in the
/// login/setup paths use this as a one-line increment; it is a no-op-safe wrapper
/// over the `metrics` facade (it does nothing until [`install_recorder`] runs).
pub fn record_login_attempt(success: bool) {
    let result = if success { "success" } else { "failure" };
    metrics::counter!("console_login_attempts_total", "result" => result).increment(1);
}

/// Increment the first-run setup-completion counter (no labels — a single global
/// aggregate). One-line increment for the setup success path.
pub fn record_setup_completion() {
    metrics::counter!("console_setup_completions_total").increment(1);
}

/// Salvo handler: render the current Prometheus text-exposition snapshot.
///
/// Mounted internal-only on the ROOT/public subtree (NO auth_guard / csrf_guard /
/// FeatureFlagHoop) — Prometheus scrapes it container-to-container on the internal
/// network; it is never host-published (INFRA-05) and never on the edge surface.
/// The body is COUNTS/BUCKETS only (no per-identity label, T-16-04). If the
/// recorder was never installed (should not happen in the binary, which installs
/// at boot), it renders an empty body with the same content type rather than 500.
#[handler]
pub async fn metrics_text(res: &mut Response) {
    let body = HANDLE.get().map(|h| h.render()).unwrap_or_default();
    res.status_code(StatusCode::OK);
    // Prometheus text exposition is served as text/plain. (The dedicated
    // `version=0.0.4` parameter is optional; plain text/plain is accepted by every
    // Prometheus scraper.)
    res.render(Text::Plain(body));
}
