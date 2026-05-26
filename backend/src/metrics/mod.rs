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

use std::sync::{Once, OnceLock};

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use salvo::prelude::*;

/// Process-global render handle. Set ONCE by [`install_recorder`]; read by the
/// [`metrics_text`] handler to render the current text-format snapshot. A
/// `OnceLock` (not a `Mutex`) because the handle is cheap to clone and render is
/// internally synchronized by the exporter.
static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();
/// Guards the one-time install. `Once::call_once` BLOCKS every concurrent caller
/// until the first one has FULLY completed (recorder set + handle stored + console
/// families described/pre-registered), so a handler that calls `metrics_text` from
/// another thread can never observe a half-installed state (an empty `HANDLE` or
/// unregistered families). This is what makes the multi-test, multi-thread
/// `cargo test` run deterministic — the prior `set_global_recorder`+`HANDLE.set`
/// split had a window where a loser thread could render before the winner stored
/// its handle.
static INSTALL: Once = Once::new();

/// Install the process-global Prometheus recorder and stash its render handle.
///
/// Idempotent + re-entrant + thread-safe: the body runs EXACTLY ONCE (guarded by
/// a [`Once`]); a second call (or a concurrent call from another test in the same
/// process) is a no-op that returns only AFTER the first install has fully
/// completed. The global recorder can be set only once per process, so this is the
/// correct single-install discipline; the binary calls it once at boot while the
/// integration suite may call it from several tests in one process.
///
/// On install the initial console counter families are described + pre-registered
/// (at zero) so a scrape immediately after boot — before any login has happened —
/// still renders the `# HELP`/`# TYPE` lines and a `0` series, rather than an
/// endpoint that silently exposes nothing until first traffic.
pub fn install_recorder() {
    INSTALL.call_once(|| {
        // Build the recorder + handle. `build_recorder` constructs the recorder
        // WITHOUT the exporter's optional HTTP listener / push task (we render
        // through the Salvo handler instead), so no `default-features` runtime is
        // needed.
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();

        // Set the process-global recorder. In a normal process this is the FIRST
        // and only install, so it succeeds. If some OTHER code already installed a
        // global recorder (not the case in this crate), the error is tolerated and
        // we still store our handle as a best-effort render source.
        let _ = metrics::set_global_recorder(recorder);
        let _ = HANDLE.set(handle);

        // Describe + pre-register the console counter families (counts/buckets
        // ONLY — no per-identity label, T-16-04) so a scrape before any traffic
        // still renders them at zero.
        metrics::describe_counter!(
            "console_login_attempts_total",
            "Total console-operator login attempts, labelled only by aggregate result."
        );
        metrics::counter!("console_login_attempts_total", "result" => "success").increment(0);
        metrics::counter!("console_login_attempts_total", "result" => "failure").increment(0);

        metrics::describe_counter!(
            "console_setup_completions_total",
            "Total successful first-run console /setup completions."
        );
        metrics::counter!("console_setup_completions_total").increment(0);
    });
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
