//! Phase 20 (CLI Operator Experience Redesign) — Wave-0 falsifiable contract.
//!
//! This file is the EXECUTABLE SPECIFICATION for the Phase-20 UX redesign. It is
//! written BEFORE any implementation (Nyquist compliance): every behavior-bearing
//! Phase-20 requirement gets an automated check that exists first, so waves 1–3
//! build against a fixed contract instead of inventing one.
//!
//! The six locked tests (names are LOAD-BEARING — 20-VALIDATION depends on them):
//!   * `edit_features_calls_put_route`        (CLI-09  / NOT ignored — runs today)
//!   * `check_is_read_only_no_mtime_change`   (CLI-08  / Wave 3)
//!   * `check_exit_code_reflects_health`      (CLI-08b / Wave 3)
//!   * `multiselect_defaults_match_current`   (CLI-07b / Wave 1)
//!   * `zero_ansi_when_piped`                 (CLI-07e / Wave 2)
//!   * `non_tty_never_hangs`                  (CLI-07e / Wave 2)
//!
//! ## Forward-referenced (LOCKED) public surface the later waves MUST expose
//!
//! These names are pinned HERE so waves 1–3 implement against a fixed contract.
//! The tests that exercise them are `#[ignore]`-gated with a `"Wave N: …"` reason
//! until the symbol exists, so this file COMPILES against today's surface while
//! still encoding the assertion.
//!
//!   Wave 1 — the pure `ui` diff core (no TTY needed, unit-testable):
//!     * `console_cli::ui::OutputMode`            — `{ Rich, Plain }`
//!     * `console_cli::ui::resolve_mode(text_flag: bool) -> OutputMode`
//!     * `console_cli::ui::feature_default_mask(&Features, &[String]) -> Vec<bool>`
//!         the `[x]`/`[ ]` MultiSelect pre-check mask, indexed parallel to the
//!         ordered key list (Req 2 / CLI-07b).
//!     * `console_cli::ui::diff_features(&before_mask, &after_indices, &ordered_keys)
//!            -> Vec<(String, bool)>`
//!         ONLY the keys whose checked-state changed; a bare Enter (after == before)
//!         yields an EMPTY diff (the Req-2 no-op invariant).
//!
//!   Wave 3 — `check` command group:
//!     * `Cmd::Check` clap variant (read-only `status`/`services`/`config`/`features`)
//!     * `console_cli::check::overall_exit_code(&[probe::ProbeResult]) -> i32`
//!         the PURE verdict core: `0` iff every result `ok`, non-zero otherwise.
//!         (`check status` maps this onto the process exit code; CLI-08b.)
//!     * the `check config --config <PATH>` form (validate, write NOTHING).
//!
//!   Wave 3 — `edit` command group:
//!     * `Cmd::Edit` clap variant (guided `features`/`services`/`config`).
//!       `edit features` MUST route through the EXISTING PUT
//!       `/api/console/features/{key}` (the same route `edit_features_calls_put_route`
//!       pins today) — never a direct DB/YAML write.
//!
//!   Wave 2 — degradation surface:
//!     * the global `--text` flag on `Cli` (forces `OutputMode::Plain`).
//!     * a non-TTY bare invocation prints usage and exits code `2` (never hangs).
//!
//! Conventions mirrored EXACTLY from `cli/tests/cli_commands.rs` (read this
//! session): `mockito::Server::new_async().await` + `.mock(METHOD, PATH)` +
//! `.match_header(...)` + `.match_body(Matcher::Json(...))` + `.with_status(...)`
//! + `.create_async().await`, then `m.assert_async().await`; drive the library
//! dispatch fns directly where possible (NOT a subprocess); the Api-Key header
//! value is `"Api-Key <raw>"`.

use console_cli::{client::ApiClient, online, FeatureAction};

// ─── CLI-09: `edit features` reuses the EXISTING PUT route (runs TODAY) ─────────

/// `edit features`, when it applies a per-key change in Wave 3, MUST route through
/// the SAME PUT `/api/console/features/{key}` `{"enabled":bool}` the day-2 `feature
/// enable` command already uses (per 20-RESEARCH "edit features apply path"). This
/// test PROVES that route contract exists TODAY by driving `online::feature`
/// directly — so Wave 3's `edit features` has a fixed, already-verified apply path
/// to call (no second writer; backend stays the single writer).
///
/// NOT ignored: this exercises today's stable surface and must stay green.
#[tokio::test]
async fn edit_features_calls_put_route() {
    let mut server = mockito::Server::new_async().await;
    let m = server
        .mock("PUT", "/api/console/features/saml")
        .match_header("authorization", "Api-Key k")
        // An ONLINE api-key request is CSRF-exempt — no X-CSRF-Token is sent.
        .match_header("x-csrf-token", mockito::Matcher::Missing)
        .match_body(mockito::Matcher::Json(serde_json::json!({"enabled": true})))
        .with_status(200)
        .with_body(r#"{"key":"saml","enabled":true}"#)
        .create_async()
        .await;

    let client = ApiClient::new(&server.url(), Some("k")).unwrap();
    online::feature(&client, FeatureAction::Enable { key: "saml".into() })
        .await
        .expect("the PUT /api/console/features/{key} apply path must succeed");

    // The matcher asserts EXACT method + path + body + Api-Key header. Wave-3
    // `edit features` MUST route through this same PUT; this proves the contract
    // exists today.
    m.assert_async().await;
}

// ─── CLI-08: `check` is READ-ONLY — no target-file mtime change (Wave 3) ────────

/// CLI-08 acceptance: a `check` run causes NO modification to `.env` /
/// `console.config.toml` (verifiable: no target-file mtime change across the run).
/// This is the very guard that detects a second-writer regression in Wave 3
/// (threat T-20-WRITE). It records each fixture file's mtime, runs `check config`
/// via the library `run()` dispatch, and asserts both mtimes are UNCHANGED.
///
/// DB mtime is covered by the same construction once a DB target is in scope.
#[tokio::test]
#[ignore = "Wave 3: check command (Cmd::Check + `check config --config <PATH>`) not yet implemented"]
async fn check_is_read_only_no_mtime_change() {
    use clap::Parser;
    use console_cli::{run, Cli};

    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join(".env");
    let cfg_path = dir.path().join("console.config.toml");
    std::fs::write(&env_path, "CONSOLE_SERVICE_KRATOS=in-stack\n").unwrap();
    // Minimal VALID console.config.toml (parse_config accepts this shape today).
    std::fs::write(&cfg_path, "[services.kratos]\nmode = \"in-stack\"\n").unwrap();

    let env_mtime_before = std::fs::metadata(&env_path).unwrap().modified().unwrap();
    let cfg_mtime_before = std::fs::metadata(&cfg_path).unwrap().modified().unwrap();

    // Wave 3 will add `check config --config <PATH>` (read-only validation).
    let cli = Cli::try_parse_from([
        "ory-console",
        "check",
        "config",
        "--config",
        cfg_path.to_string_lossy().as_ref(),
    ])
    .expect("`check config --config <PATH>` must parse once Cmd::Check exists");
    // A read-only command may legitimately return Ok (config valid) or an Err
    // (config invalid / unreachable) — EITHER way it must write NOTHING.
    let _ = run(cli).await;

    let env_mtime_after = std::fs::metadata(&env_path).unwrap().modified().unwrap();
    let cfg_mtime_after = std::fs::metadata(&cfg_path).unwrap().modified().unwrap();

    assert_eq!(
        env_mtime_before, env_mtime_after,
        "check must NOT modify .env (read-only / no-second-writer; T-20-WRITE)"
    );
    assert_eq!(
        cfg_mtime_before, cfg_mtime_after,
        "check must NOT modify console.config.toml (read-only; T-20-WRITE)"
    );
}

// ─── CLI-08b: exit code reflects health (Wave 3) ───────────────────────────────

/// CLI-08b acceptance: `check status` exits `0` when all selected services are
/// healthy and non-zero when any is unreachable. This drives the PURE verdict core
/// `check::overall_exit_code(&[ProbeResult]) -> i32` Wave 3 will expose — so the
/// test is deterministic and needs no process exit. (One mockito server stands in
/// for a healthy service, an unroutable TEST-NET-1 address for the unreachable one,
/// but the assertion is on the pure verdict mapping, mirroring `probe::should_block`.)
/// The body forward-references `console_cli::check::overall_exit_code`, which does
/// not exist until Wave 3. The assertion is encoded under the `wave3` cargo feature
/// (off today) so the LOCKED contract is documented inline AND the file compiles
/// against today's surface; the test stays `#[ignore]`-gated regardless.
#[tokio::test]
#[ignore = "Wave 3: check status verdict (console_cli::check::overall_exit_code) not yet implemented"]
async fn check_exit_code_reflects_health() {
    #[cfg(feature = "wave3")]
    {
        use console_cli::check;
        use console_cli::probe::ProbeResult;

        // A healthy service: a mockito server answering 200 on the readiness path.
        let mut healthy = mockito::Server::new_async().await;
        let _ok = healthy
            .mock("GET", "/health/ready")
            .with_status(200)
            .with_body("{}")
            .create_async()
            .await;
        // (The server URL is the realistic source of an ok=true ProbeResult; the
        // verdict core under test is pure, so we assert directly on ProbeResult sets.)
        let healthy_url = format!("{}/health/ready", healthy.url());
        // The unreachable endpoint is reserved TEST-NET-1, port 1 (never routable).
        let unroutable_url = "http://192.0.2.1:1/health/ready";

        let ok_a = ProbeResult {
            service: "kratos".into(),
            url: healthy_url.clone(),
            ok: true,
            status_or_error: "200".into(),
            hint: String::new(),
        };
        let ok_b = ProbeResult {
            service: "hydra".into(),
            url: healthy_url,
            ok: true,
            status_or_error: "200".into(),
            hint: String::new(),
        };
        let unreachable = ProbeResult {
            service: "keto".into(),
            url: unroutable_url.into(),
            ok: false,
            status_or_error: "transport error".into(),
            hint: "is the container up?".into(),
        };

        // All healthy → exit 0.
        assert_eq!(
            check::overall_exit_code(&[ok_a.clone(), ok_b.clone()]),
            0,
            "all selected services healthy → exit 0"
        );
        // One unreachable → non-zero.
        assert_ne!(
            check::overall_exit_code(&[ok_a, ok_b, unreachable]),
            0,
            "one unreachable service → non-zero exit"
        );
    }
}

// ─── CLI-07b: MultiSelect pre-check mask == current state; diff is no-op-clean ──

/// CLI-07b acceptance: the `[x]`/`[ ]` feature MultiSelect is pre-checked to the
/// current EFFECTIVE feature state (a bare Enter is a no-op), and the resulting
/// enabled set equals exactly the rows left `[x]`. This tests the PURE diff core
/// (`ui::feature_default_mask` + `ui::diff_features`) — not the widget — so it is a
/// deterministic unit-style check with no TTY.
///
/// Encodes the Req-2 invariant: when `after == before` (bare Enter), the diff is
/// EMPTY (no PUT issued); only changed keys appear in the diff.
/// The body forward-references `console_cli::ui::{feature_default_mask,
/// diff_features}`, which do not exist until Wave 1. The assertion is encoded under
/// the `wave1` cargo feature (off today) so the LOCKED contract is documented
/// inline AND the file compiles against today's surface; the test stays
/// `#[ignore]`-gated regardless.
#[test]
#[ignore = "Wave 1: ui diff core (console_cli::ui::{feature_default_mask, diff_features}) not yet implemented"]
fn multiselect_defaults_match_current() {
    #[cfg(feature = "wave1")]
    {
        use console_cli::config_model::parse_config;
        use console_cli::ui;

        // saml ON (operator override), observability OFF (default) — rest defaults.
        let cfg = parse_config(
            r#"
[services.kratos]
mode = "in-stack"
[features]
saml = true
"#,
        )
        .expect("sample config must parse");
        let features = cfg.effective_features(); // Features(BTreeMap<String,bool>)

        // A STABLE key order (the order the MultiSelect rows render in).
        let ordered_keys: Vec<String> = features.0.keys().cloned().collect();

        // 1. The pre-check mask: `true` positions must EXACTLY equal the enabled keys.
        let mask: Vec<bool> = ui::feature_default_mask(&features, &ordered_keys);
        assert_eq!(
            mask.len(),
            ordered_keys.len(),
            "mask is indexed parallel to the ordered key list"
        );
        for (i, key) in ordered_keys.iter().enumerate() {
            let enabled = *features.0.get(key).unwrap();
            assert_eq!(
                mask[i], enabled,
                "mask[{i}] ({key}) must match the current effective state"
            );
        }

        // 2. Bare Enter — `after` indices == the positions already checked in `mask`.
        //    The diff MUST be EMPTY (the Req-2 no-op invariant).
        let after_indices: Vec<usize> = mask
            .iter()
            .enumerate()
            .filter_map(|(i, &on)| if on { Some(i) } else { None })
            .collect();
        let no_op = ui::diff_features(&mask, &after_indices, &ordered_keys);
        assert!(
            no_op.is_empty(),
            "a bare Enter (after == before mask) yields an EMPTY diff (no-op): {no_op:?}"
        );

        // 3. Toggle exactly one row → the diff contains ONLY that changed key.
        //    Flip the FIRST currently-OFF key ON (or the first ON key OFF if all on).
        let flip_idx = mask.iter().position(|&on| !on).unwrap_or(0);
        let flip_key = ordered_keys[flip_idx].clone();
        let flipped_on = !mask[flip_idx];
        let mut after2 = after_indices.clone();
        if flipped_on {
            after2.push(flip_idx); // now checked
        } else {
            after2.retain(|&i| i != flip_idx); // now unchecked
        }
        let diff = ui::diff_features(&mask, &after2, &ordered_keys);
        assert_eq!(
            diff,
            vec![(flip_key.clone(), flipped_on)],
            "exactly one changed key ({flip_key} -> {flipped_on}) appears in the diff"
        );
    }
}

// ─── CLI-07e: zero ANSI when piped / non-TTY never hangs (Wave 2) ──────────────
//
// These two exercise the COMPILED `ory-console` binary because ANSI emission +
// non-TTY hang are PROCESS-LEVEL behaviors (not reachable by driving the library
// dispatch in-process). The binary path comes from the cargo-provided
// `CARGO_BIN_EXE_ory-console` env var (cargo sets it for the `[[bin]] name =
// "ory-console"` target — no extra dependency). A wall-clock deadline guard
// (spawn + poll `try_wait`) proves "never hangs" without blocking the test run.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Spawn `ory-console` with the given args + extra env, `stdin = /dev/null`
/// (a non-TTY), capturing stdout+stderr. Poll `try_wait` until a ~5s wall-clock
/// deadline; PANIC (test failure) if the deadline passes — this is the
/// "never hangs" guard. Returns `(exit_code, combined_stdout_stderr_bytes)`.
#[cfg(test)]
fn run_bin_with_deadline(
    args: &[&str],
    envs: &[(&str, &str)],
    deadline: Duration,
) -> (Option<i32>, Vec<u8>) {
    let bin = env!("CARGO_BIN_EXE_ory-console");
    let mut cmd = Command::new(bin);
    cmd.args(args)
        .stdin(Stdio::null()) // a NON-TTY stdin — must never block on a widget
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn ory-console");

    let start = Instant::now();
    loop {
        match child.try_wait().expect("try_wait") {
            Some(status) => {
                // Drain the captured pipes.
                let out = child.wait_with_output().expect("wait_with_output");
                let mut bytes = out.stdout;
                bytes.extend_from_slice(&out.stderr);
                return (status.code(), bytes);
            }
            None => {
                if start.elapsed() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!(
                        "ory-console {args:?} did not exit within {deadline:?} — \
                         it HUNG on a non-TTY (interactive widget reached off-TTY?)"
                    );
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    }
}

/// CLI-07e acceptance: `NO_COLOR=1 ory-console feature list | cat` AND
/// `ory-console --text feature list | cat` contain ZERO ANSI escape bytes.
///
/// Runs the bin TWICE (the `NO_COLOR` degradation path and the `--text`
/// degradation path), each pointed at a mockito server returning a small features
/// JSON body, and asserts the captured stdout+stderr contains ZERO occurrences of
/// the escape-introducer byte sequence `\x1b[` (searched as the RAW bytes
/// `[0x1b, 0x5b]`, NOT a string `contains`, so a colored escape cannot slip
/// through). This is the falsifiable detector for the control-sequence-injection /
/// log-forgery threat (T-20-ANSI).
#[test]
#[ignore = "Wave 2: --text flag + ui plain mode (zero-ANSI degradation) not yet implemented"]
fn zero_ansi_when_piped() {
    // A local mockito server returning a small features body for `feature list`.
    let mut server = mockito::Server::new();
    let _m = server
        .mock("GET", "/api/console/features")
        .expect_at_least(0) // tolerate either ordering / a degraded no-call path
        .with_status(200)
        .with_body(r#"{"features":{"saml":false,"identities":true}}"#)
        .create();
    let url = server.url();

    let deadline = Duration::from_secs(5);

    // Path 1: NO_COLOR=1 (no --text).
    let (_c1, bytes_no_color) = run_bin_with_deadline(
        &["feature", "list"],
        &[
            ("NO_COLOR", "1"),
            ("CONSOLE_API_URL", url.as_str()),
            ("CONSOLE_API_KEY", "k"),
        ],
        deadline,
    );
    assert!(
        !contains_ansi_introducer(&bytes_no_color),
        "NO_COLOR=1 feature list emitted an ANSI escape (\\x1b[) — found in output"
    );

    // Path 2: --text (no NO_COLOR).
    let (_c2, bytes_text) = run_bin_with_deadline(
        &["--text", "feature", "list"],
        &[
            ("CONSOLE_API_URL", url.as_str()),
            ("CONSOLE_API_KEY", "k"),
        ],
        deadline,
    );
    assert!(
        !contains_ansi_introducer(&bytes_text),
        "--text feature list emitted an ANSI escape (\\x1b[) — found in output"
    );
}

/// Search the RAW byte sequence `\x1b[` (the CSI introducer: ESC `0x1b` followed
/// by `[` `0x5b`). Byte-level — not a `str::contains` — so no escape slips through
/// a lossy decode.
#[cfg(test)]
fn contains_ansi_introducer(bytes: &[u8]) -> bool {
    bytes.windows(2).any(|w| w == [0x1b, 0x5b])
}

/// CLI-07e acceptance: a non-TTY stdin NEVER blocks on an interactive widget.
///   * Bare `ory-console` (no subcommand) with a null stdin EXITS within the
///     deadline and with the LOCKED bare-invocation-on-non-TTY exit code `2`
///     (20-CONTEXT Area 4 / 20-RESEARCH Pitfall 2).
///   * `ory-console init` with a null stdin EXITS PROMPTLY with a non-zero code and
///     a message mentioning `--defaults` or `--config` (the existing
///     `interactive_config` TTY guard, generalized in Wave 2) — never blocks.
#[test]
#[ignore = "Wave 2: bare-invocation guard (non-TTY → usage + exit 2, never hang) not yet implemented"]
fn non_tty_never_hangs() {
    let deadline = Duration::from_secs(5);

    // 1. Bare invocation on a non-TTY → usage + exit code 2 (locked), never hangs.
    let (code_bare, _bytes_bare) = run_bin_with_deadline(&[], &[], deadline);
    assert_eq!(
        code_bare,
        Some(2),
        "bare `ory-console` on a non-TTY must exit code 2 (usage), not hang or 0"
    );

    // 2. `init` on a non-TTY → prompt exit, non-zero, with --defaults/--config hint.
    let (code_init, bytes_init) = run_bin_with_deadline(&["init"], &[], deadline);
    assert!(
        matches!(code_init, Some(c) if c != 0),
        "`init` on a non-TTY must exit non-zero (cannot prompt), not hang or succeed: {code_init:?}"
    );
    let text_init = String::from_utf8_lossy(&bytes_init);
    assert!(
        text_init.contains("--defaults") || text_init.contains("--config"),
        "`init` on a non-TTY must guide the operator to --defaults/--config: {text_init}"
    );
}
