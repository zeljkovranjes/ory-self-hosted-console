//! The SINGLE rendering + prompt authority for the whole CLI (Phase 20 / CLI-07).
//!
//! Every heading, table, status line, spinner, and interactive prompt the CLI
//! emits goes through THIS module. It resolves an [`OutputMode`] ONCE (from
//! `console`'s TTY detection + `NO_COLOR` + the Wave-2 `--text` flag) and owns
//! every `dialoguer` / `console` / `indicatif` / `comfy-table` call so degradation
//! (CLI-07e) is implemented in exactly ONE place:
//!
//!   * [`OutputMode::Rich`]  — a user-attended terminal: cyan/bold headings, green
//!     `✓` / red `✗` / yellow `⚠` status glyphs, UTF8 box-drawing tables, animated
//!     spinners, and arrow-key `dialoguer` widgets.
//!   * [`OutputMode::Plain`] — a pipe / CI / `--text` / `NO_COLOR` context: plain
//!     ASCII, a borderless table preset, a hidden spinner draw target, and a
//!     line-reading [`ScriptedPrompter`] (a `dialoguer` widget is NEVER constructed
//!     off a Rich path — Pitfall 2). Plain output contains ZERO `\x1b[` bytes.
//!
//! It also exposes the PURE feature-diff core ([`feature_default_mask`] +
//! [`diff_features`]) that both `init`'s feature step and the later-wave
//! `edit features` build on — no TTY, no widget, unit-testable.
//!
//! Human chrome (headings, status, prompts, spinners) is written to STDERR,
//! matching the existing `eprint!` convention in [`crate::wizard`]; STDOUT stays
//! clean for piped/scriptable data.
//!
//! SECURITY: the [`Prompter::password`] helper renders ONLY the masked prompt and
//! returns the secret to the caller — no `ui` helper ever logs or renders the
//! value (the `dialoguer` `password` feature also pulls `zeroize`, which clears
//! the input buffer).

use std::io::BufRead;
use std::time::Duration;

use crate::CliError;

/// The resolved output mode for the whole process. Computed ONCE at startup via
/// [`resolve_mode`] and threaded through every `ui` helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    /// A user-attended terminal: color, UTF8 tables, animated spinners, widgets.
    Rich,
    /// A pipe / CI / `--text` / `NO_COLOR` context: ASCII, no color, no animation,
    /// line-reading prompts. Emits zero ANSI escape bytes.
    Plain,
}

/// Resolve the [`OutputMode`] ONCE from the terminal context.
///
/// `Plain` when ANY of: the caller passed `--text` (`text_flag`), the process is
/// not user-attended on BOTH stdout and stderr, or `NO_COLOR` is set (any value).
/// In the `Plain` branch this also disables `console`'s colors as a belt-and-
/// suspenders guard so any stray `console` styling can never emit an escape. In
/// the `Rich` branch the process is interactive and `console` honors
/// `CLICOLOR`/`CLICOLOR_FORCE` natively.
pub fn resolve_mode(text_flag: bool) -> OutputMode {
    // `console::user_attended[_stderr]` are the console-rs TTY detectors (verified
    // present on console 0.16.3); we gate on BOTH so a half-piped invocation
    // (e.g. stdout redirected) degrades cleanly.
    let interactive = console::user_attended() && console::user_attended_stderr();
    if text_flag || !interactive || std::env::var_os("NO_COLOR").is_some() {
        console::set_colors_enabled(false);
        console::set_colors_enabled_stderr(false);
        OutputMode::Plain
    } else {
        OutputMode::Rich
    }
}

/// Re-derive the [`OutputMode`] WITHOUT the global color side effect of
/// [`resolve_mode`] (IN-02). Pure: it only reads `console`'s TTY detectors +
/// `NO_COLOR` and returns the mode, never mutating process-global color state.
///
/// Used on hot/secondary paths (e.g. `bootstrap::read_secret`'s interactive
/// gate, CR-01) that must reproduce `resolve_mode`'s Rich-vs-Plain decision but
/// MUST NOT churn the global color flags the single startup `resolve_mode` call
/// already set. The startup call (`Ui::from_flag`) remains the ONE place that
/// disables colors; this helper only mirrors its classification.
pub fn current_mode() -> OutputMode {
    let interactive = console::user_attended() && console::user_attended_stderr();
    if !interactive || std::env::var_os("NO_COLOR").is_some() {
        OutputMode::Plain
    } else {
        OutputMode::Rich
    }
}

/// A tiny holder for the resolved [`OutputMode`] that exposes the rendering
/// helpers. Construct once (`Ui::new(resolve_mode(text_flag))`) and pass by
/// reference to the command handlers.
#[derive(Debug, Clone, Copy)]
pub struct Ui {
    /// The resolved mode driving every helper's Rich-vs-Plain branch.
    pub mode: OutputMode,
}

impl Ui {
    /// Build a [`Ui`] over an already-resolved [`OutputMode`].
    pub fn new(mode: OutputMode) -> Self {
        Ui { mode }
    }

    /// Resolve the mode from `text_flag` and build a [`Ui`] in one step.
    pub fn from_flag(text_flag: bool) -> Self {
        Ui::new(resolve_mode(text_flag))
    }

    /// A section heading on STDERR — cyan + bold in Rich, plain text in Plain.
    pub fn heading(&self, text: &str) {
        match self.mode {
            OutputMode::Rich => eprintln!("{}", console::style(text).cyan().bold()),
            OutputMode::Plain => eprintln!("{text}"),
        }
    }

    /// A success status line on STDERR — green `✓` in Rich, `[ok]` in Plain.
    pub fn status_ok(&self, text: &str) {
        match self.mode {
            OutputMode::Rich => eprintln!("{} {text}", console::style("✓").green()),
            OutputMode::Plain => eprintln!("[ok] {text}"),
        }
    }

    /// An error status line on STDERR — red `✗` in Rich, `[FAIL]` in Plain.
    pub fn status_err(&self, text: &str) {
        match self.mode {
            OutputMode::Rich => eprintln!("{} {text}", console::style("✗").red()),
            OutputMode::Plain => eprintln!("[FAIL] {text}"),
        }
    }

    /// A warning status line on STDERR — yellow `⚠` in Rich, `[warn]` in Plain.
    pub fn status_warn(&self, text: &str) {
        match self.mode {
            OutputMode::Rich => eprintln!("{} {text}", console::style("⚠").yellow()),
            OutputMode::Plain => eprintln!("[warn] {text}"),
        }
    }

    /// A dim hint line on STDERR — dimmed in Rich, plain in Plain.
    pub fn hint(&self, text: &str) {
        match self.mode {
            OutputMode::Rich => eprintln!("{}", console::style(text).dim()),
            OutputMode::Plain => eprintln!("{text}"),
        }
    }

    /// A key/value panel on STDERR (`key: value` rows). The key is dim-styled in
    /// Rich; Plain emits aligned plain `key: value` rows with zero color.
    pub fn kv_panel(&self, rows: &[(&str, &str)]) {
        for (k, v) in rows {
            match self.mode {
                OutputMode::Rich => eprintln!("  {}: {v}", console::style(k).dim()),
                OutputMode::Plain => eprintln!("  {k}: {v}"),
            }
        }
    }

    /// Render an aligned table to STDOUT (the data surface). Rich uses the
    /// `UTF8_FULL` box-drawing preset; Plain uses the borderless `NOTHING` preset
    /// and applies NO color to any cell, so a piped capture contains zero `\x1b[`
    /// bytes (T-20-ANSI).
    pub fn table(&self, headers: &[&str], rows: &[Vec<String>]) {
        let mut t = comfy_table::Table::new();
        let preset = match self.mode {
            OutputMode::Rich => comfy_table::presets::UTF8_FULL,
            OutputMode::Plain => comfy_table::presets::NOTHING,
        };
        t.load_preset(preset);
        t.set_header(headers.iter().map(|h| h.to_string()).collect::<Vec<_>>());
        for row in rows {
            t.add_row(row.clone());
        }
        println!("{t}");
    }

    /// Start a spinner for a long operation, returning a [`SpinnerHandle`] the
    /// caller finishes with `finish_ok`/`finish_err`. In Rich the spinner animates
    /// on a steady tick; in Plain the draw target is hidden and a single start line
    /// is printed to STDERR (no animation, no escape bytes).
    pub fn spinner(&self, label: &str) -> SpinnerHandle {
        match self.mode {
            OutputMode::Rich => {
                let pb = indicatif::ProgressBar::new_spinner();
                pb.set_message(label.to_string());
                pb.enable_steady_tick(Duration::from_millis(120));
                SpinnerHandle {
                    mode: self.mode,
                    pb,
                }
            }
            OutputMode::Plain => {
                // A hidden draw target → no animation, no escape sequences. Print a
                // single plain start line so the operator still sees progress.
                let pb = indicatif::ProgressBar::with_draw_target(
                    None,
                    indicatif::ProgressDrawTarget::hidden(),
                );
                eprintln!("... {label}");
                SpinnerHandle {
                    mode: self.mode,
                    pb,
                }
            }
        }
    }

    /// The [`Prompter`] for this mode: a [`DialoguerPrompter`] on a Rich (TTY)
    /// path, a line-reading [`ScriptedPrompter`] over stdin otherwise. A
    /// `dialoguer` widget is therefore NEVER reached off a Rich path (Pitfall 2).
    pub fn prompter(&self) -> Box<dyn Prompter> {
        match self.mode {
            OutputMode::Rich => Box::new(DialoguerPrompter),
            OutputMode::Plain => Box::new(ScriptedPrompter::from_stdin()),
        }
    }
}

/// A handle to a running spinner. Finish it with [`SpinnerHandle::finish_ok`] or
/// [`SpinnerHandle::finish_err`].
pub struct SpinnerHandle {
    mode: OutputMode,
    pb: indicatif::ProgressBar,
}

impl SpinnerHandle {
    /// Finish the spinner with a success result — green `✓` line in Rich, a plain
    /// `[ok]` line in Plain.
    pub fn finish_ok(self, msg: &str) {
        match self.mode {
            OutputMode::Rich => self
                .pb
                .finish_with_message(format!("{} {msg}", console::style("✓").green())),
            OutputMode::Plain => {
                self.pb.finish_and_clear();
                eprintln!("[ok] {msg}");
            }
        }
    }

    /// Finish the spinner with an error result — red `✗` line in Rich, a plain
    /// `[FAIL]` line in Plain.
    pub fn finish_err(self, msg: &str) {
        match self.mode {
            OutputMode::Rich => self
                .pb
                .finish_with_message(format!("{} {msg}", console::style("✗").red())),
            OutputMode::Plain => {
                self.pb.finish_and_clear();
                eprintln!("[FAIL] {msg}");
            }
        }
    }
}

/// The prompt abstraction that keeps the prompt FLOW testable without a TTY.
///
/// Rich callers get [`DialoguerPrompter`] (arrow-key widgets); Plain/test callers
/// get [`ScriptedPrompter`] (numbered/line answers). A widget is NEVER constructed
/// unless the caller holds [`OutputMode::Rich`] (Pitfall 2), so a non-TTY
/// invocation can never hang on a `dialoguer` prompt.
pub trait Prompter {
    /// Single-choice selection. Returns the chosen item index. `default` is the
    /// pre-highlighted (Rich) / bare-Enter (Plain) index.
    fn select(&self, prompt: &str, items: &[&str], default: usize) -> Result<usize, CliError>;

    /// Multi-choice (`[x]`/`[ ]`) selection. `defaults` is the pre-check mask
    /// (indexed parallel to `items`). Returns the indices left checked.
    ///
    /// TOGGLE semantics (WR-04): the prompt starts from `defaults` and an
    /// interaction FLIPS individual rows — both prompters share this model. Rich
    /// (`dialoguer::MultiSelect`) flips a row on Space; the scripted/Plain path
    /// flips each comma-separated index named in the answer. A bare Enter keeps the
    /// defaults exactly (the no-op path). A scripted answer is therefore NOT a full
    /// replacement set — it toggles, so it can both add to and reduce the defaults.
    fn multiselect(
        &self,
        prompt: &str,
        items: &[&str],
        defaults: &[bool],
    ) -> Result<Vec<usize>, CliError>;

    /// Yes/no confirmation with a `default`.
    fn confirm(&self, prompt: &str, default: bool) -> Result<bool, CliError>;

    /// Free-text input with a `default` (a bare Enter accepts the default).
    fn input(&self, prompt: &str, default: &str) -> Result<String, CliError>;

    /// Masked secret entry — the value is returned to the caller and NEVER
    /// rendered. Only the (masked) prompt is shown.
    fn password(&self, prompt: &str) -> Result<String, CliError>;
}

/// The Rich-mode [`Prompter`]: arrow-key `dialoguer` widgets themed with
/// `ColorfulTheme`. Only ever constructed on an [`OutputMode::Rich`] path.
pub struct DialoguerPrompter;

impl DialoguerPrompter {
    fn theme() -> dialoguer::theme::ColorfulTheme {
        dialoguer::theme::ColorfulTheme::default()
    }
}

impl Prompter for DialoguerPrompter {
    fn select(&self, prompt: &str, items: &[&str], default: usize) -> Result<usize, CliError> {
        dialoguer::Select::with_theme(&Self::theme())
            .with_prompt(prompt)
            .items(items)
            .default(default)
            .interact()
            .map_err(|e| CliError::Io(format!("prompt error: {e}")))
    }

    fn multiselect(
        &self,
        prompt: &str,
        items: &[&str],
        defaults: &[bool],
    ) -> Result<Vec<usize>, CliError> {
        dialoguer::MultiSelect::with_theme(&Self::theme())
            .with_prompt(prompt)
            .items(items)
            .defaults(defaults)
            .interact()
            .map_err(|e| CliError::Io(format!("prompt error: {e}")))
    }

    fn confirm(&self, prompt: &str, default: bool) -> Result<bool, CliError> {
        dialoguer::Confirm::with_theme(&Self::theme())
            .with_prompt(prompt)
            .default(default)
            .interact()
            .map_err(|e| CliError::Io(format!("prompt error: {e}")))
    }

    fn input(&self, prompt: &str, default: &str) -> Result<String, CliError> {
        dialoguer::Input::<String>::with_theme(&Self::theme())
            .with_prompt(prompt)
            .default(default.to_string())
            .allow_empty(true)
            .interact_text()
            .map_err(|e| CliError::Io(format!("prompt error: {e}")))
    }

    fn password(&self, prompt: &str) -> Result<String, CliError> {
        dialoguer::Password::with_theme(&Self::theme())
            .with_prompt(prompt)
            .interact()
            .map_err(|e| CliError::Io(format!("prompt error: {e}")))
    }
}

/// The Plain/test [`Prompter`]: reads line answers from an injected `BufRead`,
/// mirroring the existing `prompt_line` semantics — a bare (empty) line accepts
/// the default, and EOF falls back to the default. NEVER touches a `dialoguer`
/// widget, so a non-TTY caller can never hang.
pub struct ScriptedPrompter {
    reader: std::sync::Mutex<Box<dyn BufRead + Send>>,
}

impl ScriptedPrompter {
    /// Drive prompts from process stdin (the Plain/non-TTY runtime path).
    pub fn from_stdin() -> Self {
        ScriptedPrompter {
            reader: std::sync::Mutex::new(Box::new(std::io::BufReader::new(std::io::stdin()))),
        }
    }

    /// Drive prompts from an arbitrary `BufRead` (the scripted-test path).
    pub fn new<R: BufRead + Send + 'static>(reader: R) -> Self {
        ScriptedPrompter {
            reader: std::sync::Mutex::new(Box::new(reader)),
        }
    }

    /// Read one trimmed answer line. `Ok(None)` on EOF / empty line (→ default).
    fn read_answer(&self) -> Result<Option<String>, CliError> {
        let mut guard = self
            .reader
            .lock()
            .map_err(|_| CliError::Io("prompt reader lock poisoned".into()))?;
        let mut line = String::new();
        let n = guard
            .read_line(&mut line)
            .map_err(|e| CliError::Io(format!("reading prompt answer: {e}")))?;
        if n == 0 {
            return Ok(None); // EOF → default
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            Ok(None) // bare Enter → default
        } else {
            Ok(Some(trimmed.to_string()))
        }
    }
}

impl Prompter for ScriptedPrompter {
    fn select(&self, prompt: &str, items: &[&str], default: usize) -> Result<usize, CliError> {
        eprintln!("{prompt}");
        for (i, item) in items.iter().enumerate() {
            let marker = if i == default { " [default]" } else { "" };
            eprintln!("  {}) {item}{marker}", i + 1);
        }
        match self.read_answer()? {
            None => Ok(default),
            Some(ans) => {
                // Accept either the 1-based index or the literal item label.
                if let Ok(n) = ans.parse::<usize>() {
                    if n >= 1 && n <= items.len() {
                        return Ok(n - 1);
                    }
                }
                if let Some(idx) = items.iter().position(|it| *it == ans) {
                    return Ok(idx);
                }
                Err(CliError::Io(format!(
                    "invalid selection `{ans}` (expected 1..={} or an item name)",
                    items.len()
                )))
            }
        }
    }

    fn multiselect(
        &self,
        prompt: &str,
        items: &[&str],
        defaults: &[bool],
    ) -> Result<Vec<usize>, CliError> {
        eprintln!("{prompt}");
        for (i, item) in items.iter().enumerate() {
            let checked = defaults.get(i).copied().unwrap_or(false);
            let mark = if checked { "[x]" } else { "[ ]" };
            eprintln!("  {} {mark} {item}", i + 1);
        }
        // WR-04: the scripted answer TOGGLES the named indices against the defaults
        // — sharing the Rich `dialoguer::MultiSelect` mental model (Space flips an
        // individual row from its default). A bare Enter keeps the defaults (the
        // no-op path); naming index N flips row N (off→on or on→off).
        eprintln!("  (comma-separated indices to TOGGLE against the defaults, or Enter to keep them)");
        // Start from the pre-checked defaults; each named index flips that row.
        let mut checked: Vec<bool> = (0..items.len())
            .map(|i| defaults.get(i).copied().unwrap_or(false))
            .collect();
        match self.read_answer()? {
            // Bare Enter → keep exactly the pre-checked defaults (the no-op path).
            None => {}
            Some(ans) => {
                for tok in ans.split(',') {
                    let tok = tok.trim();
                    if tok.is_empty() {
                        continue;
                    }
                    let n: usize = tok.parse().map_err(|_| {
                        CliError::Io(format!("invalid index `{tok}` in multiselect answer"))
                    })?;
                    if n < 1 || n > items.len() {
                        return Err(CliError::Io(format!(
                            "index {n} out of range 1..={}",
                            items.len()
                        )));
                    }
                    // TOGGLE row n (1-based → 0-based).
                    checked[n - 1] = !checked[n - 1];
                }
            }
        }
        Ok(checked
            .iter()
            .enumerate()
            .filter_map(|(i, &on)| if on { Some(i) } else { None })
            .collect())
    }

    fn confirm(&self, prompt: &str, default: bool) -> Result<bool, CliError> {
        let hint = if default { "[Y/n]" } else { "[y/N]" };
        eprintln!("{prompt} {hint}");
        match self.read_answer()? {
            None => Ok(default),
            Some(ans) => match ans.to_ascii_lowercase().as_str() {
                "y" | "yes" => Ok(true),
                "n" | "no" => Ok(false),
                other => Err(CliError::Io(format!("invalid yes/no answer `{other}`"))),
            },
        }
    }

    fn input(&self, prompt: &str, default: &str) -> Result<String, CliError> {
        eprintln!("{prompt} [{default}]");
        match self.read_answer()? {
            None => Ok(default.to_string()),
            Some(ans) => Ok(ans),
        }
    }

    fn password(&self, prompt: &str) -> Result<String, CliError> {
        // No masking on the scripted/Plain path (no TTY); the value is read but
        // NEVER echoed by this helper.
        //
        // WR-01: EOF / a bare Enter is NOT a valid empty secret — return a clear
        // error so every caller fails LOUDLY instead of silently proceeding with an
        // empty secret. (`read_secret`'s own empty-check stays as defense-in-depth.)
        eprintln!("{prompt}");
        match self.read_answer()? {
            None => Err(CliError::Io(
                "no value provided on the prompt (EOF / empty input); set it via env or a --*-file"
                    .into(),
            )),
            Some(ans) => Ok(ans),
        }
    }
}

// ─── The PURE feature-diff core (no TTY, no widget — unit-testable) ─────────────

/// The `[x]`/`[ ]` MultiSelect pre-check mask: for each key in `ordered_keys`,
/// `true` iff that key is currently enabled in `features` (a key absent from the
/// map yields `false`). The result is indexed PARALLEL to `ordered_keys`, so it
/// can be passed straight to `dialoguer::MultiSelect::defaults` and a bare Enter
/// reproduces the current effective state (the Req-2 no-op invariant; CLI-07b).
pub fn feature_default_mask(
    features: &crate::config_model::Features,
    ordered_keys: &[String],
) -> Vec<bool> {
    ordered_keys
        .iter()
        .map(|key| features.0.get(key).copied().unwrap_or(false))
        .collect()
}

/// Diff a MultiSelect result against its pre-check mask. `before_mask` is the
/// per-key checked state going IN (parallel to `ordered_keys`); `after_indices`
/// is the set of indices left checked coming OUT. Returns ONLY the keys whose
/// checked-state CHANGED, as `(key, new_enabled)` pairs in `ordered_keys` order.
///
/// When `after` reproduces `before` (a bare Enter), the diff is EMPTY — the Req-2
/// no-op invariant: no PUT is issued for an unchanged feature.
pub fn diff_features(
    before_mask: &[bool],
    after_indices: &[usize],
    ordered_keys: &[String],
) -> Vec<(String, bool)> {
    let after_set: std::collections::HashSet<usize> = after_indices.iter().copied().collect();
    let mut diff = Vec::new();
    for (i, key) in ordered_keys.iter().enumerate() {
        let before = before_mask.get(i).copied().unwrap_or(false);
        let after = after_set.contains(&i);
        if before != after {
            diff.push((key.clone(), after));
        }
    }
    diff
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_model::Features;
    use std::collections::BTreeMap;
    use std::io::Cursor;

    fn features(pairs: &[(&str, bool)]) -> Features {
        let mut m = BTreeMap::new();
        for (k, v) in pairs {
            m.insert((*k).to_string(), *v);
        }
        Features(m)
    }

    fn keys(ks: &[&str]) -> Vec<String> {
        ks.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn feature_default_mask_mirrors_current_effective_state() {
        let f = features(&[("identities", true), ("saml", false), ("oauth2", true)]);
        let ordered = keys(&["identities", "saml", "oauth2"]);
        assert_eq!(feature_default_mask(&f, &ordered), vec![true, false, true]);
    }

    #[test]
    fn feature_default_mask_absent_key_is_false() {
        let f = features(&[("identities", true)]);
        let ordered = keys(&["identities", "not_in_map"]);
        assert_eq!(feature_default_mask(&f, &ordered), vec![true, false]);
    }

    #[test]
    fn diff_features_bare_enter_is_empty_no_op() {
        // before [true,false]; after keeps index 0 checked → no change.
        let before = vec![true, false];
        let after = vec![0usize];
        let ordered = keys(&["a", "b"]);
        assert!(diff_features(&before, &after, &ordered).is_empty());
    }

    #[test]
    fn diff_features_both_changed() {
        // before [true,false]; after checks only index 1 → a:true→false, b:false→true.
        let before = vec![true, false];
        let after = vec![1usize];
        let ordered = keys(&["a", "b"]);
        assert_eq!(
            diff_features(&before, &after, &ordered),
            vec![("a".to_string(), false), ("b".to_string(), true)]
        );
    }

    #[test]
    fn diff_features_single_toggle_on() {
        let before = vec![false, false];
        let after = vec![1usize];
        let ordered = keys(&["a", "b"]);
        assert_eq!(
            diff_features(&before, &after, &ordered),
            vec![("b".to_string(), true)]
        );
    }

    #[test]
    fn resolve_mode_text_flag_forces_plain() {
        assert_eq!(resolve_mode(true), OutputMode::Plain);
        // Disabling colors is the belt-and-suspenders side effect.
        assert!(!console::colors_enabled());
    }

    #[test]
    fn plain_table_emits_zero_ansi() {
        // The Plain preset + no cell color must yield byte-clean output. We render
        // through comfy-table exactly as `Ui::table` does and assert no `\x1b[`.
        let mut t = comfy_table::Table::new();
        t.load_preset(comfy_table::presets::NOTHING);
        t.set_header(vec!["service".to_string(), "health".to_string()]);
        t.add_row(vec!["kratos".to_string(), "ready".to_string()]);
        let rendered = format!("{t}");
        assert!(
            !rendered.as_bytes().windows(2).any(|w| w == [0x1b, 0x5b]),
            "Plain table must contain zero ANSI introducer bytes: {rendered:?}"
        );
    }

    #[test]
    fn scripted_prompter_select_bare_enter_takes_default() {
        let p = ScriptedPrompter::new(Cursor::new(b"\n".to_vec()));
        let idx = p.select("mode", &["in-stack", "byo", "off"], 1).unwrap();
        assert_eq!(idx, 1, "bare Enter accepts the default index");
    }

    #[test]
    fn scripted_prompter_select_by_index_and_name() {
        let p = ScriptedPrompter::new(Cursor::new(b"3\n".to_vec()));
        assert_eq!(p.select("m", &["a", "b", "c"], 0).unwrap(), 2);
        let p2 = ScriptedPrompter::new(Cursor::new(b"byo\n".to_vec()));
        assert_eq!(p2.select("m", &["in-stack", "byo", "off"], 0).unwrap(), 1);
    }

    #[test]
    fn scripted_prompter_multiselect_bare_enter_keeps_defaults() {
        let p = ScriptedPrompter::new(Cursor::new(b"\n".to_vec()));
        let chosen = p
            .multiselect("feats", &["a", "b", "c"], &[true, false, true])
            .unwrap();
        assert_eq!(chosen, vec![0, 2], "bare Enter keeps the pre-checked defaults");
    }

    #[test]
    fn scripted_prompter_multiselect_explicit_indices_toggle() {
        // WR-04: named indices TOGGLE against the defaults (matching the Rich
        // widget's Space-flips-a-row model). Defaults [T,F,F]; toggle 2 and 3 →
        // [T,T,T] → indices 0,1,2.
        let p = ScriptedPrompter::new(Cursor::new(b"2,3\n".to_vec()));
        let chosen = p
            .multiselect("feats", &["a", "b", "c"], &[true, false, false])
            .unwrap();
        assert_eq!(chosen, vec![0, 1, 2]);
    }

    #[test]
    fn scripted_prompter_multiselect_toggle_can_turn_a_default_off() {
        // WR-04: toggling a row that is ON by default turns it OFF — the scripted
        // path can REDUCE the set, not only ADD to it. Defaults [T,F,T]; toggle 1
        // (T→F) and 2 (F→T) → [F,T,T] → indices 1,2.
        let p = ScriptedPrompter::new(Cursor::new(b"1,2\n".to_vec()));
        let chosen = p
            .multiselect("feats", &["a", "b", "c"], &[true, false, true])
            .unwrap();
        assert_eq!(chosen, vec![1, 2]);
    }

    #[test]
    fn scripted_prompter_password_eof_is_error_not_empty() {
        // WR-01: EOF (or a bare Enter) must be a clear error, never a silent Ok("").
        let p = ScriptedPrompter::new(Cursor::new(Vec::new()));
        let err = p
            .password("secret (hidden)")
            .expect_err("EOF must error, not return an empty secret");
        assert!(matches!(err, CliError::Io(_)), "{err:?}");
        // A non-empty answer still flows through unchanged.
        let p2 = ScriptedPrompter::new(Cursor::new(b"hunter2\n".to_vec()));
        assert_eq!(p2.password("secret").unwrap(), "hunter2");
    }

    #[test]
    fn scripted_prompter_confirm_and_input_defaults() {
        let p = ScriptedPrompter::new(Cursor::new(b"\n".to_vec()));
        assert!(p.confirm("ok?", true).unwrap());
        let p2 = ScriptedPrompter::new(Cursor::new(b"\n".to_vec()));
        assert_eq!(p2.input("name", "default-name").unwrap(), "default-name");
        let p3 = ScriptedPrompter::new(Cursor::new(b"custom\n".to_vec()));
        assert_eq!(p3.input("name", "d").unwrap(), "custom");
    }
}
