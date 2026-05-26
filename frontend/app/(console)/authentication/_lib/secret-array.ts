// Phase 7 Plan 04 — shared client-side helpers for the write-only-secret list
// editors (OIDC providers, SMS channel auth, web_hook auth).
//
// The single contract (07-02 `secret_merge::MASKED`, the backend source of
// truth): on GET the backend replaces every stored secret with a fixed sentinel
// literal; on PUT it detects that SAME literal to mean "preserve the stored
// value" and merges the incoming array against the stored array by id. The
// frontend NEVER re-declares the literal — for any secret the operator did NOT
// retype, the page resends EXACTLY the value GET returned (the server sentinel
// echoed verbatim); for a retyped secret it sends the new value.
//
// CR-01 / WR-05 — three UNAMBIGUOUS secret states the operator can express:
//   - PRESERVE: leave the field blank AND keep the item's identity unchanged ->
//       resend the original GET value verbatim (the server sentinel). The backend
//       merge-by-id inherits the stored secret.
//   - SET:      type a new value -> send the new value (overwrites on the backend).
//   - CLEAR:    explicitly request removal -> send an empty string "" (a real,
//       non-sentinel value the backend writes as-is, removing the credential).
//
// CR-01 echo-the-sentinel SAFETY: echoing the sentinel is ONLY valid when the
// item's identity (OIDC `id`, SMS `id`, webhook `config.url`) is UNCHANGED. The
// backend keys merge-by-id on that identity; if it changed, no stored item
// matches and the sentinel would be unresolvable — the backend now fails closed
// (422). To keep the happy path 422-free, when the identity changed the UI must
// NOT echo the sentinel: it requires the operator to re-enter the secret (or the
// caller treats it as "no secret"). `composeSecret`'s `idChanged` flag enforces
// this: an untouched secret on a renamed item resolves to `undefined` (no echo)
// so the operator is prompted client-side rather than hitting the backend 422.

/** Explicit "remove this stored secret" marker: a real empty string the backend
 *  writes verbatim (distinct from the preserve-sentinel and from "untouched"). */
export const CLEAR_SECRET = "";

/** Options controlling how an untouched (blank) secret field is resolved. */
export type ComposeSecretOpts = {
  /** True when the item's merge identity (id/url) changed vs. what GET returned.
   *  When set, the stored sentinel can NOT be echoed (it would be unresolvable on
   *  the backend), so an untouched field resolves to `undefined` — the dialog must
   *  require the secret to be re-entered. */
  idChanged?: boolean;
  /** True when the operator explicitly asked to CLEAR the stored secret. Sends an
   *  empty string (removal) regardless of `original`. */
  clear?: boolean;
};

/**
 * Decide the value to send for a write-only secret field.
 *
 * @param draft    What the operator typed into the (initially blank) field.
 *                 Empty string = untouched (unless `clear` is set).
 * @param original The value GET returned for this field (the server sentinel for
 *                 a stored secret, or undefined if none was stored).
 * @param opts     `idChanged` (forbid echoing the sentinel on a renamed item) and
 *                 `clear` (explicit removal).
 * @returns The value to PUT:
 *   - `clear`            -> "" (explicit removal);
 *   - a typed draft      -> the new value (set);
 *   - blank, id unchanged-> the original verbatim (preserve via the sentinel);
 *   - blank, id changed  -> `undefined` (cannot preserve a renamed item's secret;
 *                           the dialog must require re-entry — CR-01 fail-closed).
 */
export function composeSecret(
  draft: string,
  original: string | undefined,
  opts: ComposeSecretOpts = {},
): string | undefined {
  if (opts.clear) return CLEAR_SECRET;
  if (draft.length > 0) return draft;
  // Untouched. Echo the stored sentinel ONLY when the item's identity is
  // unchanged — otherwise the backend cannot resolve it (CR-01).
  if (opts.idChanged) return undefined;
  return original;
}
