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
// `composeSecret` encodes exactly that rule with zero knowledge of the literal:
// an empty (untouched) draft yields the original GET value verbatim; a non-empty
// draft (the operator typed something) yields the new value.

/**
 * Decide the value to send for a write-only secret field.
 *
 * @param draft    What the operator typed into the (initially blank) field.
 *                 Empty string = untouched.
 * @param original The value GET returned for this field (the server sentinel for
 *                 a stored secret, or undefined if none was stored).
 * @returns The value to PUT: the new draft if typed, else the original verbatim
 *          (so the backend merge-by-id preserves the stored secret), else
 *          undefined (no secret to send).
 */
export function composeSecret(
  draft: string,
  original: string | undefined,
): string | undefined {
  if (draft.length > 0) return draft;
  return original;
}
