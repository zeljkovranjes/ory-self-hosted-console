import { describe, expect, it } from "vitest";

import { composeSecret, CLEAR_SECRET } from "./secret-array";

const SENTINEL = "__ory_console_masked__";

describe("composeSecret — the three unambiguous secret states (CR-01 / WR-05)", () => {
  it("PRESERVE: blank draft + unchanged id echoes the GET sentinel verbatim", () => {
    expect(composeSecret("", SENTINEL)).toBe(SENTINEL);
  });

  it("SET: a typed draft sends the new value (overwrite)", () => {
    expect(composeSecret("new-secret", SENTINEL)).toBe("new-secret");
  });

  it("SET overrides even when id changed", () => {
    expect(composeSecret("new-secret", SENTINEL, { idChanged: true })).toBe(
      "new-secret",
    );
  });

  it("CLEAR: explicit clear sends the empty marker regardless of original", () => {
    expect(composeSecret("", SENTINEL, { clear: true })).toBe(CLEAR_SECRET);
    expect(composeSecret("typed", SENTINEL, { clear: true })).toBe(CLEAR_SECRET);
  });

  it("CR-01 fail-closed: blank draft + idChanged does NOT echo the sentinel", () => {
    // A renamed item cannot preserve its stored secret by echoing the sentinel —
    // the backend would fail closed. The helper yields undefined so the caller
    // prompts for re-entry instead of sending the unresolvable sentinel.
    expect(composeSecret("", SENTINEL, { idChanged: true })).toBeUndefined();
  });

  it("no stored secret + blank draft yields undefined (nothing to send)", () => {
    expect(composeSecret("", undefined)).toBeUndefined();
  });
});
