import { render } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// WR-01 / WR-02 — CsrfSeed deterministically seeds the client CSRF token cache
// from the server /me token in an EFFECT (not during render), so every console
// page can mutate without a missing-token 403, independent of AccountMenu.

const setCsrfTokenMock = vi.fn();
vi.mock("@/lib/api", () => ({
  setCsrfToken: (...args: unknown[]) => setCsrfTokenMock(...args),
}));

import { CsrfSeed } from "./csrf-seed";

beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("CsrfSeed (WR-01/WR-02)", () => {
  it("seeds the token via setCsrfToken after mount (in an effect, not render)", () => {
    render(<CsrfSeed token="tok-abc" />);
    expect(setCsrfTokenMock).toHaveBeenCalledWith("tok-abc");
  });

  it("renders nothing (no DOM output)", () => {
    const { container } = render(<CsrfSeed token="tok-abc" />);
    expect(container).toBeEmptyDOMElement();
  });

  it("does not seed an empty token", () => {
    render(<CsrfSeed token="" />);
    expect(setCsrfTokenMock).not.toHaveBeenCalled();
  });

  it("re-seeds when the token prop changes", () => {
    const { rerender } = render(<CsrfSeed token="tok-1" />);
    expect(setCsrfTokenMock).toHaveBeenLastCalledWith("tok-1");
    rerender(<CsrfSeed token="tok-2" />);
    expect(setCsrfTokenMock).toHaveBeenLastCalledWith("tok-2");
  });
});
