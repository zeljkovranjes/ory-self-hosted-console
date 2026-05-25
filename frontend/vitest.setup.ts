// Extends Vitest's `expect` with jest-dom matchers (toBeInTheDocument,
// toHaveAttribute, ...) for the React Testing Library component tests.
import "@testing-library/jest-dom/vitest";
import { vi } from "vitest";

// jsdom does not implement `window.matchMedia`, which next-themes calls when
// `enableSystem` is set (it reads the OS dark-mode preference). Provide a
// no-match stub so the theme provider (and anything mounting it) renders under
// jsdom without throwing. Components that genuinely test media-query behavior
// can override this per-test.
if (typeof window !== "undefined" && !window.matchMedia) {
  window.matchMedia = vi.fn().mockImplementation((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  }));
}
