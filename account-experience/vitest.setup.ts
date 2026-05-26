// Extends Vitest's `expect` with jest-dom matchers for the RTL component tests.
import "@testing-library/jest-dom/vitest"
import { vi } from "vitest"

// jsdom lacks window.matchMedia (Elements / theme code may read it). Stub it.
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
  }))
}

// jsdom lacks ResizeObserver, used by some primitives on mount.
if (typeof globalThis.ResizeObserver === "undefined") {
  globalThis.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  } as unknown as typeof ResizeObserver
}
