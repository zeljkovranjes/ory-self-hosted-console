import { describe, it, expect } from "vitest";
import { cn } from "./utils";

// Wave-0 smoke test: proves the Vitest harness is runnable. cn() is the shadcn
// className helper used by every primitive — exercising it confirms clsx +
// tailwind-merge resolve and the test infra (jsdom, config, alias) works.
describe("cn", () => {
  it("joins class names", () => {
    expect(cn("a", "b")).toBe("a b");
  });

  it("dedupes conflicting tailwind utilities (last wins)", () => {
    expect(cn("p-2", "p-4")).toBe("p-4");
  });

  it("drops falsy entries", () => {
    expect(cn("a", false, undefined, "b")).toBe("a b");
  });
});
