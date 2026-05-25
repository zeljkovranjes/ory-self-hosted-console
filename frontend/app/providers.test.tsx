import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Providers } from "./providers";

// Smoke test: the app-wide Providers mount (TanStack Query + next-themes) render
// their children without throwing. The isServer-aware client and ThemeProvider
// are exercised here under jsdom (browser branch).
describe("Providers", () => {
  it("renders children inside the Query + theme context", () => {
    render(
      <Providers>
        <span>hello console</span>
      </Providers>,
    );
    expect(screen.getByText("hello console")).toBeInTheDocument();
  });
});
