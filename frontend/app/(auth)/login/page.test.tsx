import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import LoginPage from "./page";
import { api } from "@/lib/api";

// FE-01 component test: /login renders the password form and conditionally
// renders the GitHub button driven by state.github_oauth_enabled (T-05-16).

const replace = vi.fn();
vi.mock("next/navigation", () => ({
  useRouter: () => ({ replace }),
  useSearchParams: () => new URLSearchParams(""),
}));

vi.mock("@/lib/api", () => ({
  api: vi.fn(),
  ApiError: class ApiError extends Error {
    constructor(
      public status: number,
      public fieldErrors: { path: string; message: string }[] = [],
    ) {
      super();
    }
  },
  setCsrfToken: vi.fn(),
}));

const mockApi = vi.mocked(api);

afterEach(() => {
  vi.clearAllMocks();
});

// Default resolution so any trailing effect re-invocation (e.g. cleanup races)
// resolves rather than rejecting on an undefined queued value.
function withState(state: {
  initialized: boolean;
  github_oauth_enabled: boolean;
}) {
  mockApi.mockResolvedValue(state);
}

describe("LoginPage", () => {
  it("renders email + password fields once state is initialized", async () => {
    withState({ initialized: true, github_oauth_enabled: false });
    render(<LoginPage />);

    expect(await screen.findByLabelText("Email")).toBeInTheDocument();
    const password = screen.getByLabelText("Password");
    expect(password).toHaveAttribute("type", "password");
    expect(password).toHaveAttribute("autocomplete", "current-password");
  });

  it("does NOT render the GitHub button when github_oauth_enabled is false", async () => {
    withState({ initialized: true, github_oauth_enabled: false });
    render(<LoginPage />);

    await screen.findByLabelText("Email");
    expect(
      screen.queryByRole("link", { name: /sign in with github/i }),
    ).not.toBeInTheDocument();
  });

  it("renders the GitHub button pointing at the backend OAuth start when enabled", async () => {
    withState({ initialized: true, github_oauth_enabled: true });
    render(<LoginPage />);

    const link = await screen.findByRole("link", {
      name: /sign in with github/i,
    });
    expect(link).toHaveAttribute("href", "/backend/auth/github/login");
  });

  it("redirects to /setup when the console is not initialized", async () => {
    withState({ initialized: false, github_oauth_enabled: false });
    render(<LoginPage />);

    await waitFor(() => expect(replace).toHaveBeenCalledWith("/setup"));
  });
});
