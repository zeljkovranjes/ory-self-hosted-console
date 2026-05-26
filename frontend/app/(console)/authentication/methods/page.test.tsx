import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";

// AUTH-01 — the Methods page binds a SettingsForm to /api/config/kratos/methods.
// lib/api is mocked so we assert the CONTRACT: 9 method switches render; the GET
// prefills current enabled state; toggling password + Save PUTs a flat object
// keyed by /selfservice/methods/<m>/enabled; a 422 surfaces inline.

const apiMock = vi.fn();
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, api: (...args: unknown[]) => apiMock(...args) };
});
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

import { ApiError } from "@/lib/api";
import MethodsPage from "./page";

function renderPage() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <MethodsPage />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("Authentication / Methods (/authentication/methods)", () => {
  it("renders a switch for each of the 9 auth methods", async () => {
    apiMock.mockResolvedValueOnce({ "/selfservice/methods/password/enabled": true });
    renderPage();

    for (const label of [
      /password/i,
      /one-time code/i,
      /social sign-in/i,
      /totp/i,
      /backup codes/i,
      /webauthn/i,
      /passkey/i,
      /magic link/i,
      /profile/i,
    ]) {
      expect(await screen.findByRole("switch", { name: label })).toBeInTheDocument();
    }
  });

  it("prefills the current enabled state from the GET", async () => {
    apiMock.mockResolvedValueOnce({
      "/selfservice/methods/password/enabled": true,
      "/selfservice/methods/oidc/enabled": false,
    });
    renderPage();
    const password = await screen.findByRole("switch", { name: /password/i });
    expect(password).toBeChecked();
    const oidc = screen.getByRole("switch", { name: /social sign-in/i });
    expect(oidc).not.toBeChecked();
  });

  it("Save PUTs only the dirtied pointer keyed by /selfservice/methods/<m>/enabled", async () => {
    // SettingsForm submits DIRTY-ONLY fields (Phase-10 WR-01 — the backend merges
    // the patch over the loaded doc). Toggling ONLY the password switch sends ONLY
    // its pointer; the untouched oidc pointer is absent from the PUT body.
    apiMock.mockResolvedValueOnce({ "/selfservice/methods/password/enabled": false });
    apiMock.mockResolvedValueOnce({ status: "healthy" });
    renderPage();

    const password = await screen.findByRole("switch", { name: /password/i });
    await userEvent.click(password); // toggle to true (dirties only this pointer)
    await userEvent.click(screen.getByRole("button", { name: /save/i }));

    await waitFor(() => {
      const putCall = apiMock.mock.calls.find(
        (c) => (c[1] as RequestInit | undefined)?.method === "PUT",
      );
      expect(putCall).toBeTruthy();
      expect(String(putCall?.[0])).toBe("/api/config/kratos/methods");
      const body = JSON.parse((putCall?.[1] as RequestInit).body as string);
      expect(body).toHaveProperty("/selfservice/methods/password/enabled", true);
      // The untouched oidc pointer is NOT sent (dirty-only).
      expect(body).not.toHaveProperty("/selfservice/methods/oidc/enabled");
    });
  });

  it("surfaces a backend 422 inline", async () => {
    apiMock.mockResolvedValueOnce({ "/selfservice/methods/webauthn/enabled": false });
    apiMock.mockRejectedValueOnce(
      new ApiError(422, [
        {
          path: "/selfservice/methods/webauthn/enabled",
          message: "webauthn requires RP config",
        },
      ]),
    );
    renderPage();

    const webauthn = await screen.findByRole("switch", { name: /webauthn/i });
    await userEvent.click(webauthn);
    await userEvent.click(screen.getByRole("button", { name: /save/i }));

    expect(
      await screen.findByText(/webauthn requires rp config/i),
    ).toBeInTheDocument();
  });

  it("does not reference any Ory host (egress only via /api/config)", async () => {
    apiMock.mockResolvedValueOnce({});
    renderPage();
    await screen.findByRole("switch", { name: /password/i });
    for (const call of apiMock.mock.calls) {
      expect(String(call[0])).toMatch(/^\/api\/config\//);
    }
  });
});
