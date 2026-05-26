import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";

// AUTH-02 — the Passwordless & Passkeys page. Asserts the RP config fields +
// passwordless flags render and that Save PUTs the passkey/webauthn/code
// pointers to /api/config/kratos/passwordless.

const apiMock = vi.fn();
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, api: (...args: unknown[]) => apiMock(...args) };
});
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

import PasswordlessPage from "./page";

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <PasswordlessPage />
    </QueryClientProvider>,
  );
}

beforeEach(() => vi.clearAllMocks());

describe("Authentication / Passwordless (/authentication/passwordless)", () => {
  it("renders passkey + webauthn RP fields and the code passwordless flag", async () => {
    apiMock.mockResolvedValueOnce({});
    renderPage();
    expect(await screen.findByLabelText(/passkey rp id/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/passkey rp display name/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/webauthn rp id/i)).toBeInTheDocument();
    expect(
      screen.getByRole("switch", { name: /code passwordless/i }),
    ).toBeInTheDocument();
  });

  it("Save PUTs the passkey rp id + code passwordless pointers", async () => {
    apiMock.mockResolvedValueOnce({});
    apiMock.mockResolvedValueOnce({ status: "healthy" });
    renderPage();

    const rpId = await screen.findByLabelText(/passkey rp id/i);
    await userEvent.type(rpId, "example.com");
    await userEvent.click(screen.getByRole("button", { name: /save/i }));

    await waitFor(() => {
      const putCall = apiMock.mock.calls.find(
        (c) => (c[1] as RequestInit | undefined)?.method === "PUT",
      );
      expect(putCall).toBeTruthy();
      expect(String(putCall?.[0])).toBe("/api/config/kratos/passwordless");
      const body = JSON.parse((putCall?.[1] as RequestInit).body as string);
      expect(body).toHaveProperty(
        "/selfservice/methods/passkey/config/rp/id",
        "example.com",
      );
      expect(body).toHaveProperty(
        "/selfservice/methods/code/passwordless_enabled",
      );
    });
  });
});
