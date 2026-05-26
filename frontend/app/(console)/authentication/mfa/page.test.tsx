import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";

// AUTH-03 — the MFA page. Asserts the required_aal selects offer EXACTLY
// aal1/highest_available (NOT highest_aal — 07-RESEARCH Pitfall 1) and that Save
// writes the login + whoami required_aal pointers.

const apiMock = vi.fn();
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, api: (...args: unknown[]) => apiMock(...args) };
});
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

import MfaPage from "./page";

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MfaPage />
    </QueryClientProvider>,
  );
}

beforeEach(() => vi.clearAllMocks());

describe("Authentication / MFA (/authentication/mfa)", () => {
  it("the login required_aal select offers exactly aal1 and highest_available", async () => {
    apiMock.mockResolvedValueOnce({});
    renderPage();
    const trigger = await screen.findByLabelText(/login.*required aal/i);
    await userEvent.click(trigger);
    const names = (await screen.findAllByRole("option")).map((o) =>
      o.textContent?.trim(),
    );
    expect(names).toEqual(["aal1", "highest_available"]);
    expect(names).not.toContain("highest_aal");
  });

  it("does NOT offer highest_aal anywhere on the page", async () => {
    apiMock.mockResolvedValueOnce({});
    renderPage();
    await screen.findByLabelText(/login.*required aal/i);
    expect(screen.queryByText("highest_aal")).not.toBeInTheDocument();
  });

  it("Save writes login + whoami required_aal pointers to /api/config/kratos/mfa", async () => {
    apiMock.mockResolvedValueOnce({
      "/selfservice/flows/login/required_aal": "highest_available",
    });
    apiMock.mockResolvedValueOnce({ status: "healthy" });
    renderPage();

    const totp = await screen.findByRole("switch", { name: /totp/i });
    await userEvent.click(totp); // dirty the form

    await userEvent.click(screen.getByRole("button", { name: /save/i }));
    await waitFor(() => {
      const putCall = apiMock.mock.calls.find(
        (c) => (c[1] as RequestInit | undefined)?.method === "PUT",
      );
      expect(putCall).toBeTruthy();
      expect(String(putCall?.[0])).toBe("/api/config/kratos/mfa");
      const body = JSON.parse((putCall?.[1] as RequestInit).body as string);
      expect(body).toHaveProperty("/selfservice/flows/login/required_aal");
      expect(body).toHaveProperty("/session/whoami/required_aal");
    });
  });
});
