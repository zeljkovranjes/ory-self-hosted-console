import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";

// AUTH-03 — the MFA page. Asserts the required_aal select offers EXACTLY
// aal1/highest_available (NOT highest_aal — 07-RESEARCH Pitfall 1) and that Save
// writes the whoami required_aal pointer. The login required_aal pointer is NOT
// exposed (v26.2.0 schema rejects it — integration-audit finding).

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
  it("the required_aal select offers exactly aal1 and highest_available", async () => {
    apiMock.mockResolvedValueOnce({});
    renderPage();
    const trigger = await screen.findByLabelText(/required aal/i);
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
    await screen.findByLabelText(/required aal/i);
    expect(screen.queryByText("highest_aal")).not.toBeInTheDocument();
  });

  // SettingsForm submits DIRTY-ONLY fields (Phase-10 WR-01 — the backend merges
  // the patch over the loaded doc, so only changed pointers are sent). So this
  // asserts the dirtied pointer reaches the PUT and the dead login AAL pointer is
  // never sent regardless.
  it("Save PUTs only the dirtied pointer to /api/config/kratos/mfa, never the login AAL pointer", async () => {
    apiMock.mockResolvedValueOnce({
      "/session/whoami/required_aal": "highest_available",
    });
    apiMock.mockResolvedValueOnce({ status: "healthy" });
    renderPage();

    const totp = await screen.findByRole("switch", { name: /totp/i });
    await userEvent.click(totp); // dirty the totp pointer

    await userEvent.click(screen.getByRole("button", { name: /save/i }));
    await waitFor(() => {
      const putCall = apiMock.mock.calls.find(
        (c) => (c[1] as RequestInit | undefined)?.method === "PUT",
      );
      expect(putCall).toBeTruthy();
      expect(String(putCall?.[0])).toBe("/api/config/kratos/mfa");
      const body = JSON.parse((putCall?.[1] as RequestInit).body as string);
      expect(body).toHaveProperty("/selfservice/methods/totp/enabled");
      expect(body).not.toHaveProperty("/selfservice/flows/login/required_aal");
    });
  });
});
