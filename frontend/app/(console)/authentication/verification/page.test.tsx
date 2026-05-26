import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";

// AUTH-08 — the Account Verification page. Asserts the `use` select offers
// exactly link/code, the lifespan duration regex blocks an invalid value, and
// Save PUTs to /api/config/kratos/verification.

const apiMock = vi.fn();
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, api: (...args: unknown[]) => apiMock(...args) };
});
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

import VerificationPage from "./page";

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <VerificationPage />
    </QueryClientProvider>,
  );
}

beforeEach(() => vi.clearAllMocks());

const defaults = {
  "/selfservice/flows/verification/use": "code",
  "/selfservice/flows/verification/lifespan": "1h",
};

describe("Authentication / Verification (/authentication/verification)", () => {
  it("the use select offers exactly link and code", async () => {
    apiMock.mockResolvedValueOnce(defaults);
    renderPage();
    const trigger = await screen.findByLabelText(/verification method/i);
    await userEvent.click(trigger);
    const names = (await screen.findAllByRole("option")).map((o) =>
      o.textContent?.trim(),
    );
    expect(names).toEqual(["link", "code"]);
  });

  it("an invalid lifespan blocks submit", async () => {
    apiMock.mockResolvedValueOnce(defaults);
    renderPage();
    const lifespan = await screen.findByLabelText(/verification lifespan/i);
    await userEvent.clear(lifespan);
    await userEvent.type(lifespan, "bad");
    await userEvent.click(screen.getByRole("button", { name: /save/i }));
    expect(
      await screen.findByText(/enter a duration, e\.g\./i),
    ).toBeInTheDocument();
    const putCall = apiMock.mock.calls.find(
      (c) => (c[1] as RequestInit | undefined)?.method === "PUT",
    );
    expect(putCall).toBeUndefined();
  });

  it("Save PUTs only the dirtied pointer to /api/config/kratos/verification", async () => {
    // SettingsForm submits DIRTY-ONLY fields (Phase-10 WR-01 — the backend merges
    // the patch over the loaded doc). Toggling ONLY the enable switch sends ONLY
    // its pointer; the untouched `use` pointer is absent from the PUT body.
    apiMock.mockResolvedValueOnce(defaults);
    apiMock.mockResolvedValueOnce({ status: "healthy" });
    renderPage();
    const enabled = await screen.findByRole("switch", {
      name: /enable verification/i,
    });
    await userEvent.click(enabled);
    await userEvent.click(screen.getByRole("button", { name: /save/i }));
    await waitFor(() => {
      const putCall = apiMock.mock.calls.find(
        (c) => (c[1] as RequestInit | undefined)?.method === "PUT",
      );
      expect(putCall).toBeTruthy();
      expect(String(putCall?.[0])).toBe("/api/config/kratos/verification");
      const body = JSON.parse((putCall?.[1] as RequestInit).body as string);
      expect(body).toHaveProperty("/selfservice/flows/verification/enabled");
      // The untouched `use` pointer is NOT sent (dirty-only).
      expect(body).not.toHaveProperty("/selfservice/flows/verification/use");
    });
  });
});
