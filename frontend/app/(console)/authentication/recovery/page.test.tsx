import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";

// AUTH-07 — the Account Recovery page. Asserts the `use` select offers exactly
// link/code, the lifespan duration regex blocks an invalid value, and Save PUTs
// to /api/config/kratos/recovery.

const apiMock = vi.fn();
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, api: (...args: unknown[]) => apiMock(...args) };
});
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

import RecoveryPage from "./page";

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <RecoveryPage />
    </QueryClientProvider>,
  );
}

beforeEach(() => vi.clearAllMocks());

const defaults = {
  "/selfservice/flows/recovery/use": "code",
  "/selfservice/flows/recovery/lifespan": "1h",
};

describe("Authentication / Recovery (/authentication/recovery)", () => {
  it("the use select offers exactly link and code", async () => {
    apiMock.mockResolvedValueOnce(defaults);
    renderPage();
    const trigger = await screen.findByLabelText(/recovery method/i);
    await userEvent.click(trigger);
    const names = (await screen.findAllByRole("option")).map((o) =>
      o.textContent?.trim(),
    );
    expect(names).toEqual(["link", "code"]);
  });

  it("an invalid lifespan blocks submit", async () => {
    apiMock.mockResolvedValueOnce(defaults);
    renderPage();
    const lifespan = await screen.findByLabelText(/recovery lifespan/i);
    await userEvent.clear(lifespan);
    await userEvent.type(lifespan, "nope");
    await userEvent.click(screen.getByRole("button", { name: /save/i }));
    expect(
      await screen.findByText(/enter a duration, e\.g\./i),
    ).toBeInTheDocument();
    const putCall = apiMock.mock.calls.find(
      (c) => (c[1] as RequestInit | undefined)?.method === "PUT",
    );
    expect(putCall).toBeUndefined();
  });

  it("Save PUTs to /api/config/kratos/recovery", async () => {
    apiMock.mockResolvedValueOnce(defaults);
    apiMock.mockResolvedValueOnce({ status: "healthy" });
    renderPage();
    const enabled = await screen.findByRole("switch", { name: /enable recovery/i });
    await userEvent.click(enabled);
    await userEvent.click(screen.getByRole("button", { name: /save/i }));
    await waitFor(() => {
      const putCall = apiMock.mock.calls.find(
        (c) => (c[1] as RequestInit | undefined)?.method === "PUT",
      );
      expect(putCall).toBeTruthy();
      expect(String(putCall?.[0])).toBe("/api/config/kratos/recovery");
      const body = JSON.parse((putCall?.[1] as RequestInit).body as string);
      expect(body).toHaveProperty("/selfservice/flows/recovery/enabled");
      expect(body).toHaveProperty("/selfservice/flows/recovery/use");
    });
  });
});
