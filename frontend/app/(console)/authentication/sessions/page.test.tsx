import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";

// AUTH-06 — the Sessions page binds a SettingsForm to /api/config/kratos/sessions.
// Asserts: lifespan duration regex blocks an invalid value; same_site offers
// exactly Strict/Lax/None; Save PUTs to the sessions section.

const apiMock = vi.fn();
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, api: (...args: unknown[]) => apiMock(...args) };
});
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

import SessionsPage from "./page";

function renderPage() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <SessionsPage />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
});

const defaults = {
  "/session/lifespan": "24h",
  "/session/cookie/same_site": "Lax",
};

describe("Authentication / Sessions (/authentication/sessions)", () => {
  it("an invalid lifespan blocks submit with an inline Zod error", async () => {
    apiMock.mockResolvedValueOnce(defaults);
    renderPage();

    const lifespan = await screen.findByLabelText(/session lifespan/i);
    await userEvent.clear(lifespan);
    await userEvent.type(lifespan, "24x");
    await userEvent.click(screen.getByRole("button", { name: /save/i }));

    expect(
      await screen.findByText(/duration like|invalid duration|e\.g\./i),
    ).toBeInTheDocument();
    const putCall = apiMock.mock.calls.find(
      (c) => (c[1] as RequestInit | undefined)?.method === "PUT",
    );
    expect(putCall).toBeUndefined();
  });

  it("the same_site select offers exactly Strict / Lax / None", async () => {
    apiMock.mockResolvedValueOnce(defaults);
    renderPage();

    const trigger = await screen.findByLabelText(/same.?site/i);
    await userEvent.click(trigger);
    const options = await screen.findAllByRole("option");
    const names = options.map((o) => o.textContent?.trim());
    expect(names).toEqual(["Strict", "Lax", "None"]);
  });

  it("Save PUTs a valid lifespan to /api/config/kratos/sessions", async () => {
    apiMock.mockResolvedValueOnce(defaults);
    apiMock.mockResolvedValueOnce({ status: "healthy" });
    renderPage();

    const lifespan = await screen.findByLabelText(/session lifespan/i);
    await userEvent.clear(lifespan);
    await userEvent.type(lifespan, "48h");
    await userEvent.click(screen.getByRole("button", { name: /save/i }));

    await waitFor(() => {
      const putCall = apiMock.mock.calls.find(
        (c) => (c[1] as RequestInit | undefined)?.method === "PUT",
      );
      expect(putCall).toBeTruthy();
      expect(String(putCall?.[0])).toBe("/api/config/kratos/sessions");
      const body = JSON.parse((putCall?.[1] as RequestInit).body as string);
      expect(body["/session/lifespan"]).toBe("48h");
    });
  });
});
