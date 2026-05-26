import {
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

// SSO-05/06/07 — the Organizations CRUD page. lib/api is mocked so we assert the
// CONTRACT (not a live backend):
//   - the flag-ON body lists orgs fetched via /api/organizations through lib/api
//     (the sole egress — every call path starts with /api/);
//   - create POSTs label + domains[] + linked connection tenant;
//   - a domain-collision (409) and an invalid-domain (422) reject are surfaced
//     VERBATIM in the form and NEVER collapsed into a success (T-14-12);
//   - there is NO Enterprise/license/requires-Ory copy anywhere (SSO-07).

const apiMock = vi.fn();
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, api: (...args: unknown[]) => apiMock(...args) };
});
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

// Force the "organizations" flag ON so FeatureGate renders the real body.
const featuresMock = vi.fn();
vi.mock("@/lib/features", () => ({ useFeatures: () => featuresMock() }));

import { ApiError } from "@/lib/api";
import OrganizationsPage from "./page";

function renderWithClient(ui: React.ReactNode) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

function findPost() {
  return apiMock.mock.calls.find(
    (c) => (c[1] as RequestInit | undefined)?.method === "POST",
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  window.localStorage.clear();
  featuresMock.mockReturnValue({
    data: {
      features: { organizations: { enabled: true, label: "Organizations" } },
    },
  });
});

describe("Organizations page (SSO-05/06/07)", () => {
  it("lists organizations fetched via /api/organizations and shows domains + linked connection", async () => {
    apiMock.mockResolvedValue([
      {
        id: "11111111-1111-1111-1111-111111111111",
        label: "Acme Corp",
        domains: ["acme.com", "acme.co.uk"],
        sso_connection_tenant: "acme",
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
      },
    ]);

    renderWithClient(<OrganizationsPage />);

    await waitFor(() =>
      expect(screen.getByText("Acme Corp")).toBeInTheDocument(),
    );
    expect(apiMock).toHaveBeenCalledWith("/api/organizations");
    expect(screen.getByText("acme.com")).toBeInTheDocument();
    expect(screen.getByText("acme")).toBeInTheDocument();
    // Every egress path is a same-origin /api/ path (no Ory host literal).
    for (const call of apiMock.mock.calls) {
      expect(String(call[0])).toMatch(/^\/api\//);
    }
  });

  it("create POSTs label + domains[] + linked connection tenant", async () => {
    // list call (initial) then the create POST.
    apiMock.mockResolvedValueOnce([]); // initial list
    apiMock.mockResolvedValueOnce({
      id: "22222222-2222-2222-2222-222222222222",
      label: "Beta Inc",
      domains: ["beta.com"],
      sso_connection_tenant: "beta",
      created_at: "2026-01-01T00:00:00Z",
      updated_at: "2026-01-01T00:00:00Z",
    });
    apiMock.mockResolvedValue([]); // any refetch

    renderWithClient(<OrganizationsPage />);

    await userEvent.click(
      await screen.findByRole("button", { name: /create organization/i }),
    );
    const dialog = await screen.findByRole("dialog");

    await userEvent.type(within(dialog).getByLabelText(/^label/i), "Beta Inc");
    await userEvent.type(
      within(dialog).getByLabelText(/verified domains/i),
      "beta.com",
    );
    await userEvent.type(
      within(dialog).getByLabelText(/linked sso connection/i),
      "beta",
    );
    await userEvent.click(
      within(dialog).getByRole("button", { name: /create organization/i }),
    );

    await waitFor(() => expect(findPost()).toBeTruthy());
    const post = findPost()!;
    expect(post[0]).toBe("/api/organizations");
    const body = JSON.parse((post[1] as RequestInit).body as string);
    expect(body.label).toBe("Beta Inc");
    expect(body.domains).toEqual(["beta.com"]);
    expect(body.sso_connection_tenant).toBe("beta");
  });

  it("surfaces a 409 domain-collision VERBATIM and never collapses it into success", async () => {
    apiMock.mockResolvedValueOnce([]); // initial list
    apiMock.mockRejectedValueOnce(new ApiError(409));

    renderWithClient(<OrganizationsPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: /create organization/i }),
    );
    const dialog = await screen.findByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText(/^label/i), "Dup Corp");
    await userEvent.type(
      within(dialog).getByLabelText(/verified domains/i),
      "acme.com",
    );
    await userEvent.click(
      within(dialog).getByRole("button", { name: /create organization/i }),
    );

    const surfaced = await screen.findAllByText(
      /already verified by another organization/i,
    );
    expect(surfaced.length).toBeGreaterThanOrEqual(1);
  });

  it("surfaces a 422 invalid-domain reject VERBATIM", async () => {
    apiMock.mockResolvedValueOnce([]); // initial list
    apiMock.mockRejectedValueOnce(
      new ApiError(422, [
        { path: "", message: "'unknown.example' is not a valid registrable domain." },
      ]),
    );

    renderWithClient(<OrganizationsPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: /create organization/i }),
    );
    const dialog = await screen.findByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText(/^label/i), "Bad Corp");
    await userEvent.type(
      within(dialog).getByLabelText(/verified domains/i),
      "unknown.example",
    );
    await userEvent.click(
      within(dialog).getByRole("button", { name: /create organization/i }),
    );

    const surfaced = await screen.findAllByText(
      /not a valid registrable domain/i,
    );
    expect(surfaced.length).toBeGreaterThanOrEqual(1);
  });

  it("has NO Enterprise/license/requires-Ory copy", async () => {
    apiMock.mockResolvedValue([]);
    const { container } = renderWithClient(<OrganizationsPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: /create organization/i }),
    );
    await screen.findByRole("dialog");
    const text = container.textContent ?? "";
    expect(text).not.toMatch(/enterprise/i);
    expect(text).not.toMatch(/license/i);
    expect(text).not.toMatch(/requires ory/i);
  });

  it("OFF: the flag-disabled state shows the neutral FeatureGate body, no CRUD", () => {
    featuresMock.mockReturnValue({
      data: {
        features: { organizations: { enabled: false, label: "Organizations" } },
      },
    });
    renderWithClient(<OrganizationsPage />);
    expect(screen.getByText("This feature is disabled")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /create organization/i }),
    ).toBeNull();
  });
});
