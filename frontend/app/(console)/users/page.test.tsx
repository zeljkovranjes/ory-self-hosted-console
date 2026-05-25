import {
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

// Component test for the IDENT-01 Users list + detail. We do NOT hit a real
// backend: lib/api.ts's `api()` is mocked so we assert the CONTRACT — the
// DataTable renders identity rows fetched via /api/kratos/identities, search +
// row actions are present, and (critically, T-06-20) credential SECRET material
// is never rendered (only credential TYPE names).

const apiMock = vi.fn();
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, api: (...args: unknown[]) => apiMock(...args) };
});

// next/navigation is used by the detail page + delete action; stub it.
const pushMock = vi.fn();
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock, refresh: vi.fn() }),
  useParams: () => ({ id: "id-1" }),
}));

import UsersPage from "./page";
import { IdentityDetail } from "./[id]/identity-detail";

function renderWithClient(ui: React.ReactNode) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>{ui}</QueryClientProvider>,
  );
}

const sampleRows = [
  {
    id: "id-1",
    schema_id: "default",
    state: "active",
    traits: { email: "alice@example.com" },
    created_at: "2026-01-01T00:00:00Z",
  },
  {
    id: "id-2",
    schema_id: "default",
    state: "inactive",
    traits: { email: "bob@example.com" },
    created_at: "2026-02-01T00:00:00Z",
  },
];

beforeEach(() => {
  vi.clearAllMocks();
});

describe("Users list page (IDENT-01)", () => {
  it("renders identity rows from the mocked /api/kratos/identities fetch", async () => {
    apiMock.mockResolvedValue({
      rows: sampleRows,
      next_token: null,
      total: 2,
    });
    renderWithClient(<UsersPage />);

    await waitFor(() =>
      expect(screen.getByText("alice@example.com")).toBeInTheDocument(),
    );
    expect(screen.getByText("bob@example.com")).toBeInTheDocument();
    // Calls the backend identities list path (not a direct Ory host).
    expect(apiMock).toHaveBeenCalled();
    expect(String(apiMock.mock.calls[0][0])).toContain("/api/kratos/identities");
  });

  it("exposes a search box and Create/Import/Edit-schema header actions", async () => {
    apiMock.mockResolvedValue({ rows: sampleRows, next_token: null, total: 2 });
    renderWithClient(<UsersPage />);
    await waitFor(() =>
      expect(screen.getByText("alice@example.com")).toBeInTheDocument(),
    );

    expect(screen.getByRole("searchbox")).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: /create identity/i }),
    ).toHaveAttribute("href", "/users/new");
    expect(screen.getByRole("link", { name: /import/i })).toHaveAttribute(
      "href",
      "/users/import",
    );
    expect(
      screen.getByRole("link", { name: /edit schema/i }),
    ).toHaveAttribute("href", "/users/schema");
  });

  it("provides per-row view/edit/delete actions", async () => {
    apiMock.mockResolvedValue({ rows: sampleRows, next_token: null, total: 2 });
    renderWithClient(<UsersPage />);
    await waitFor(() =>
      expect(screen.getByText("alice@example.com")).toBeInTheDocument(),
    );

    // Open the first row's kebab menu.
    const kebabs = screen.getAllByRole("button", { name: /open actions/i });
    await userEvent.click(kebabs[0]);
    expect(
      await screen.findByRole("menuitem", { name: /view/i }),
    ).toBeInTheDocument();
    expect(screen.getByRole("menuitem", { name: /edit/i })).toBeInTheDocument();
    expect(
      screen.getByRole("menuitem", { name: /delete/i }),
    ).toBeInTheDocument();
  });
});

describe("Identity detail (IDENT-01) — no secrets", () => {
  const identity = {
    id: "id-1",
    schema_id: "default",
    state: "active",
    traits: { email: "alice@example.com" },
    metadata_public: { tier: "gold" },
    metadata_admin: { internal_note: "VIP" },
    verifiable_addresses: [
      { value: "alice@example.com", verified: true, via: "email" },
    ],
    recovery_addresses: [{ value: "alice@example.com", via: "email" }],
    // Shaped by the backend to TYPE keys only — but assert the UI never renders
    // an inner config string even if one leaked through.
    credentials: { password: {}, oidc: {} },
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-03-01T00:00:00Z",
  };

  it("shows traits, addresses, credential TYPE names, and labels admin metadata", () => {
    renderWithClient(<IdentityDetail identity={identity} />);

    // The identifier appears in several places (header, traits, addresses).
    expect(screen.getAllByText(/alice@example\.com/).length).toBeGreaterThan(0);
    // Credential TYPE names render as chips.
    expect(screen.getByText("password")).toBeInTheDocument();
    expect(screen.getByText("oidc")).toBeInTheDocument();
    // metadata_admin is labeled admin-only.
    expect(screen.getByText(/admin-only/i)).toBeInTheDocument();
    expect(screen.getByText(/VIP/)).toBeInTheDocument();
  });

  it("never renders credential secret config material (T-06-20)", () => {
    const leaky = {
      ...identity,
      credentials: {
        password: { config: { hashed_password: "$argon2id$SECRETHASH" } },
      },
    };
    const { container } = renderWithClient(<IdentityDetail identity={leaky} />);
    expect(container.textContent ?? "").not.toContain("SECRETHASH");
    expect(container.textContent ?? "").not.toContain("hashed_password");
  });
});
