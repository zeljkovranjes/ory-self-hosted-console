import {
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

// SSO-02/03/04/07 — the SAML Sign-In connection page. lib/api is mocked so we
// assert the CONTRACT (not a live backend):
//   - the flag-ON body lists connections fetched via /api/sso/connections?tenant=
//     through lib/api (the sole egress — every call path starts with /api/);
//   - the clientSecret VALUE is never rendered (only the masked Set/Not set badge
//     echoed from clientSecret_set — T-14-11);
//   - a 422 (CA-missing / SSRF reject) on create is surfaced VERBATIM in the form
//     and is NEVER collapsed into a success (T-14-12);
//   - there is NO "skip signature validation" affordance and NO Enterprise/
//     license/requires-Ory copy anywhere (SSO-07).

const apiMock = vi.fn();
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, api: (...args: unknown[]) => apiMock(...args) };
});
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

// Force the "saml" flag ON so FeatureGate renders the real body.
const featuresMock = vi.fn();
vi.mock("@/lib/features", () => ({ useFeatures: () => featuresMock() }));

import { ApiError } from "@/lib/api";
import SamlSignInPage from "./page";
import { TENANT_REGISTRY_KEY } from "./types";

function renderWithClient(ui: React.ReactNode) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

beforeEach(() => {
  vi.clearAllMocks();
  window.localStorage.clear();
  featuresMock.mockReturnValue({
    data: { features: { saml: { enabled: true, label: "SAML Sign-In" } } },
  });
});

describe("SAML Sign-In page (SSO-02/03/04/07)", () => {
  it("lists connections fetched via /api/sso/connections?tenant= and renders only the masked secret badge", async () => {
    // Seed a remembered tenant so the fetcher fans out to it.
    window.localStorage.setItem(TENANT_REGISTRY_KEY, JSON.stringify(["acme"]));
    apiMock.mockResolvedValue({
      connections: [
        {
          tenant: "acme",
          clientID: "client-abc",
          clientSecret_set: true,
          idpMetadata: {
            entityID: "https://idp.acme.com/entity",
            provider: "okta",
            thumbprint: "AB:CD:EF",
          },
        },
      ],
    });

    renderWithClient(<SamlSignInPage />);

    await waitFor(() =>
      expect(screen.getByText("https://idp.acme.com/entity")).toBeInTheDocument(),
    );
    // The fetch went through lib/api with the per-tenant query path.
    expect(apiMock).toHaveBeenCalledWith(
      "/api/sso/connections?tenant=acme",
    );
    // The masked presence badge shows; no secret value anywhere.
    expect(screen.getByText("Set")).toBeInTheDocument();
    // Every egress path is a same-origin /api/ path (no Polis/Ory host literal).
    for (const call of apiMock.mock.calls) {
      expect(String(call[0])).toMatch(/^\/api\//);
    }
  });

  it("surfaces a 422 CA-missing / SSRF reject VERBATIM and never collapses it into success", async () => {
    apiMock.mockRejectedValue(
      new ApiError(422, [
        {
          path: "metadata_xml",
          message:
            "IdP metadata has no signing certificate; a signing certificate is mandatory.",
        },
      ]),
    );

    renderWithClient(<SamlSignInPage />);

    await userEvent.click(
      await screen.findByRole("button", { name: /create connection/i }),
    );
    const dialog = await screen.findByRole("dialog");

    await userEvent.type(within(dialog).getByLabelText(/connection id/i), "acme");
    await userEvent.type(
      within(dialog).getByLabelText("IdP metadata XML"),
      "<EntityDescriptor/>",
    );
    await userEvent.type(
      within(dialog).getByLabelText(/default redirect url/i),
      "https://console.example.com/saml",
    );
    await userEvent.type(
      within(dialog).getByLabelText(/allowed redirect urls/i),
      "https://console.example.com/saml",
    );
    await userEvent.click(
      within(dialog).getByRole("button", { name: /create connection/i }),
    );

    // The verbatim backend reason is surfaced; NOT collapsed into a success.
    // It appears both inline (field error) and in the destructive banner, so
    // assert at least one occurrence.
    const surfaced = await screen.findAllByText(
      /signing certificate is mandatory/i,
    );
    expect(surfaced.length).toBeGreaterThanOrEqual(1);
  });

  it("has NO skip-signature affordance and NO Enterprise/license/requires-Ory copy", async () => {
    apiMock.mockResolvedValue({ connections: [] });
    const { container } = renderWithClient(<SamlSignInPage />);

    await userEvent.click(
      await screen.findByRole("button", { name: /create connection/i }),
    );
    await screen.findByRole("dialog");

    const text = container.textContent ?? "";
    expect(text).not.toMatch(/enterprise/i);
    expect(text).not.toMatch(/license/i);
    expect(text).not.toMatch(/requires ory/i);
    expect(text).not.toMatch(/skip signature/i);
  });

  it("OFF: the flag-disabled state shows the neutral FeatureGate body, no CRUD", () => {
    featuresMock.mockReturnValue({
      data: { features: { saml: { enabled: false, label: "SAML Sign-In" } } },
    });
    renderWithClient(<SamlSignInPage />);
    expect(screen.getByText("This feature is disabled")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /create connection/i }),
    ).toBeNull();
  });
});
