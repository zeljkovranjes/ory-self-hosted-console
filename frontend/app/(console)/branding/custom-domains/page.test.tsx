import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";

// AX-04 — Custom Domains editor. @/lib/api is mocked so we assert the CONTRACT:
//   - the flag-ON body mounts the base_url/allowed-returns editor (ConfigSection
//     over /api/config/kratos/ui-urls) plus the snippet + reachability panels;
//   - the reverse-proxy snippet GETs /api/account-experience/reverse-proxy-snippet
//     through lib/api and renders the returned string;
//   - the reachability check POSTs /api/account-experience/reachability via
//     lib/api, and a 422 SSRF rejection surfaces INLINE (never a reachable result);
//   - flag OFF shows the neutral FeatureGate body with no editor/controls;
//   - there is NO Enterprise/license/requires-Ory copy and NO TLS/DNS provisioning
//     framing (FLAG-03/SSO-07). Every egress is a same-origin /api/ path.

const apiMock = vi.fn();
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, api: (...args: unknown[]) => apiMock(...args) };
});
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

// Drive the account_experience flag via the single client source of truth.
const featuresMock = vi.fn();
vi.mock("@/lib/features", () => ({ useFeatures: () => featuresMock() }));

import { ApiError } from "@/lib/api";
import CustomDomainsPage from "./page";

function renderPage() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <CustomDomainsPage />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  featuresMock.mockReturnValue({
    data: {
      features: {
        account_experience: { enabled: true, label: "Account Experience" },
      },
    },
  });
});

describe("Custom Domains page (AX-04)", () => {
  it("mounts the base URL editor (ConfigSection over /api/config/kratos/ui-urls)", async () => {
    apiMock.mockResolvedValue({ "/serve/public/base_url": "" });
    renderPage();

    // The public base URL field is present (the custom-domain rebind target).
    expect(
      await screen.findByLabelText(/public base url \(issuer\)/i),
    ).toBeInTheDocument();
    // The ConfigSection loaded the ui-urls section.
    await waitFor(() =>
      expect(apiMock).toHaveBeenCalledWith("/api/config/kratos/ui-urls"),
    );
    // Every egress is a same-origin /api/ path.
    for (const call of apiMock.mock.calls) {
      expect(String(call[0])).toMatch(/^\/api\//);
    }
  });

  it("generates a reverse-proxy snippet via GET /api/account-experience/reverse-proxy-snippet", async () => {
    apiMock.mockResolvedValueOnce({ "/serve/public/base_url": "" }); // ConfigSection load
    apiMock.mockResolvedValueOnce({
      snippet: "# nginx\nserver { server_name accounts.example.com; }",
    });
    renderPage();

    const host = await screen.findByLabelText(
      /custom domain for the reverse-proxy snippet/i,
    );
    await userEvent.type(host, "accounts.example.com");
    await userEvent.click(
      screen.getByRole("button", { name: /generate snippet/i }),
    );

    await waitFor(() => {
      const call = apiMock.mock.calls.find((c) =>
        String(c[0]).startsWith("/api/account-experience/reverse-proxy-snippet"),
      );
      expect(call).toBeTruthy();
      expect(String(call?.[0])).toContain("host=accounts.example.com");
    });
    expect(
      await screen.findByLabelText(/reverse-proxy guidance snippet/i),
    ).toHaveTextContent(/server_name accounts\.example\.com/i);
  });

  it("routes the reachability check through lib/api (POST /api/account-experience/reachability)", async () => {
    apiMock.mockResolvedValueOnce({ "/serve/public/base_url": "" }); // ConfigSection load
    apiMock.mockResolvedValueOnce({ reachable: true, status: 200 });
    renderPage();

    const urlInput = await screen.findByLabelText(
      /url to check for reachability/i,
    );
    await userEvent.type(urlInput, "https://accounts.example.com/health/ready");
    await userEvent.click(
      screen.getByRole("button", { name: /check reachability/i }),
    );

    await waitFor(() =>
      expect(apiMock).toHaveBeenCalledWith(
        "/api/account-experience/reachability",
        expect.objectContaining({ method: "POST" }),
      ),
    );
    const putCall = apiMock.mock.calls.find(
      (c) => (c[1] as RequestInit | undefined)?.method === "POST",
    );
    const body = JSON.parse((putCall?.[1] as RequestInit).body as string);
    expect(body.url).toBe("https://accounts.example.com/health/ready");
    // The success banner title is exactly "Reachable" (the prose elsewhere also
    // contains the word — target the title node specifically).
    expect(await screen.findByText("Reachable")).toBeInTheDocument();
    expect(screen.getByText(/HTTP 200/i)).toBeInTheDocument();
  });

  it("surfaces an SSRF rejection (422) INLINE and never collapses it into a reachable result (T-15-15)", async () => {
    apiMock.mockResolvedValueOnce({ "/serve/public/base_url": "" }); // ConfigSection load
    apiMock.mockRejectedValueOnce(
      new ApiError(422, [
        {
          path: "/",
          message:
            "This URL resolves to a private, loopback, or cloud-metadata address and is not allowed.",
        },
      ]),
    );
    renderPage();

    const urlInput = await screen.findByLabelText(
      /url to check for reachability/i,
    );
    await userEvent.type(urlInput, "http://kratos:4434/admin/identities");
    await userEvent.click(
      screen.getByRole("button", { name: /check reachability/i }),
    );

    expect(
      await screen.findByText(
        /resolves to a private, loopback, or cloud-metadata address/i,
      ),
    ).toBeInTheDocument();
    expect(screen.getByText(/url rejected/i)).toBeInTheDocument();
    // NOT collapsed into a reachable result.
    expect(screen.queryByText(/^reachable$/i)).toBeNull();
  });

  it("OFF: shows the neutral FeatureGate body with no editor or controls", () => {
    featuresMock.mockReturnValue({
      data: {
        features: {
          account_experience: { enabled: false, label: "Account Experience" },
        },
      },
    });
    renderPage();
    expect(screen.getByText("This feature is disabled")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /check reachability/i }),
    ).toBeNull();
    expect(
      screen.queryByRole("button", { name: /generate snippet/i }),
    ).toBeNull();
  });

  it("has NO Enterprise/license/requires-Ory copy and no TLS/DNS provisioning", async () => {
    apiMock.mockResolvedValue({ "/serve/public/base_url": "" });
    const { container } = renderPage();
    await screen.findByLabelText(/public base url \(issuer\)/i);
    const text = container.textContent ?? "";
    expect(text).not.toMatch(/enterprise/i);
    expect(text).not.toMatch(/license/i);
    expect(text).not.toMatch(/requires ory/i);
    // It explicitly states the operator owns TLS/DNS (no provisioning claim).
    expect(text).toMatch(/owned by your reverse proxy/i);
    expect(text).not.toMatch(/provisions? (certificates|tls|dns) for you/i);
  });
});
