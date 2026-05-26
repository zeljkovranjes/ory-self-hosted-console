import {
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

// ACT-04 + OBS-04 — the Logs & events page. Two sources, two tabs:
//   - "Console audit" (always-on) lists /api/console/audit;
//   - "Container logs" (observability-gated) searches Loki via
//     /api/console/logs. lib/api is mocked so we assert the CONTRACT:
//       * the audit tab fetches the console audit log (unchanged);
//       * the container-logs tab OFF -> FeatureGate disabled state;
//       * ON + profile_not_running -> the enable-the-profile affordance (no error);
//       * ON + running -> the Loki lines render.
// Monaco is heavy; stub it so the audit DataTable/dialog path doesn't pull it.

const apiMock = vi.fn();
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, api: (...args: unknown[]) => apiMock(...args) };
});

const featuresMock = vi.fn();
vi.mock("@/lib/features", () => ({ useFeatures: () => featuresMock() }));

vi.mock("@/components/monaco-editor", () => ({
  MonacoEditor: () => null,
}));

import LogsPage from "./page";

function renderWithClient(ui: React.ReactNode) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

function flagOn() {
  featuresMock.mockReturnValue({
    data: {
      features: {
        observability: {
          enabled: true,
          label: "Observability",
          requires_runtime: true,
        },
      },
    },
  });
}

function flagOff() {
  featuresMock.mockReturnValue({
    data: {
      features: { observability: { enabled: false, label: "Observability" } },
    },
  });
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("Logs & events page (ACT-04 + OBS-04)", () => {
  it("the console audit tab fetches /api/console/audit (intact, ungated)", async () => {
    flagOff();
    apiMock.mockResolvedValue([
      {
        id: "11111111-1111-1111-1111-111111111111",
        actor_id: null,
        actor_email: "ops@example.com",
        action: "DELETE /api/hydra/clients/abc",
        method: "DELETE",
        path: "/api/hydra/clients/abc",
        target_type: "oauth2_client",
        target_id: "abc",
        outcome: "success",
        metadata: {},
        created_at: "2026-01-01T00:00:00Z",
      },
    ]);

    renderWithClient(<LogsPage />);

    await waitFor(() => expect(apiMock).toHaveBeenCalled());
    expect(
      apiMock.mock.calls.some((c) =>
        String(c[0]).startsWith("/api/console/audit"),
      ),
    ).toBe(true);
  });

  it("Container logs OFF: shows the FeatureGate disabled state", async () => {
    flagOff();
    apiMock.mockResolvedValue([]);
    renderWithClient(<LogsPage />);

    await userEvent.click(
      screen.getByRole("tab", { name: /container logs/i }),
    );
    expect(
      await screen.findByText("This feature is disabled"),
    ).toBeInTheDocument();
    // No Loki egress while OFF.
    expect(
      apiMock.mock.calls.some((c) => String(c[0]).startsWith("/api/console/logs")),
    ).toBe(false);
  });

  it("Container logs ON + profile_not_running: enable-the-profile affordance, not an error", async () => {
    flagOn();
    apiMock.mockImplementation((path: string) => {
      if (String(path).startsWith("/api/console/logs")) {
        return Promise.resolve({
          source: "loki",
          state: "profile_not_running",
          intent: "all",
          result: null,
        });
      }
      return Promise.resolve([]);
    });

    renderWithClient(<LogsPage />);
    await userEvent.click(
      screen.getByRole("tab", { name: /container logs/i }),
    );

    await waitFor(() =>
      expect(
        screen.getAllByText(/observability profile is not running/i).length,
      ).toBeGreaterThanOrEqual(1),
    );
    expect(
      screen.getAllByText(/docker compose --profile observability up/i).length,
    ).toBeGreaterThanOrEqual(1);
    for (const call of apiMock.mock.calls) {
      expect(String(call[0])).toMatch(/^\/api\/console\//);
    }
  });

  it("Container logs ON + running: renders the Loki lines", async () => {
    flagOn();
    apiMock.mockImplementation((path: string) => {
      if (String(path).startsWith("/api/console/logs")) {
        return Promise.resolve({
          source: "loki",
          state: "running",
          intent: "all",
          result: {
            resultType: "streams",
            result: [
              {
                stream: { service: "backend" },
                values: [["1716000000000000000", "level=info msg=started"]],
              },
            ],
          },
        });
      }
      return Promise.resolve([]);
    });

    renderWithClient(<LogsPage />);
    await userEvent.click(
      screen.getByRole("tab", { name: /container logs/i }),
    );

    await waitFor(() =>
      expect(screen.getByText(/level=info msg=started/i)).toBeInTheDocument(),
    );
  });
});
