import {
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

// OBS-03 — the Prometheus-backed Activity dashboard. lib/api is mocked so we
// assert the CONTRACT (the two gating layers + the metric panels), not a live
// backend:
//   - flag OFF  -> FeatureGate disabled state, NO metrics fetch;
//   - flag ON + profile_not_running payload -> the ProfileNotRunning affordance
//     (the enable-the-profile instruction), NEVER an error/crash;
//   - flag ON + running -> the Prometheus series render as metric panels.
// Every egress path is the same-origin /api/console/metrics/activity (no host).

const apiMock = vi.fn();
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, api: (...args: unknown[]) => apiMock(...args) };
});

const featuresMock = vi.fn();
vi.mock("@/lib/features", () => ({ useFeatures: () => featuresMock() }));

import ActivityPage from "./page";

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

beforeEach(() => {
  vi.clearAllMocks();
});

describe("Activity dashboard (OBS-03)", () => {
  it("OFF: renders the FeatureGate disabled state and never fetches metrics", () => {
    featuresMock.mockReturnValue({
      data: {
        features: { observability: { enabled: false, label: "Observability" } },
      },
    });
    renderWithClient(<ActivityPage />);
    expect(screen.getByText("This feature is disabled")).toBeInTheDocument();
    expect(apiMock).not.toHaveBeenCalled();
  });

  it("ON + profile_not_running: shows the enable-the-profile affordance, not an error", async () => {
    flagOn();
    apiMock.mockResolvedValue({
      source: "prometheus",
      state: "profile_not_running",
      intent: "login-rate",
      result: null,
    });

    renderWithClient(<ActivityPage />);

    await waitFor(() =>
      expect(
        screen.getAllByText(/observability profile is not running/i).length,
      ).toBeGreaterThanOrEqual(1),
    );
    expect(
      screen.getAllByText(/docker compose --profile observability up/i).length,
    ).toBeGreaterThanOrEqual(1);
    // Every egress path is a same-origin /api/console/ path (no host literal).
    for (const call of apiMock.mock.calls) {
      expect(String(call[0])).toMatch(/^\/api\/console\/metrics\/activity/);
    }
  });

  it("ON + running: renders the Prometheus series as metric panels", async () => {
    flagOn();
    apiMock.mockResolvedValue({
      source: "prometheus",
      state: "running",
      intent: "login-rate",
      result: {
        resultType: "matrix",
        result: [
          {
            metric: { result: "success" },
            values: [
              [1716000000, "0.5"],
              [1716000060, "0.75"],
            ],
          },
        ],
      },
    });

    renderWithClient(<ActivityPage />);

    await waitFor(() =>
      expect(screen.getAllByText("success").length).toBeGreaterThanOrEqual(1),
    );
    // The latest sample value (0.750) renders in a panel.
    expect(screen.getAllByText("0.750").length).toBeGreaterThanOrEqual(1);
    expect(
      screen.getByText(/Login attempts \/ sec/i),
    ).toBeInTheDocument();
  });
});
