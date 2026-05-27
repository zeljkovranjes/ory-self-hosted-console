import {
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

// EVT-01/02/03 — the Event-streams (sink) page. lib/api is mocked so we assert the
// CONTRACT (not a live backend):
//   - the flag-ON body lists sinks via /api/event-sinks through lib/api (the sole
//     egress — every call path starts with /api/);
//   - the list renders a Set/Not set badge and NEVER a raw secret value (T-17-01);
//   - the create form's `kind` select conditionally reveals webhook URL vs
//     NATS/Kafka broker + subject + creds fields;
//   - a 422 SSRF reject on the target is surfaced VERBATIM and NEVER collapsed into
//     a success (T-17-08);
//   - there is NO Enterprise/license/requires-Ory copy anywhere (no-license-copy);
//   - the flag-OFF state renders the neutral FeatureGate body (no CRUD).

const apiMock = vi.fn();
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, api: (...args: unknown[]) => apiMock(...args) };
});
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

const pushMock = vi.fn();
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock, refresh: vi.fn() }),
}));

// Force the "event_streams" flag ON so FeatureGate renders the real body.
const featuresMock = vi.fn();
vi.mock("@/lib/features", () => ({ useFeatures: () => featuresMock() }));

import { ApiError } from "@/lib/api";
import EventStreamsPage from "./page";

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

const RAW_SECRET = "super-secret-hmac-value-do-not-leak";

beforeEach(() => {
  vi.clearAllMocks();
  window.localStorage.clear();
  featuresMock.mockReturnValue({
    data: {
      features: { event_streams: { enabled: true, label: "Event Streams" } },
    },
  });
});

describe("Event-streams page (EVT-01/02/03)", () => {
  it("lists sinks via /api/event-sinks and renders a Set badge, NEVER a raw secret", async () => {
    apiMock.mockResolvedValue([
      {
        id: "11111111-1111-1111-1111-111111111111",
        name: "Acme webhook",
        kind: "webhook",
        target: "https://hooks.acme.com/ory",
        subject: null,
        events: ["identity.created"],
        secret_set: true,
        sasl_username_set: false,
        tls: false,
        enabled: true,
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
      },
    ]);

    const { container } = renderWithClient(<EventStreamsPage />);

    await waitFor(() =>
      expect(screen.getByText("Acme webhook")).toBeInTheDocument(),
    );
    expect(apiMock).toHaveBeenCalledWith("/api/event-sinks");
    // The masked badge is present; no raw secret leaks anywhere in the DOM.
    expect(screen.getByText("Set")).toBeInTheDocument();
    expect(container.textContent ?? "").not.toContain(RAW_SECRET);
    // Every egress path is a same-origin /api/ path (no Ory host literal).
    for (const call of apiMock.mock.calls) {
      expect(String(call[0])).toMatch(/^\/api\//);
    }
  });

  it("the create form's kind select conditionally shows webhook URL vs NATS broker+subject fields", async () => {
    apiMock.mockResolvedValue([]);
    renderWithClient(<EventStreamsPage />);

    await userEvent.click(
      await screen.findByRole("button", { name: /create sink/i }),
    );
    const dialog = await screen.findByRole("dialog");

    // Default kind = webhook → URL label, NO subject field.
    expect(within(dialog).getByLabelText(/^url/i)).toBeInTheDocument();
    expect(within(dialog).queryByLabelText(/^subject/i)).toBeNull();

    // Switch the kind to NATS → broker URL + subject + credential fields appear.
    await userEvent.click(within(dialog).getByLabelText(/sink kind/i));
    await userEvent.click(await screen.findByRole("option", { name: /nats/i }));

    await waitFor(() =>
      expect(within(dialog).getByLabelText(/^subject/i)).toBeInTheDocument(),
    );
    expect(within(dialog).getByLabelText(/broker url/i)).toBeInTheDocument();
    expect(
      within(dialog).getByLabelText(/credential|token/i),
    ).toBeInTheDocument();
  });

  it("create POSTs to /api/event-sinks with kind + target + events", async () => {
    apiMock.mockResolvedValueOnce([]); // initial list
    apiMock.mockResolvedValueOnce({
      name: "New hook",
      secret: "one-time-shown-secret",
    });
    apiMock.mockResolvedValue([]); // refetch

    renderWithClient(<EventStreamsPage />);

    await userEvent.click(
      await screen.findByRole("button", { name: /create sink/i }),
    );
    const dialog = await screen.findByRole("dialog");

    await userEvent.type(within(dialog).getByLabelText(/^name/i), "New hook");
    await userEvent.type(
      within(dialog).getByLabelText(/^url/i),
      "https://hooks.example.com/ory",
    );
    // Pick one event.
    await userEvent.click(within(dialog).getByRole("button", { name: /select events/i }));
    await userEvent.click(
      await screen.findByRole("menuitemcheckbox", { name: /identity\.created/i }),
    );
    // Close the menu then submit.
    await userEvent.keyboard("{Escape}");
    await userEvent.click(within(dialog).getByRole("button", { name: /^create sink$/i }));

    await waitFor(() => expect(findPost()).toBeTruthy());
    const post = findPost()!;
    expect(post[0]).toBe("/api/event-sinks");
    const body = JSON.parse((post[1] as RequestInit).body as string);
    expect(body.kind).toBe("webhook");
    expect(body.target).toBe("https://hooks.example.com/ory");
    expect(body.events).toContain("identity.created");
  });

  it("surfaces a 422 SSRF reject VERBATIM and does NOT close as success", async () => {
    apiMock.mockResolvedValueOnce([]); // initial list
    apiMock.mockRejectedValueOnce(
      new ApiError(422, [
        {
          path: "target",
          message:
            "This URL resolves to a loopback address and is not allowed.",
        },
      ]),
    );

    renderWithClient(<EventStreamsPage />);

    await userEvent.click(
      await screen.findByRole("button", { name: /create sink/i }),
    );
    const dialog = await screen.findByRole("dialog");

    await userEvent.type(within(dialog).getByLabelText(/^name/i), "SSRF hook");
    await userEvent.type(
      within(dialog).getByLabelText(/^url/i),
      "http://127.0.0.1/hook",
    );
    await userEvent.click(within(dialog).getByRole("button", { name: /select events/i }));
    await userEvent.click(
      await screen.findByRole("menuitemcheckbox", { name: /identity\.created/i }),
    );
    await userEvent.keyboard("{Escape}");
    await userEvent.click(within(dialog).getByRole("button", { name: /^create sink$/i }));

    // The reject is surfaced verbatim (banner + inline) and the dialog stays open.
    const surfaced = await screen.findAllByText(
      /resolves to a loopback address and is not allowed/i,
    );
    expect(surfaced.length).toBeGreaterThanOrEqual(1);
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("has NO Enterprise/license/requires-Ory copy", async () => {
    apiMock.mockResolvedValue([]);
    const { container } = renderWithClient(<EventStreamsPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: /create sink/i }),
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
        features: { event_streams: { enabled: false, label: "Event Streams" } },
      },
    });
    renderWithClient(<EventStreamsPage />);
    expect(screen.getByText("This feature is disabled")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /create sink/i }),
    ).toBeNull();
  });
});
