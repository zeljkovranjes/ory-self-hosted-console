import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";

// AUTH-10 — SMS page. A single http channel (id `sms`, type `http`) with a
// Monaco Jsonnet request body and a write-only auth secret. Save composes the
// whole `/courier/channels` array. An untouched auth secret resends EXACTLY the
// value GET returned (the server sentinel echoed verbatim).

const SERVER_SENTINEL = "__ory_console_masked__";

const apiMock = vi.fn();
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, api: (...args: unknown[]) => apiMock(...args) };
});
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

vi.mock("@/components/monaco-editor", () => ({
  MonacoEditor: (props: {
    value: string;
    onChange: (v: string) => void;
    ariaLabel?: string;
  }) => (
    <textarea
      data-testid="monaco"
      aria-label={props.ariaLabel}
      value={props.value}
      onChange={(e) => props.onChange(e.target.value)}
    />
  ),
}));

import SmsPage from "./page";

const CHANNELS_PTR = "/courier/channels";

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <SmsPage />
    </QueryClientProvider>,
  );
}

function findPut() {
  return apiMock.mock.calls.find(
    (c) => (c[1] as RequestInit | undefined)?.method === "PUT",
  );
}
function putBody() {
  return JSON.parse(
    (findPut()?.[1] as RequestInit).body as string,
  ) as Record<string, unknown>;
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("Authentication / SMS (AUTH-10)", () => {
  it("the request body uses a MonacoEditor", async () => {
    apiMock.mockResolvedValueOnce({});
    renderPage();
    expect(await screen.findByTestId("monaco")).toBeInTheDocument();
  });

  it("Save PUTs a /courier/channels array with id `sms` / type `http`", async () => {
    apiMock.mockResolvedValueOnce({}); // GET (no channel yet)
    apiMock.mockResolvedValueOnce({ status: "healthy" }); // PUT
    renderPage();

    const url = await screen.findByLabelText(/request url/i);
    await userEvent.type(url, "https://sms.example.com/send");
    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));

    await waitFor(() => expect(findPut()).toBeTruthy());
    const body = putBody();
    expect(body).toHaveProperty(CHANNELS_PTR);
    const arr = body[CHANNELS_PTR] as Array<Record<string, unknown>>;
    expect(arr).toHaveLength(1);
    expect(arr[0]).toMatchObject({ id: "sms", type: "http" });
    const rc = arr[0].request_config as Record<string, unknown>;
    expect(rc.url).toBe("https://sms.example.com/send");
  });

  it("an untouched auth secret is resent EXACTLY as GET returned it (sentinel echoed verbatim)", async () => {
    apiMock.mockResolvedValueOnce({
      [CHANNELS_PTR]: [
        {
          id: "sms",
          type: "http",
          request_config: {
            url: "https://sms.example.com/send",
            method: "POST",
            body: "local x = 1;",
            auth: {
              type: "basic_auth",
              config: { user: "u", password: SERVER_SENTINEL },
            },
          },
        },
      ],
    });
    apiMock.mockResolvedValueOnce({ status: "healthy" });
    renderPage();

    // Touch a non-secret field to dirty the form, leave the secret blank.
    const url = await screen.findByLabelText(/request url/i);
    await userEvent.type(url, "X");
    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));

    await waitFor(() => expect(findPut()).toBeTruthy());
    const arr = putBody()[CHANNELS_PTR] as Array<Record<string, unknown>>;
    const auth = (arr[0].request_config as Record<string, unknown>).auth as {
      config: { password: string };
    };
    expect(auth.config.password).toBe(SERVER_SENTINEL);
  });

  it("never references an Ory host (egress only via /api)", async () => {
    apiMock.mockResolvedValueOnce({});
    apiMock.mockResolvedValueOnce({ status: "healthy" });
    renderPage();
    const url = await screen.findByLabelText(/request url/i);
    await userEvent.type(url, "https://x");
    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() => expect(findPut()).toBeTruthy());
    for (const call of apiMock.mock.calls) {
      expect(String(call[0])).toMatch(/^\/api\//);
    }
  });
});
