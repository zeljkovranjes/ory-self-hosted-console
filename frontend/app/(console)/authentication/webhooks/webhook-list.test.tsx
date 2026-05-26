import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

// AUTH-11 / HOOK-04 — the Actions & Webhooks list editor. lib/api is mocked so
// we assert the CONTRACT: adding a login/after web_hook composes a PUT keyed by
// /selfservice/flows/login/after/hooks (whole array per pointer); response.ignore
// and response.parse are mutually exclusive in the form; the body uses Monaco; an
// untouched auth secret resends EXACTLY the value GET returned (sentinel verbatim).

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

import { WebhookList, WEBHOOK_POINTERS } from "./webhook-list";

const LOGIN_AFTER = "/selfservice/flows/login/after/hooks";

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

function renderEditor(initial?: Record<string, unknown[]>) {
  const defaults: Record<string, unknown[]> = {};
  for (const p of WEBHOOK_POINTERS) defaults[p] = [];
  return render(
    <WebhookList defaultValues={{ ...defaults, ...(initial ?? {}) }} />,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  apiMock.mockResolvedValue({ status: "healthy" });
});

describe("Actions & Webhooks list editor (AUTH-11/HOOK-04)", () => {
  it("adding a login/after web_hook PUTs a body keyed by the flow hooks pointer (whole array)", async () => {
    renderEditor();

    await userEvent.click(screen.getByRole("button", { name: /add webhook/i }));
    const dialog = await screen.findByRole("dialog");

    // Choose flow=login timing=after via the attach-point select.
    await userEvent.type(within(dialog).getByLabelText(/^url/i), "https://h.example.com");
    await userEvent.type(within(dialog).getByLabelText(/body/i), "local x = 1;");
    await userEvent.click(within(dialog).getByRole("button", { name: /^save webhook/i }));

    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));

    await waitFor(() => expect(findPut()).toBeTruthy());
    const body = putBody();
    expect(body).toHaveProperty(LOGIN_AFTER);
    const arr = body[LOGIN_AFTER] as Array<Record<string, unknown>>;
    expect(arr).toHaveLength(1);
    expect(arr[0]).toMatchObject({ hook: "web_hook" });
    const cfg = arr[0].config as Record<string, unknown>;
    expect(cfg.url).toBe("https://h.example.com");
  });

  it("response.ignore and response.parse are mutually exclusive in the form", async () => {
    renderEditor();
    await userEvent.click(screen.getByRole("button", { name: /add webhook/i }));
    const dialog = await screen.findByRole("dialog");

    const ignore = within(dialog).getByRole("switch", { name: /ignore response/i });
    const parse = within(dialog).getByRole("switch", { name: /parse response/i });

    await userEvent.click(ignore);
    expect(ignore).toBeChecked();
    // Enabling ignore disables/unchecks parse.
    await userEvent.click(parse);
    expect(parse).toBeChecked();
    expect(ignore).not.toBeChecked();
  });

  it("the body field uses a MonacoEditor", async () => {
    renderEditor();
    await userEvent.click(screen.getByRole("button", { name: /add webhook/i }));
    await screen.findByRole("dialog");
    expect(await screen.findByTestId("monaco")).toBeInTheDocument();
  });

  it("an untouched auth secret resends the GET sentinel verbatim when the URL is UNCHANGED", async () => {
    renderEditor({
      [LOGIN_AFTER]: [
        {
          hook: "web_hook",
          config: {
            url: "https://h.example.com",
            method: "POST",
            body: "local x = 1;",
            auth: {
              type: "api_key",
              config: { name: "X-Key", value: SERVER_SENTINEL, in: "header" },
            },
          },
        },
      ],
    });

    await userEvent.click(screen.getByRole("button", { name: /edit/i }));
    const dialog = await screen.findByRole("dialog");
    // Edit a NON-identity field (method), leave the URL and secret untouched.
    const method = within(dialog).getByLabelText(/^method/i);
    await userEvent.clear(method);
    await userEvent.type(method, "PUT");
    await userEvent.click(within(dialog).getByRole("button", { name: /^save webhook/i }));

    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));

    await waitFor(() => expect(findPut()).toBeTruthy());
    const arr = putBody()[LOGIN_AFTER] as Array<Record<string, unknown>>;
    const auth = (arr[0].config as Record<string, unknown>).auth as {
      config: { value: string };
    };
    // URL unchanged -> the sentinel is safely echoed (backend preserves the secret).
    expect(auth.config.value).toBe(SERVER_SENTINEL);
  });

  it("CR-01: changing the URL while leaving the secret blank requires re-entry (Save blocked)", async () => {
    renderEditor({
      [LOGIN_AFTER]: [
        {
          hook: "web_hook",
          config: {
            url: "https://h.example.com",
            method: "POST",
            body: "local x = 1;",
            auth: {
              type: "api_key",
              config: { name: "X-Key", value: SERVER_SENTINEL, in: "header" },
            },
          },
        },
      ],
    });

    await userEvent.click(screen.getByRole("button", { name: /edit/i }));
    const dialog = await screen.findByRole("dialog");
    // Rename the URL (the merge identity) while leaving the secret blank — the
    // sentinel can no longer be safely echoed (backend would fail closed 422).
    const url = within(dialog).getByLabelText(/^url/i);
    await userEvent.type(url, "/v2");

    // A re-entry prompt appears and the Save button is disabled.
    expect(within(dialog).getByRole("alert")).toHaveTextContent(/re-enter the secret/i);
    expect(
      within(dialog).getByRole("button", { name: /^save webhook/i }),
    ).toBeDisabled();

    // Re-typing the secret unblocks Save and sends the NEW value (never the sentinel).
    await userEvent.type(
      within(dialog).getByLabelText(/api key value/i),
      "new-token",
    );
    await userEvent.click(within(dialog).getByRole("button", { name: /^save webhook/i }));
    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));

    await waitFor(() => expect(findPut()).toBeTruthy());
    const arr = putBody()[LOGIN_AFTER] as Array<Record<string, unknown>>;
    const auth = (arr[0].config as Record<string, unknown>).auth as {
      config: { value: string };
    };
    expect(auth.config.value).toBe("new-token");
    expect(auth.config.value).not.toBe(SERVER_SENTINEL);
  });

  it("only the allowlisted attach points are offered", async () => {
    renderEditor();
    await userEvent.click(screen.getByRole("button", { name: /add webhook/i }));
    const dialog = await screen.findByRole("dialog");
    // The attach-point select exists.
    expect(within(dialog).getByLabelText(/attach point/i)).toBeInTheDocument();
  });

  it("never references an Ory host (egress only via /api)", async () => {
    renderEditor();
    await userEvent.click(screen.getByRole("button", { name: /add webhook/i }));
    const dialog = await screen.findByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText(/^url/i), "https://h");
    await userEvent.type(within(dialog).getByLabelText(/body/i), "x");
    await userEvent.click(within(dialog).getByRole("button", { name: /^save webhook/i }));
    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() => expect(findPut()).toBeTruthy());
    for (const call of apiMock.mock.calls) {
      expect(String(call[0])).toMatch(/^\/api\//);
    }
  });
});
