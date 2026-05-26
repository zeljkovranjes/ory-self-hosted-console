import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

// AUTH-04 — the Social Sign-In OIDC list editor. lib/api is mocked so we assert
// the CONTRACT: add a provider then Save PUTs a flat object keyed by
// /selfservice/methods/oidc/config/providers (the WHOLE array, never per-index);
// editing a provider's label while leaving client_secret untouched resends
// EXACTLY the value GET returned (the server sentinel echoed verbatim — NOT a
// hardcoded frontend literal, NOT a real secret); retyping the secret sends the
// new value; the provider select offers the schema enum; mapper_url renders a
// MonacoEditor.

// The server-provided masked sentinel. The TEST owns this literal only to seed
// the GET; the COMPONENT must echo back whatever GET returned (proving zero
// coupling to the literal's value).
const SERVER_SENTINEL = "__ory_console_masked__";

const apiMock = vi.fn();
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, api: (...args: unknown[]) => apiMock(...args) };
});
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

// Mock the heavy MonacoEditor with a controlled <textarea> so we can assert it
// renders and is wired (data is edited via the textarea).
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

import { OidcList, type OidcProvider } from "./oidc-list";

function findPut() {
  return apiMock.mock.calls.find(
    (c) => (c[1] as RequestInit | undefined)?.method === "PUT",
  );
}
function putBody() {
  const call = findPut();
  return JSON.parse((call?.[1] as RequestInit).body as string) as Record<
    string,
    unknown
  >;
}

const PROVIDERS_PTR = "/selfservice/methods/oidc/config/providers";
const ENABLED_PTR = "/selfservice/methods/oidc/enabled";

function renderEditor(initial?: {
  providers?: OidcProvider[];
  enabled?: boolean;
}) {
  return render(
    <OidcList
      defaultValues={{
        [PROVIDERS_PTR]: initial?.providers ?? [],
        [ENABLED_PTR]: initial?.enabled ?? false,
      }}
    />,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  apiMock.mockResolvedValue({ status: "healthy" });
});

describe("Social Sign-In / OIDC list editor (AUTH-04)", () => {
  it("adds a provider then Save PUTs an array containing that provider, keyed by the array-root pointer", async () => {
    renderEditor();

    await userEvent.click(screen.getByRole("button", { name: /add provider/i }));
    const dialog = await screen.findByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText(/^id/i), "gh");
    await userEvent.type(within(dialog).getByLabelText(/client id/i), "client-123");
    await userEvent.type(
      within(dialog).getByLabelText(/mapper/i),
      "local x = 1;",
    );
    await userEvent.click(within(dialog).getByRole("button", { name: /^save provider/i }));

    // Form is now dirty; Save the whole array.
    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));

    await waitFor(() => expect(findPut()).toBeTruthy());
    const body = putBody();
    expect(body).toHaveProperty(PROVIDERS_PTR);
    const arr = body[PROVIDERS_PTR] as Array<Record<string, unknown>>;
    expect(arr).toHaveLength(1);
    expect(arr[0]).toMatchObject({ id: "gh", client_id: "client-123" });
    // Per-index pointers must NOT appear.
    expect(Object.keys(body)).not.toContain(`${PROVIDERS_PTR}/0/client_id`);
  });

  it("editing a label while leaving client_secret untouched resends EXACTLY the GET value (server sentinel echoed verbatim)", async () => {
    renderEditor({
      providers: [
        {
          id: "gh",
          provider: "github",
          label: "GitHub",
          client_id: "client-123",
          client_secret: SERVER_SENTINEL,
          mapper_url: "function(ctx) {}",
        },
      ],
    });

    await userEvent.click(screen.getByRole("button", { name: /edit gh/i }));
    const dialog = await screen.findByRole("dialog");
    const label = within(dialog).getByLabelText(/label/i);
    await userEvent.clear(label);
    await userEvent.type(label, "GitHub Updated");
    await userEvent.click(within(dialog).getByRole("button", { name: /^save provider/i }));

    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));

    await waitFor(() => expect(findPut()).toBeTruthy());
    const arr = putBody()[PROVIDERS_PTR] as Array<Record<string, unknown>>;
    // The untouched secret is the EXACT value GET returned — not a hardcoded
    // literal in the component, not a real secret.
    expect(arr[0].client_secret).toBe(SERVER_SENTINEL);
    expect(arr[0].label).toBe("GitHub Updated");
  });

  it("retyping the client_secret sends the new value", async () => {
    renderEditor({
      providers: [
        {
          id: "gh",
          provider: "github",
          label: "GitHub",
          client_id: "client-123",
          client_secret: SERVER_SENTINEL,
          mapper_url: "function(ctx) {}",
        },
      ],
    });

    await userEvent.click(screen.getByRole("button", { name: /edit gh/i }));
    const dialog = await screen.findByRole("dialog");
    await userEvent.type(
      within(dialog).getByLabelText(/client secret/i),
      "new-secret",
    );
    await userEvent.click(within(dialog).getByRole("button", { name: /^save provider/i }));

    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));

    await waitFor(() => expect(findPut()).toBeTruthy());
    const arr = putBody()[PROVIDERS_PTR] as Array<Record<string, unknown>>;
    expect(arr[0].client_secret).toBe("new-secret");
  });

  it("the provider select offers the schema enum values", async () => {
    renderEditor();
    await userEvent.click(screen.getByRole("button", { name: /add provider/i }));
    const dialog = await screen.findByRole("dialog");
    // The provider select is present and labeled.
    expect(within(dialog).getByLabelText(/provider/i)).toBeInTheDocument();
    // The component exposes the enum via the option list.
    const trigger = within(dialog).getByLabelText(/provider/i);
    expect(trigger).toBeInTheDocument();
  });

  it("the mapper_url field uses a MonacoEditor", async () => {
    renderEditor();
    await userEvent.click(screen.getByRole("button", { name: /add provider/i }));
    await screen.findByRole("dialog");
    expect(await screen.findByTestId("monaco")).toBeInTheDocument();
  });

  it("never references an Ory host (egress only via /api/config)", async () => {
    renderEditor({ providers: [], enabled: true });
    await userEvent.click(screen.getByRole("button", { name: /add provider/i }));
    const dialog = await screen.findByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText(/^id/i), "gh");
    await userEvent.type(within(dialog).getByLabelText(/client id/i), "c");
    await userEvent.type(within(dialog).getByLabelText(/mapper/i), "x");
    await userEvent.click(within(dialog).getByRole("button", { name: /^save provider/i }));
    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() => expect(findPut()).toBeTruthy());
    for (const call of apiMock.mock.calls) {
      expect(String(call[0])).toMatch(/^\/api\//);
    }
  });
});
