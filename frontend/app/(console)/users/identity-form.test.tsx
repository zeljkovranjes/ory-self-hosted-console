import {
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

// Component test for the IDENT-02 schema-driven create/edit form. lib/api.ts is
// mocked so we assert the CONTRACT: fields render from the active identity
// schema; a missing required trait blocks submit; create POSTs
// {schema_id,traits,...}; edit PUTs WITH the required state; a backend 422 maps
// to inline field errors; and an empty metadata editor OMITS the key (not null).

const apiMock = vi.fn();
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, api: (...args: unknown[]) => apiMock(...args) };
});

const pushMock = vi.fn();
const refreshMock = vi.fn();
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock, refresh: refreshMock }),
}));

vi.mock("sonner", () => ({
  toast: { success: vi.fn(), error: vi.fn() },
}));

// Monaco is heavy + client-only; stub it with a controlled textarea so we can
// type JSON into the metadata editors in jsdom.
vi.mock("@/components/monaco-editor", () => ({
  MonacoEditor: ({
    value,
    onChange,
    ariaLabel,
  }: {
    value: string;
    onChange: (v: string) => void;
    ariaLabel?: string;
  }) => (
    <textarea
      aria-label={ariaLabel}
      value={value}
      onChange={(e) => onChange(e.target.value)}
    />
  ),
}));

import { IdentityForm } from "./identity-form";

const activeSchema = {
  type: "object",
  properties: {
    traits: {
      type: "object",
      properties: {
        email: { type: "string", format: "email", title: "E-Mail" },
        first_name: { type: "string", title: "First name" },
      },
      required: ["email"],
    },
  },
};

function renderForm(ui: React.ReactNode) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

beforeEach(() => {
  vi.clearAllMocks();
  // The form fetches the active schema on mount.
  apiMock.mockImplementation((path: string) => {
    if (typeof path === "string" && path.includes("identity-schema")) {
      return Promise.resolve(activeSchema);
    }
    return Promise.resolve({ status: "ok" });
  });
});

describe("IdentityForm (IDENT-02) — schema-driven", () => {
  it("renders trait fields generated from the active schema", async () => {
    renderForm(<IdentityForm mode="create" />);
    expect(await screen.findByLabelText(/e-mail/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/first name/i)).toBeInTheDocument();
  });

  it("blocks create submit when a required trait is missing", async () => {
    renderForm(<IdentityForm mode="create" />);
    await screen.findByLabelText(/e-mail/i);
    // Submit with empty required email.
    await userEvent.click(screen.getByRole("button", { name: /create/i }));

    await waitFor(() =>
      expect(
        apiMock.mock.calls.filter((c) =>
          String(c[0]).match(/\/api\/kratos\/identities$/),
        ),
      ).toHaveLength(0),
    );
  });

  it("create POSTs {schema_id, traits} and omits empty metadata", async () => {
    renderForm(<IdentityForm mode="create" />);
    await userEvent.type(await screen.findByLabelText(/e-mail/i), "new@example.com");
    await userEvent.click(screen.getByRole("button", { name: /create/i }));

    await waitFor(() => {
      const post = apiMock.mock.calls.find(
        (c) =>
          String(c[0]).endsWith("/api/kratos/identities") &&
          (c[1] as RequestInit | undefined)?.method === "POST",
      );
      expect(post).toBeDefined();
    });
    const post = apiMock.mock.calls.find(
      (c) =>
        String(c[0]).endsWith("/api/kratos/identities") &&
        (c[1] as RequestInit | undefined)?.method === "POST",
    )!;
    const body = JSON.parse((post[1] as RequestInit).body as string);
    expect(body.traits.email).toBe("new@example.com");
    expect(body.schema_id).toBeTruthy();
    // Empty metadata editors must be OMITTED, not sent as null (Pitfall 4).
    expect("metadata_public" in body).toBe(false);
    expect("metadata_admin" in body).toBe(false);
  });

  it("edit PUTs WITH the required state field", async () => {
    const identity = {
      id: "id-9",
      schema_id: "default",
      state: "active",
      traits: { email: "ex@example.com", first_name: "Ex" },
    };
    renderForm(<IdentityForm mode="edit" identity={identity} />);
    await screen.findByLabelText(/e-mail/i);
    // dirty a field so submit is enabled
    await userEvent.type(screen.getByLabelText(/first name/i), "tra");
    await userEvent.click(screen.getByRole("button", { name: /save/i }));

    await waitFor(() => {
      const put = apiMock.mock.calls.find(
        (c) => (c[1] as RequestInit | undefined)?.method === "PUT",
      );
      expect(put).toBeDefined();
    });
    const put = apiMock.mock.calls.find(
      (c) => (c[1] as RequestInit | undefined)?.method === "PUT",
    )!;
    const body = JSON.parse((put[1] as RequestInit).body as string);
    expect(body.state).toBe("active");
    expect(body.traits.email).toBe("ex@example.com");
  });

  it("maps a backend 422 to an inline field error", async () => {
    const { ApiError } = await import("@/lib/api");
    apiMock.mockImplementation((path: string, init?: RequestInit) => {
      if (String(path).includes("identity-schema")) {
        return Promise.resolve(activeSchema);
      }
      if (init?.method === "POST") {
        return Promise.reject(
          new ApiError(422, [
            { path: "traits.email", message: "Email already in use" },
          ]),
        );
      }
      return Promise.resolve({});
    });

    renderForm(<IdentityForm mode="create" />);
    await userEvent.type(await screen.findByLabelText(/e-mail/i), "dup@example.com");
    await userEvent.click(screen.getByRole("button", { name: /create/i }));

    expect(
      await screen.findByText("Email already in use"),
    ).toBeInTheDocument();
  });
});
