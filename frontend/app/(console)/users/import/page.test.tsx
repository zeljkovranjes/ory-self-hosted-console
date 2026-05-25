import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

// Component test for the IDENT-04 bulk-import page (/users/import). lib/api is
// mocked so we assert the CONTRACT: Validate shows the record count + blocks
// Import on an over-limit/malformed payload; a valid payload enables Import and
// POSTs the bare array; per-record results render; a backend 422 surfaces; Export
// pages the identities list and triggers a bare-array JSON download.

const apiMock = vi.fn();
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, api: (...args: unknown[]) => apiMock(...args) };
});

vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

import { ApiError } from "@/lib/api";
import { HASHED_LIMIT } from "@/lib/cli-identity";
import ImportPage from "./page";

const validArray = JSON.stringify([
  { schema_id: "default", traits: { email: "a@example.com" } },
  { schema_id: "default", traits: { email: "b@example.com" } },
]);

beforeEach(() => {
  vi.clearAllMocks();
});

function paste(text: string) {
  const textarea = screen.getByLabelText(/paste/i);
  fireEvent.change(textarea, { target: { value: text } });
}

describe("Bulk import page (/users/import)", () => {
  it("documents CLI interchangeability", () => {
    render(<ImportPage />);
    expect(screen.getByText(/ory import identities/i)).toBeInTheDocument();
  });

  it("Validate reports the record count for a valid payload and enables Import", async () => {
    render(<ImportPage />);
    paste(validArray);
    await userEvent.click(screen.getByRole("button", { name: /validate/i }));

    expect(await screen.findByText(/2 records/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^import$/i })).toBeEnabled();
  });

  it("Validate blocks Import on a malformed payload", async () => {
    render(<ImportPage />);
    paste("{not an array");
    await userEvent.click(screen.getByRole("button", { name: /validate/i }));

    expect(await screen.findByText(/valid json array/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^import$/i })).toBeDisabled();
  });

  it("Validate blocks Import on an over-limit payload", async () => {
    const tooMany = JSON.stringify(
      Array.from({ length: HASHED_LIMIT + 1 }, (_, i) => ({
        schema_id: "default",
        traits: { email: `u${i}@example.com` },
      })),
    );
    render(<ImportPage />);
    paste(tooMany);
    await userEvent.click(screen.getByRole("button", { name: /validate/i }));

    expect(await screen.findByText(/maximum of 1000/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^import$/i })).toBeDisabled();
  });

  it("Import POSTs the bare array and renders per-record results", async () => {
    apiMock.mockResolvedValueOnce({
      results: [
        { action: "create", identity: { id: "id-1" } },
        { action: "error", error: { message: "duplicate" } },
      ],
    });
    render(<ImportPage />);
    paste(validArray);
    await userEvent.click(screen.getByRole("button", { name: /validate/i }));
    await screen.findByText(/2 records/i);
    await userEvent.click(screen.getByRole("button", { name: /^import$/i }));

    await waitFor(() => {
      const post = apiMock.mock.calls.find(
        (c) => (c[1] as RequestInit | undefined)?.method === "POST",
      );
      expect(post).toBeTruthy();
      expect(String(post?.[0])).toContain("/api/kratos/identities/import");
      // Body is the bare array.
      const body = JSON.parse((post?.[1] as RequestInit).body as string);
      expect(Array.isArray(body)).toBe(true);
      expect(body).toHaveLength(2);
    });
    // Per-record results render (one success, one error).
    expect(await screen.findByText(/duplicate/i)).toBeInTheDocument();
  });

  it("surfaces a backend 422 limit rejection explicitly", async () => {
    apiMock.mockRejectedValueOnce(
      new ApiError(422, [{ path: "/", message: "import exceeds limit" }]),
    );
    render(<ImportPage />);
    paste(validArray);
    await userEvent.click(screen.getByRole("button", { name: /validate/i }));
    await screen.findByText(/2 records/i);
    await userEvent.click(screen.getByRole("button", { name: /^import$/i }));

    expect(await screen.findByText(/import exceeds limit/i)).toBeInTheDocument();
  });

  it("Export pages the identities list and downloads a bare-array JSON", async () => {
    // Two pages of identities, then exhausted.
    apiMock
      .mockResolvedValueOnce({
        rows: [
          {
            id: "id-1",
            schema_id: "default",
            state: "active",
            traits: { email: "a@example.com" },
            credentials: { password: { config: { hashed_password: "$SECRET" } } },
          },
        ],
        next_token: "tok-2",
        total: 2,
      })
      .mockResolvedValueOnce({
        rows: [
          {
            id: "id-2",
            schema_id: "default",
            state: "active",
            traits: { email: "b@example.com" },
          },
        ],
        next_token: null,
        total: 2,
      });

    // Capture the generated download blob.
    const createObjectURL = vi.fn((_blob: Blob) => "blob:mock");
    const revokeObjectURL = vi.fn();
    Object.defineProperty(URL, "createObjectURL", {
      value: createObjectURL,
      configurable: true,
    });
    Object.defineProperty(URL, "revokeObjectURL", {
      value: revokeObjectURL,
      configurable: true,
    });

    render(<ImportPage />);
    await userEvent.click(screen.getByRole("button", { name: /export/i }));

    await waitFor(() => expect(createObjectURL).toHaveBeenCalled());
    // Two list pages were fetched (followed next_token).
    const listCalls = apiMock.mock.calls.filter((c) =>
      String(c[0]).includes("/api/kratos/identities"),
    );
    expect(listCalls.length).toBe(2);

    // The exported blob is a bare array with secrets stripped.
    const blobArg = createObjectURL.mock.calls[0][0] as Blob;
    const blobText = await blobArg.text();
    const parsed = JSON.parse(blobText);
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed).toHaveLength(2);
    expect(blobText).not.toContain("SECRET");
    expect(blobText).not.toContain("hashed_password");
  });
});
