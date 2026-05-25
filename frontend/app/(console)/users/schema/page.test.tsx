import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

// Component test for the IDENT-03 identity-schema editor (/users/schema). lib/api
// is mocked so we assert the CONTRACT: the active schema loads into the editor; a
// preset selection replaces the content; Save PUTs the edited JSON and renders the
// healthy status banner; a backend 422 renders inline field errors; invalid JSON
// blocks the network call; the "Saving restarts Kratos" warning is present.

const apiMock = vi.fn();
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, api: (...args: unknown[]) => apiMock(...args) };
});

vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

// Monaco is heavy + client-only; stub it with a controlled textarea so jsdom can
// drive `value`/`onChange` directly.
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
      aria-label={ariaLabel ?? "schema-editor"}
      value={value}
      onChange={(e) => onChange(e.target.value)}
    />
  ),
}));

import { ApiError } from "@/lib/api";
import SchemaEditorPage from "./page";

const activeSchema = {
  $schema: "http://json-schema.org/draft-07/schema#",
  type: "object",
  properties: { traits: { type: "object", properties: { email: { type: "string" } } } },
};

beforeEach(() => {
  vi.clearAllMocks();
});

describe("Identity schema editor (/users/schema)", () => {
  it("loads the active schema into the editor on mount", async () => {
    apiMock.mockResolvedValueOnce(activeSchema);
    render(<SchemaEditorPage />);

    const editor = await screen.findByLabelText(/schema-editor/i);
    await waitFor(() =>
      expect((editor as HTMLTextAreaElement).value).toContain('"traits"'),
    );
    expect(String(apiMock.mock.calls[0][0])).toContain(
      "/api/kratos/identity-schema",
    );
  });

  it("shows a persistent 'Saving restarts Kratos' warning", async () => {
    apiMock.mockResolvedValueOnce(activeSchema);
    render(<SchemaEditorPage />);
    await screen.findByLabelText(/schema-editor/i);
    expect(screen.getByText(/restarts kratos/i)).toBeInTheDocument();
  });

  it("a preset selection replaces the editor content", async () => {
    apiMock.mockResolvedValueOnce(activeSchema);
    render(<SchemaEditorPage />);
    const editor = (await screen.findByLabelText(
      /schema-editor/i,
    )) as HTMLTextAreaElement;

    // The preset chooser is the shadcn (Radix) Select (UI-REVIEW Top-3 #1):
    // open the trigger, then pick the "Username" option from the listbox.
    const trigger = screen.getByLabelText(/preset/i);
    await userEvent.click(trigger);
    const option = await screen.findByRole("option", { name: /username/i });
    await userEvent.click(option);
    await waitFor(() => expect(editor.value).toContain('"username"'));
  });

  it("Save PUTs the edited JSON and renders the healthy banner", async () => {
    apiMock.mockResolvedValueOnce(activeSchema); // initial GET
    apiMock.mockResolvedValueOnce({ status: "healthy" }); // PUT
    render(<SchemaEditorPage />);
    await screen.findByLabelText(/schema-editor/i);

    await userEvent.click(screen.getByRole("button", { name: /save/i }));

    await waitFor(() => {
      const putCall = apiMock.mock.calls.find(
        (c) => (c[1] as RequestInit | undefined)?.method === "PUT",
      );
      expect(putCall).toBeTruthy();
      expect(String(putCall?.[0])).toContain("/api/kratos/identity-schema");
    });
    expect(
      await screen.findByText(/configuration healthy/i),
    ).toBeInTheDocument();
  });

  it("renders inline field errors on a 422", async () => {
    apiMock.mockResolvedValueOnce(activeSchema);
    apiMock.mockRejectedValueOnce(
      new ApiError(422, [
        { path: "/properties/traits", message: "traits must be an object" },
      ]),
    );
    render(<SchemaEditorPage />);
    await screen.findByLabelText(/schema-editor/i);

    await userEvent.click(screen.getByRole("button", { name: /save/i }));
    expect(
      await screen.findByText(/traits must be an object/i),
    ).toBeInTheDocument();
  });

  it("blocks the PUT when the editor content is not valid JSON", async () => {
    apiMock.mockResolvedValueOnce(activeSchema);
    render(<SchemaEditorPage />);
    const editor = (await screen.findByLabelText(
      /schema-editor/i,
    )) as HTMLTextAreaElement;

    // fireEvent.change avoids userEvent's keyboard-syntax parsing of "{".
    fireEvent.change(editor, { target: { value: "{not valid json" } });
    await userEvent.click(screen.getByRole("button", { name: /save/i }));

    // No PUT was attempted (only the initial GET ran).
    const putCall = apiMock.mock.calls.find(
      (c) => (c[1] as RequestInit | undefined)?.method === "PUT",
    );
    expect(putCall).toBeUndefined();
    expect(await screen.findByText(/fix it before saving/i)).toBeInTheDocument();
  });
});
