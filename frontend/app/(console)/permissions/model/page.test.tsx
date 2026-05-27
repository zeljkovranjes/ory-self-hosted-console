import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

// PERM-04 page wiring test. We mock @/lib/api (the sole egress), the heavy
// MonacoEditor (a controlled textarea capturing the language + onMount props),
// and the live-validate hook. We assert:
//   (a) the editor mounts with language="ory-opl" and supplies an onMount;
//   (b) the live hook's `unavailable` state renders a muted NON-BLOCKING hint
//       and NEVER the destructive "invalid" banner;
//   (c) the PERM-01 pre-save Validate -> Save gate is unchanged and independent
//       of the live hook (clean Validate enables Save when dirty; an edit
//       re-disables until re-validated); a live failure neither enables nor
//       extra-blocks Save.

const apiMock = vi.fn();
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, api: (...args: unknown[]) => apiMock(...args) };
});

// Capture the props the page passes to MonacoEditor.
let lastEditorProps: {
  language?: string;
  onMount?: (...a: unknown[]) => void;
} | null = null;
vi.mock("@/components/monaco-editor", () => ({
  MonacoEditor: (props: {
    language?: string;
    value?: string;
    onChange?: (v: string) => void;
    ariaLabel?: string;
    onMount?: (...a: unknown[]) => void;
  }) => {
    lastEditorProps = { language: props.language, onMount: props.onMount };
    return (
      <textarea
        data-testid="opl-editor"
        data-language={props.language}
        data-has-onmount={props.onMount ? "yes" : "no"}
        aria-label={props.ariaLabel}
        value={props.value ?? ""}
        onChange={(e) => props.onChange?.(e.target.value)}
      />
    );
  },
}));

// Mock the live hook so we can drive its `unavailable` output independently of
// the pre-save gate. We also assert it was called with the page's source.
const liveHookMock = vi.fn();
vi.mock("./use-live-opl-validate", () => ({
  useLiveOplValidate: (args: unknown) => liveHookMock(args),
  LIVE_OPL_MARKER_OWNER: "ory-opl-live",
}));

import PermissionModelPage from "./page";

beforeEach(() => {
  vi.clearAllMocks();
  lastEditorProps = null;
  // Default: live check is fine (not unavailable).
  liveHookMock.mockReturnValue({ unavailable: false });
  // Default load: an empty model.
  apiMock.mockResolvedValue({ source: "" });
});

describe("Permission Model page — PERM-04 live wiring", () => {
  it("renders the editor with language='ory-opl' and supplies an onMount handle", async () => {
    render(<PermissionModelPage />);
    const ed = await screen.findByTestId("opl-editor");
    expect(ed).toHaveAttribute("data-language", "ory-opl");
    expect(ed).toHaveAttribute("data-has-onmount", "yes");
  });

  it("calls the live-validate hook with the current editor source", async () => {
    apiMock.mockResolvedValueOnce({ source: "class Seed {}" });
    render(<PermissionModelPage />);
    await screen.findByTestId("opl-editor");
    await waitFor(() => {
      const arg = liveHookMock.mock.calls.at(-1)?.[0] as {
        source?: string;
      };
      expect(arg?.source).toBe("class Seed {}");
    });
  });

  it("renders a muted NON-BLOCKING 'live validation unavailable' hint (never the destructive invalid banner) when the hook reports unavailable", async () => {
    liveHookMock.mockReturnValue({ unavailable: true });
    render(<PermissionModelPage />);
    await screen.findByTestId("opl-editor");

    const hint = await screen.findByText(/live validation unavailable/i);
    expect(hint).toBeInTheDocument();
    // It is an aria-live polite status, not an assertive alert.
    const statusRegion = hint.closest('[role="status"]');
    expect(statusRegion).not.toBeNull();
    expect(statusRegion).toHaveAttribute("aria-live", "polite");

    // The destructive "errors"/"invalid" pre-save banner is NOT shown by the
    // live failure.
    expect(
      screen.queryByText(/permission model has errors/i),
    ).toBeNull();
  });

  it("does NOT render the unavailable hint when the live check is fine", async () => {
    liveHookMock.mockReturnValue({ unavailable: false });
    render(<PermissionModelPage />);
    await screen.findByTestId("opl-editor");
    expect(screen.queryByText(/live validation unavailable/i)).toBeNull();
  });

  it("pre-save gate unchanged: a clean Validate enables Save when dirty; an edit re-disables it — independent of the live hook", async () => {
    apiMock.mockResolvedValueOnce({ source: "original" }); // load
    render(<PermissionModelPage />);
    const ed = (await screen.findByTestId("opl-editor")) as HTMLTextAreaElement;

    // Save starts disabled (not dirty, not validated).
    const saveBtn = screen.getByRole("button", { name: /validate & save/i });
    expect(saveBtn).toBeDisabled();

    // Edit -> dirty but not yet validated -> Save still disabled.
    fireEvent.change(ed, { target: { value: "class Edited {}" } });
    expect(saveBtn).toBeDisabled();

    // Validate -> clean result -> Save enabled (the PERM-01 gate).
    apiMock.mockResolvedValueOnce({ errors: [] }); // the validate POST
    await userEvent.click(screen.getByRole("button", { name: /^validate$/i }));
    await waitFor(() => expect(saveBtn).toBeEnabled());

    // A further edit re-disables Save until re-validated.
    fireEvent.change(ed, { target: { value: "class Edited2 {}" } });
    expect(saveBtn).toBeDisabled();
  });

  it("a live failure does NOT enable Save (the live hook never touches the pre-save gate)", async () => {
    apiMock.mockResolvedValueOnce({ source: "original" }); // load
    liveHookMock.mockReturnValue({ unavailable: true });
    render(<PermissionModelPage />);
    const ed = (await screen.findByTestId("opl-editor")) as HTMLTextAreaElement;

    // Dirty but never validated -> Save stays disabled despite the live state.
    fireEvent.change(ed, { target: { value: "class Edited {}" } });
    expect(
      screen.getByRole("button", { name: /validate & save/i }),
    ).toBeDisabled();
  });
});
