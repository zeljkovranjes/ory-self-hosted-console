import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

// AX-02 — Theming editor page. @/lib/api is mocked so we assert the CONTRACT:
//   - the flag-ON body loads via GET /api/account-experience/theme (the sole
//     egress — every path starts with /api/account-experience/);
//   - a save PUTs { source } to /api/account-experience/theme through lib/api;
//   - flag OFF shows the neutral FeatureGate body with NO editor/Save;
//   - there is NO Enterprise/license/requires-Ory copy anywhere (FLAG-03/SSO-07).

const apiMock = vi.fn();
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, api: (...args: unknown[]) => apiMock(...args) };
});

// Drive the account_experience flag via the single client source of truth.
const featuresMock = vi.fn();
vi.mock("@/lib/features", () => ({ useFeatures: () => featuresMock() }));

// Mock the heavy Monaco editor as a plain textarea (it dynamically imports +
// uses next-themes; the wrapper behavior is out of scope here).
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

import ThemingPage from "./page";

beforeEach(() => {
  vi.clearAllMocks();
  featuresMock.mockReturnValue({
    data: {
      features: {
        account_experience: { enabled: true, label: "Account Experience" },
      },
    },
  });
});

describe("Theming page (AX-02)", () => {
  it("loads the current override via GET /api/account-experience/theme through lib/api", async () => {
    apiMock.mockResolvedValueOnce({ source: ":root{--ui-brand:#0a0}" });
    render(<ThemingPage />);

    const editor = await screen.findByLabelText(
      /theme override \(css variables\)/i,
    );
    await waitFor(() =>
      expect((editor as HTMLTextAreaElement).value).toContain("--ui-brand"),
    );
    expect(apiMock).toHaveBeenCalledWith("/api/account-experience/theme");
    // Every egress path is a same-origin /api/ path (no Ory/AX host literal).
    for (const call of apiMock.mock.calls) {
      expect(String(call[0])).toMatch(/^\/api\//);
    }
  });

  it("saves via PUT /api/account-experience/theme { source } through lib/api", async () => {
    apiMock.mockResolvedValueOnce({ source: "" }); // initial load
    apiMock.mockResolvedValueOnce({ status: "saved" }); // the PUT
    render(<ThemingPage />);

    const editor = await screen.findByLabelText(
      /theme override \(css variables\)/i,
    );
    // fireEvent.change avoids userEvent.type's `{`/`}` keyboard-sequence parsing.
    fireEvent.change(editor, { target: { value: ":root{--ui-brand:#123}" } });
    await userEvent.click(screen.getByRole("button", { name: /save theme/i }));

    await waitFor(() =>
      expect(apiMock).toHaveBeenCalledWith(
        "/api/account-experience/theme",
        expect.objectContaining({ method: "PUT" }),
      ),
    );
    const putCall = apiMock.mock.calls.find((c) => c[1]?.method === "PUT");
    const body = JSON.parse(String(putCall?.[1]?.body));
    expect(body.source).toContain("--ui-brand");
    expect(
      await screen.findByText(/theme override saved/i),
    ).toBeInTheDocument();
  });

  it("OFF: shows the neutral FeatureGate body with no editor or Save", () => {
    featuresMock.mockReturnValue({
      data: {
        features: {
          account_experience: { enabled: false, label: "Account Experience" },
        },
      },
    });
    render(<ThemingPage />);
    expect(screen.getByText("This feature is disabled")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /save theme/i }),
    ).toBeNull();
  });

  it("has NO Enterprise/license/requires-Ory copy", async () => {
    apiMock.mockResolvedValue({ source: "" });
    const { container } = render(<ThemingPage />);
    await screen.findByLabelText(/theme override \(css variables\)/i);
    const text = container.textContent ?? "";
    expect(text).not.toMatch(/enterprise/i);
    expect(text).not.toMatch(/license/i);
    expect(text).not.toMatch(/requires ory/i);
  });
});
