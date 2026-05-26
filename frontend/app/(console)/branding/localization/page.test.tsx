import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

// AX-03 — Localization editor page. @/lib/api is mocked so we assert the
// CONTRACT:
//   - the flag-ON body loads via GET /api/account-experience/translations;
//   - a save PUTs the catalog to /api/account-experience/translations via lib/api;
//   - a backend 422 (malformed JSON) is surfaced INLINE, never collapsed into a
//     success (T-15-08);
//   - flag OFF shows the neutral FeatureGate body with NO editor/Save;
//   - there is a link to the email-template editor and NO Enterprise/license/
//     requires-Ory copy anywhere (FLAG-03/SSO-07).

const apiMock = vi.fn();
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, api: (...args: unknown[]) => apiMock(...args) };
});

const featuresMock = vi.fn();
vi.mock("@/lib/features", () => ({ useFeatures: () => featuresMock() }));

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

import { ApiError } from "@/lib/api";
import LocalizationPage from "./page";

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

// Replace the editor contents. fireEvent.change avoids userEvent.type's special
// `{`/`}` keyboard-sequence parsing (the catalog is JSON, full of braces).
function setEditor(el: HTMLElement, next: string) {
  fireEvent.change(el, { target: { value: next } });
}

describe("Localization page (AX-03)", () => {
  it("loads the catalog via GET /api/account-experience/translations through lib/api", async () => {
    apiMock.mockResolvedValueOnce({
      translations: { en: { greeting: "Hi" } },
    });
    render(<LocalizationPage />);

    const editor = await screen.findByLabelText(/translations catalog \(json\)/i);
    await waitFor(() =>
      expect((editor as HTMLTextAreaElement).value).toContain("greeting"),
    );
    expect(apiMock).toHaveBeenCalledWith(
      "/api/account-experience/translations",
    );
    for (const call of apiMock.mock.calls) {
      expect(String(call[0])).toMatch(/^\/api\//);
    }
  });

  it("saves the catalog via PUT /api/account-experience/translations via lib/api", async () => {
    apiMock.mockResolvedValueOnce({ translations: {} }); // load
    apiMock.mockResolvedValueOnce({ status: "saved", translations: {} }); // PUT
    render(<LocalizationPage />);

    const editor = await screen.findByLabelText(/translations catalog \(json\)/i);
    await setEditor(editor, '{"en":{"greeting":"Hi"}}');
    await userEvent.click(
      screen.getByRole("button", { name: /save translations/i }),
    );

    await waitFor(() =>
      expect(apiMock).toHaveBeenCalledWith(
        "/api/account-experience/translations",
        expect.objectContaining({ method: "PUT" }),
      ),
    );
    const putCall = apiMock.mock.calls.find((c) => c[1]?.method === "PUT");
    const body = JSON.parse(String(putCall?.[1]?.body));
    expect(body.en.greeting).toBe("Hi");
    expect(await screen.findByText(/translations saved/i)).toBeInTheDocument();
  });

  it("surfaces a backend 422 INLINE and never collapses it into a success (T-15-08)", async () => {
    apiMock.mockResolvedValueOnce({ translations: {} }); // load
    apiMock.mockRejectedValueOnce(
      new ApiError(422, [
        { path: "/", message: "translations override must be valid JSON" },
      ]),
    );
    render(<LocalizationPage />);

    const editor = await screen.findByLabelText(/translations catalog \(json\)/i);
    // Valid JSON locally (passes the advisory parse) so the backend 422 is what
    // surfaces — proving the inline-surface path, not the client guard.
    await setEditor(editor, '{"en":{"k":"v"}}');
    await userEvent.click(
      screen.getByRole("button", { name: /save translations/i }),
    );

    expect(
      await screen.findByText(/translations override must be valid JSON/i),
    ).toBeInTheDocument();
    // NOT collapsed into a success.
    expect(screen.queryByText(/translations saved/i)).toBeNull();
  });

  it("links to the Email Templates editor for courier-side localization", async () => {
    apiMock.mockResolvedValue({ translations: {} });
    render(<LocalizationPage />);
    const link = await screen.findByRole("link", { name: /email templates/i });
    expect(link).toHaveAttribute("href", "/branding/email-templates");
  });

  it("OFF: shows the neutral FeatureGate body with no editor or Save", () => {
    featuresMock.mockReturnValue({
      data: {
        features: {
          account_experience: { enabled: false, label: "Account Experience" },
        },
      },
    });
    render(<LocalizationPage />);
    expect(screen.getByText("This feature is disabled")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /save translations/i }),
    ).toBeNull();
  });

  it("has NO Enterprise/license/requires-Ory copy", async () => {
    apiMock.mockResolvedValue({ translations: {} });
    const { container } = render(<LocalizationPage />);
    await screen.findByLabelText(/translations catalog \(json\)/i);
    const text = container.textContent ?? "";
    expect(text).not.toMatch(/enterprise/i);
    expect(text).not.toMatch(/license/i);
    expect(text).not.toMatch(/requires ory/i);
  });
});
