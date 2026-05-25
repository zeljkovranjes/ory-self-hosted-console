import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";

import { ApiError } from "@/lib/api";
import { FormField, FormItem, FormLabel, FormControl, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";

// Component test for the FE-03 reusable SettingsForm. We do NOT hit the backend:
// lib/api.ts's `api()` is mocked so we can assert the CONTRACT — Zod validation
// blocks submit, a valid submit PUTs once, a backend 422 {path,message}[] maps to
// inline field errors via setError(type:'server'), Save is disabled while
// pristine/in-flight, and the status banner reflects applied/restarting/healthy/
// failed. The real ApiError class is used so `instanceof` matches.

const apiMock = vi.fn();
const toastSuccess = vi.fn();
// Capture the REAL `api()` so one test can exercise the genuine 422 parse path
// (the `{fields:[...]}` backend shape) through the actual lib/api.ts code rather
// than a hand-built ApiError — this is what would catch a contract regression.
// `vi.hoisted` makes the holder available inside the hoisted vi.mock factory
// without a TDZ error.
const apiHolder = vi.hoisted(() => ({
  real: undefined as undefined | ((...a: unknown[]) => unknown),
}));
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  apiHolder.real = actual.api as (...a: unknown[]) => unknown;
  return { ...actual, api: (...args: unknown[]) => apiMock(...args) };
});
vi.mock("sonner", () => ({
  toast: { success: (...a: unknown[]) => toastSuccess(...a) },
}));

import { SettingsForm } from "./settings-form";

const schema = z.object({
  smtp_host: z.string().min(1, "Host is required"),
  from_name: z.string().min(1, "From name is required"),
});

type Values = z.input<typeof schema>;

function Harness(props: Partial<React.ComponentProps<typeof SettingsForm<typeof schema>>>) {
  return (
    <SettingsForm<typeof schema>
      schema={schema}
      title="Courier"
      description="SMTP settings"
      submitPath="/api/config/kratos/courier"
      defaultValues={{ smtp_host: "smtp.example.com", from_name: "Ory" }}
      {...props}
    >
      {(form) => (
        <>
          <FormField
            control={form.control}
            name="smtp_host"
            render={({ field }) => (
              <FormItem>
                <FormLabel>SMTP host</FormLabel>
                <FormControl>
                  <Input {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="from_name"
            render={({ field }) => (
              <FormItem>
                <FormLabel>From name</FormLabel>
                <FormControl>
                  <Input {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </>
      )}
    </SettingsForm>
  );
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("SettingsForm (FE-03)", () => {
  it("Save is disabled while pristine and enables once a field changes", async () => {
    render(<Harness />);
    const save = screen.getByRole("button", { name: /save/i });
    expect(save).toBeDisabled();

    await userEvent.clear(screen.getByLabelText("SMTP host"));
    await userEvent.type(screen.getByLabelText("SMTP host"), "smtp.new.com");
    await waitFor(() => expect(save).toBeEnabled());
  });

  it("blocks submit on invalid input and shows the Zod message; api() not called", async () => {
    render(<Harness />);
    // Make a field invalid (empty) — dirties the form so Save is enabled.
    await userEvent.clear(screen.getByLabelText("SMTP host"));
    // Re-type then clear from_name to dirty without leaving host empty? No —
    // we want host empty to trigger the Zod error. Type a char into from_name
    // to ensure dirty, then submit.
    await userEvent.type(screen.getByLabelText("From name"), "X");
    await userEvent.click(screen.getByRole("button", { name: /save/i }));

    expect(await screen.findByText("Host is required")).toBeInTheDocument();
    expect(apiMock).not.toHaveBeenCalled();
  });

  it("valid submit calls api() PUT once with the form values", async () => {
    apiMock.mockResolvedValueOnce({ status: "healthy" });
    render(<Harness />);
    await userEvent.clear(screen.getByLabelText("From name"));
    await userEvent.type(screen.getByLabelText("From name"), "Ory Console");
    await userEvent.click(screen.getByRole("button", { name: /save/i }));

    await waitFor(() => expect(apiMock).toHaveBeenCalledTimes(1));
    const [path, init] = apiMock.mock.calls[0];
    expect(path).toBe("/api/config/kratos/courier");
    expect(init.method).toBe("PUT");
    expect(JSON.parse(init.body)).toMatchObject({ from_name: "Ory Console" });
  });

  it("maps a backend 422 to inline field errors via setError(type:'server')", async () => {
    apiMock.mockRejectedValueOnce(
      new ApiError(422, [
        { path: "smtp_host", message: "Host unreachable" },
      ]),
    );
    render(<Harness />);
    await userEvent.type(screen.getByLabelText("From name"), "Z");
    await userEvent.click(screen.getByRole("button", { name: /save/i }));

    expect(await screen.findByText("Host unreachable")).toBeInTheDocument();
  });

  it("maps inline errors from the REAL backend 422 {fields:[...]} body (end-to-end parse path)", async () => {
    // Regression guard for CR-01: drive SettingsForm through the genuine
    // lib/api.ts parse path against a stubbed fetch returning the backend's
    // ACTUAL shape — `{error:"validation_failed", fields:[{path,message}]}`
    // (backend/src/error.rs:149-151). If api.ts read the wrong key, fieldErrors
    // would be [] and this inline message would never render — failing the test.
    const fetchMock = vi.fn().mockResolvedValue({
      status: 422,
      ok: false,
      json: async () => ({
        error: "validation_failed",
        fields: [{ path: "smtp_host", message: "Host unreachable (real 422)" }],
      }),
    } as unknown as Response);
    vi.stubGlobal("fetch", fetchMock);
    // Route the component's `api()` through the real implementation for this test.
    apiMock.mockImplementation((...args: unknown[]) => apiHolder.real!(...args));
    try {
      render(<Harness />);
      await userEvent.type(screen.getByLabelText("From name"), "Z");
      await userEvent.click(screen.getByRole("button", { name: /save/i }));

      expect(
        await screen.findByText("Host unreachable (real 422)"),
      ).toBeInTheDocument();
      // The 422 must hit the backend exactly once via the real wrapper.
      await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("shows a healthy success banner and toasts on a successful save", async () => {
    apiMock.mockResolvedValueOnce({ status: "healthy" });
    render(<Harness />);
    await userEvent.type(screen.getByLabelText("From name"), "Z");
    await userEvent.click(screen.getByRole("button", { name: /save/i }));

    const banner = await screen.findByRole("status");
    expect(banner).toHaveTextContent(/healthy/i);
    expect(toastSuccess).toHaveBeenCalled();
  });

  it("shows a destructive failed banner (rolled back) on a non-422 error", async () => {
    apiMock.mockRejectedValueOnce(new ApiError(500));
    render(<Harness />);
    await userEvent.type(screen.getByLabelText("From name"), "Z");
    await userEvent.click(screen.getByRole("button", { name: /save/i }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/failed/i);
    expect(alert).toHaveTextContent(/last-known-good/i);
  });

  it("reflects the backend status field (restarting) in the banner", async () => {
    apiMock.mockResolvedValueOnce({ status: "restarting" });
    render(<Harness />);
    await userEvent.type(screen.getByLabelText("From name"), "Z");
    await userEvent.click(screen.getByRole("button", { name: /save/i }));

    const banner = await screen.findByRole("status");
    expect(banner).toHaveTextContent(/restarting/i);
  });

  it("Discard resets the form to the last-saved values and disables Save", async () => {
    render(<Harness />);
    const host = screen.getByLabelText("SMTP host");
    await userEvent.clear(host);
    await userEvent.type(host, "smtp.changed.com");
    expect(screen.getByRole("button", { name: /save/i })).toBeEnabled();

    await userEvent.click(screen.getByRole("button", { name: /discard/i }));
    await waitFor(() =>
      expect(screen.getByLabelText("SMTP host")).toHaveValue("smtp.example.com"),
    );
    expect(screen.getByRole("button", { name: /save/i })).toBeDisabled();
  });

  it("does not use dangerouslySetInnerHTML for the 422 message (rendered as text)", async () => {
    apiMock.mockRejectedValueOnce(
      new ApiError(422, [
        { path: "smtp_host", message: "<img src=x onerror=alert(1)>" },
      ]),
    );
    const { container } = render(<Harness />);
    await userEvent.type(screen.getByLabelText("From name"), "Z");
    await userEvent.click(screen.getByRole("button", { name: /save/i }));

    // The payload text renders escaped (as text), and no <img> is injected.
    expect(
      await screen.findByText("<img src=x onerror=alert(1)>"),
    ).toBeInTheDocument();
    expect(container.querySelector("img")).toBeNull();
  });
});
