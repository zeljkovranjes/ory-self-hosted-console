import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";

// AUTH-09 — Email/SMTP page. Two independent controls:
//   (1) a write-only connection URI -> dedicated PUT /api/kratos/smtp-connection
//       (GET /api/kratos/smtp-connection returns {set:bool}; the URI is NEVER
//       echoed; a blank submit does not PUT a real value).
//   (2) a SettingsForm for the non-secret SMTP keys -> PUT /api/config/kratos/smtp
//       (from_address email validation blocks submit on bad input).

const apiMock = vi.fn();
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, api: (...args: unknown[]) => apiMock(...args) };
});
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

import SmtpPage from "./page";

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <SmtpPage />
    </QueryClientProvider>,
  );
}

function putCalls() {
  return apiMock.mock.calls.filter(
    (c) => (c[1] as RequestInit | undefined)?.method === "PUT",
  );
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("Authentication / Email & SMTP (AUTH-09)", () => {
  it("the connection URI field never displays a URL/credential value", async () => {
    // GET smtp-connection -> {set:true}; GET smtp section -> {}.
    apiMock.mockImplementation((path: string) => {
      if (path === "/api/kratos/smtp-connection")
        return Promise.resolve({ set: true });
      return Promise.resolve({});
    });
    renderPage();

    const uri = (await screen.findByLabelText(
      /connection uri/i,
    )) as HTMLInputElement;
    // The control is a password field and carries no real value.
    expect(uri.value).toBe("");
    expect(uri).toHaveAttribute("type", "password");
    // The "configured" indicator is shown (set:true).
    expect(await screen.findByText(/configured/i)).toBeInTheDocument();
  });

  it("a blank connection URI submit does not PUT a real value to the dedicated path", async () => {
    apiMock.mockImplementation((path: string) => {
      if (path === "/api/kratos/smtp-connection")
        return Promise.resolve({ set: false });
      return Promise.resolve({});
    });
    renderPage();

    await screen.findByLabelText(/connection uri/i);
    await userEvent.click(
      screen.getByRole("button", { name: /save connection uri/i }),
    );

    // No PUT to the dedicated path with a real URI should have happened.
    const dedicated = putCalls().filter(
      (c) => String(c[0]) === "/api/kratos/smtp-connection",
    );
    expect(dedicated).toHaveLength(0);
  });

  it("PUTs the typed connection URI to the dedicated endpoint", async () => {
    apiMock.mockImplementation((path: string) => {
      if (path === "/api/kratos/smtp-connection")
        return Promise.resolve({ set: false });
      return Promise.resolve({});
    });
    renderPage();

    const uri = await screen.findByLabelText(/connection uri/i);
    await userEvent.type(uri, "smtps://user:pass@mail:465");
    await userEvent.click(
      screen.getByRole("button", { name: /save connection uri/i }),
    );

    await waitFor(() => {
      const dedicated = putCalls().find(
        (c) => String(c[0]) === "/api/kratos/smtp-connection",
      );
      expect(dedicated).toBeTruthy();
      const body = JSON.parse((dedicated?.[1] as RequestInit).body as string);
      expect(body).toHaveProperty("connection_uri", "smtps://user:pass@mail:465");
    });
  });

  it("an invalid from_address blocks the non-secret section submit", async () => {
    apiMock.mockImplementation((path: string) => {
      if (path === "/api/kratos/smtp-connection")
        return Promise.resolve({ set: false });
      return Promise.resolve({});
    });
    renderPage();

    const from = await screen.findByLabelText(/from address/i);
    await userEvent.type(from, "not-an-email");
    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));

    // The invalid email blocks the PUT to the section path.
    await waitFor(() => {
      const section = putCalls().filter(
        (c) => String(c[0]) === "/api/config/kratos/smtp",
      );
      expect(section).toHaveLength(0);
    });
  });
});
