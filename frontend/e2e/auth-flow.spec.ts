import { expect, test } from "@playwright/test";

// FE-01 — the live operator auth journey, driven end-to-end against the REAL
// compose stack (frontend -> same-origin /backend rewrite -> Rust backend).
//
// This spec is the Playwright half of the Phase-5 acceptance gate
// (scripts/verify/phase5-acceptance.sh). It proves, in a real browser:
//   1. an UNINITIALIZED console routes the operator to /setup;
//   2. /setup (bootstrap token + first admin) completes and routes to /login;
//   3. /login authenticates and lands on the server-guarded (console) shell
//      (topbar + sidebar render — the authoritative /me guard let us in);
//   4. clearing the session cookie and hitting a protected route redirects
//      back to /login (the 401 path: the shell is unreachable unauthenticated).
//
// Inputs (exported by the acceptance script):
//   BOOTSTRAP_TOKEN  the one-time first-run token parsed from `docker compose
//                    logs backend`. REQUIRED for the setup leg.
//   E2E_ADMIN_EMAIL / E2E_ADMIN_PASSWORD  the admin to create + sign in as
//                    (password must be >= 12 chars, CAUTH-03). Sensible
//                    defaults are provided for a fresh-volume run.
//
// Cookie-name resilience: under the compose plain-HTTP bring-up the backend is
// run with CONSOLE_INSECURE_COOKIES=true, so the session cookie is the dev name
// `console_session` (no `__Host-` prefix). In a hardened HTTPS deployment it is
// `__Host-console_session`. The spec never hardcodes one — it clears BOTH when
// it needs to drop the session, and asserts on routing/visible UI, not on the
// cookie literal.

const BOOTSTRAP_TOKEN = process.env.BOOTSTRAP_TOKEN ?? "";
const ADMIN_EMAIL = process.env.E2E_ADMIN_EMAIL ?? "phase5-e2e@example.com";
const ADMIN_PASSWORD =
  process.env.E2E_ADMIN_PASSWORD ?? "phase5-e2e-acceptance-pw";

// The two possible session-cookie names (hardened vs dev escape hatch).
const SESSION_COOKIE_NAMES = ["__Host-console_session", "console_session"];

test.describe("Auth journey (FE-01) — live stack", () => {
  test("operator moves /setup -> /login -> authenticated shell; 401 -> /login", async ({
    page,
    context,
  }) => {
    test.skip(
      !BOOTSTRAP_TOKEN,
      "BOOTSTRAP_TOKEN not provided — the acceptance script parses it from `docker compose logs backend` and exports it.",
    );

    // --- (1) Uninitialized console: visiting / routes to /setup. -------------
    // The (console) layout's server guard redirects an unauthenticated visitor
    // to /login; /login reads state and (since uninitialized) forwards to /setup.
    // Either way the operator ends on /setup on a fresh stack.
    await page.goto("/");
    await page.waitForURL(/\/setup$/, { timeout: 30_000 });
    // The setup card's title (shadcn CardTitle is a div, not a semantic heading)
    // + its submit button confirm the form rendered (after the state check).
    const createBtn = page.getByRole("button", {
      name: /create operator account/i,
    });
    await expect(createBtn).toBeVisible({ timeout: 30_000 });

    // --- (2) Complete /setup with the bootstrap token + the first admin. -----
    await page.getByLabel("Bootstrap token").fill(BOOTSTRAP_TOKEN);
    await page.getByLabel("Name").fill("Phase5 E2E Admin");
    await page.getByLabel("Email").fill(ADMIN_EMAIL);
    await page.getByLabel("Password", { exact: true }).fill(ADMIN_PASSWORD);
    await createBtn.click();

    // setup routes to /login on success (no auto-login).
    await page.waitForURL(/\/login$/, { timeout: 30_000 });
    const signInBtn = page.getByRole("button", { name: /^sign in$/i });
    await expect(signInBtn).toBeVisible({ timeout: 30_000 });

    // --- (3) Sign in -> the server-guarded (console) shell renders. ----------
    await page.getByLabel("Email").fill(ADMIN_EMAIL);
    await page.getByLabel("Password", { exact: true }).fill(ADMIN_PASSWORD);
    await signInBtn.click();

    // Land on the dashboard ("/"): the (console) layout's /me guard passed.
    await page.waitForURL((url) => new URL(url).pathname === "/", {
      timeout: 30_000,
    });

    // The authenticated shell chrome is present (topbar + sidebar). The topbar
    // shows the console title; the sidebar renders the nav links (each an <a>).
    await expect(page.getByText(/ory console/i).first()).toBeVisible({
      timeout: 30_000,
    });
    await expect(
      page.getByRole("link", { name: /users/i }).first(),
    ).toBeVisible({ timeout: 30_000 });

    // A session cookie was set by the successful login (either name).
    const cookies = await context.cookies();
    const hasSession = cookies.some((c) =>
      SESSION_COOKIE_NAMES.includes(c.name),
    );
    expect(hasSession, "a session cookie should be set after login").toBe(true);

    // --- (4) 401 path: drop the session, hit a protected route -> /login. ----
    // Clear every cookie (covers both session-cookie names), then navigate to a
    // guarded (console) route. The server layout's /me fetch now 401s, so the
    // layout redirect('/login') fires — the shell is unreachable unauthenticated.
    await context.clearCookies();
    await page.goto("/users"); // a (console) section route, behind the guard
    await page.waitForURL(/\/login$/, { timeout: 30_000 });
    await expect(
      page.getByRole("button", { name: /^sign in$/i }),
    ).toBeVisible({ timeout: 30_000 });
  });
});
