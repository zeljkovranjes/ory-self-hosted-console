"use client";

// FE-01 — operator login page.
//
// Reads the public `GET /api/console/state`: if the console is not yet
// initialized (`initialized===false`) it redirects to /setup. The
// "Sign in with GitHub" button renders ONLY when `state.github_oauth_enabled`
// is true (T-05-16: never surface a control the backend hasn't configured); the
// button is a top-level navigation to `/backend/auth/github/login`, NOT a fetch.
//
// On a successful POST /login the backend sets the `__Host-console_session`
// cookie; we then fetch `/api/console/me`, seed the CSRF token (setCsrfToken) so
// subsequent mutations carry `X-CSRF-Token`, and navigate to the validated
// post-login target. The `return_to` query param is allowlisted to same-origin
// relative paths only (T-05-15: open-redirect guard).
//
// Security (V2): password field is type=password autocomplete="current-password";
// credentials are posted via lib/api.ts only and never persisted.

import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useState } from "react";
import { api, ApiError, setCsrfToken } from "@/lib/api";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

type ConsoleState = { initialized: boolean; github_oauth_enabled: boolean };
type Me = { id: string; email: string; name: string; csrf_token?: string };

/**
 * Allowlist a post-login redirect target to a same-origin RELATIVE path.
 * Rejects absolute URLs, protocol-relative (`//host`) and backslash tricks —
 * anything that could navigate off-origin. Falls back to "/".
 */
function safeReturnTo(raw: string | null): string {
  if (!raw) return "/";
  // Must be a single leading slash followed by a non-slash (not "//" or "/\").
  if (!/^\/(?![/\\])/.test(raw)) return "/";
  return raw;
}

export default function LoginPage() {
  // useSearchParams (return_to) requires a Suspense boundary during SSR/prerender.
  return (
    <Suspense
      fallback={
        <div
          className="text-muted-foreground text-sm"
          role="status"
          aria-live="polite"
        >
          Loading…
        </div>
      }
    >
      <LoginForm />
    </Suspense>
  );
}

function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [checking, setChecking] = useState(true);
  const [githubEnabled, setGithubEnabled] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const returnTo = safeReturnTo(searchParams.get("return_to"));

  useEffect(() => {
    let active = true;
    api<ConsoleState>("/api/console/state")
      .then((state) => {
        if (!active) return;
        if (!state.initialized) {
          router.replace("/setup");
          return;
        }
        setGithubEnabled(state.github_oauth_enabled);
        setChecking(false);
      })
      .catch(() => {
        if (active) setChecking(false);
      });
    return () => {
      active = false;
    };
  }, [router]);

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setSubmitting(true);
    setFormError(null);
    const data = new FormData(e.currentTarget);
    const body = {
      email: String(data.get("email") ?? ""),
      password: String(data.get("password") ?? ""),
    };
    try {
      await api("/login", { method: "POST", body: JSON.stringify(body) });
      // Seed the CSRF token for subsequent mutations (logout, config saves).
      try {
        const me = await api<Me>("/api/console/me");
        if (me.csrf_token) setCsrfToken(me.csrf_token);
      } catch {
        // Non-fatal: the (console) layout re-fetches /me and re-seeds the token.
      }
      router.replace(returnTo);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        setFormError("Invalid email or password.");
      } else {
        setFormError("Sign in failed. Please try again.");
      }
    } finally {
      setSubmitting(false);
    }
  }

  if (checking) {
    return (
      <div
        className="text-muted-foreground text-sm"
        role="status"
        aria-live="polite"
      >
        Loading…
      </div>
    );
  }

  return (
    <Card className="w-full max-w-sm">
      <CardHeader>
        <CardTitle>Sign in</CardTitle>
        <CardDescription>
          Sign in to manage your self-hosted Ory console.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={onSubmit} noValidate className="grid gap-4">
          {formError ? (
            <Alert variant="destructive">
              <AlertTitle>Could not sign in</AlertTitle>
              <AlertDescription>{formError}</AlertDescription>
            </Alert>
          ) : null}

          <div className="grid gap-2">
            <Label htmlFor="email">Email</Label>
            <Input
              id="email"
              name="email"
              type="email"
              autoComplete="username"
              required
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="password">Password</Label>
            <Input
              id="password"
              name="password"
              type="password"
              autoComplete="current-password"
              required
            />
          </div>

          <Button type="submit" disabled={submitting} className="mt-2">
            {submitting ? "Signing in…" : "Sign in"}
          </Button>

          {githubEnabled ? (
            <Button asChild variant="outline" type="button">
              {/* Top-level navigation (not a fetch) to the backend OAuth start.
                  Renders only when state.github_oauth_enabled === true. */}
              <a href="/backend/auth/github/login">Sign in with GitHub</a>
            </Button>
          ) : null}
        </form>
      </CardContent>
    </Card>
  );
}
