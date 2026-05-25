"use client";

// FE-01 — first-run setup page.
//
// Gated on the public `GET /api/console/state` (`initialized`): when the console
// has already been bootstrapped (`initialized===true`) this page redirects to
// /login. Otherwise it collects the one-time bootstrap token plus the first
// operator's name/email/password and POSTs them to `/setup`. On success it
// routes to /login (the backend does not auto-log-in the new operator — the
// operator authenticates explicitly).
//
// Security (V2/V5): the password field is type=password with
// autocomplete="new-password"; credentials are posted via lib/api.ts only and
// never stored in client state beyond the in-flight form. The backend /setup
// route does NOT emit 422/per-field validation (a bad bootstrap token → 403,
// other input problems → 400) — so setup failures surface as a single
// destructive Alert (formError). There is intentionally NO inline per-field
// 422 mapping here, because that branch would be unreachable against the real
// backend (WR-05).

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
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

const FIELDS = ["bootstrap_token", "name", "email", "password"] as const;
type Field = (typeof FIELDS)[number];

export default function SetupPage() {
  const router = useRouter();
  const [checking, setChecking] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  // Redirect away once the console is already initialized.
  useEffect(() => {
    let active = true;
    api<ConsoleState>("/api/console/state")
      .then((state) => {
        if (!active) return;
        if (state.initialized) router.replace("/login");
        else setChecking(false);
      })
      .catch(() => {
        // If state can't be read we still render the form; the POST will surface
        // any real backend problem. Don't trap the operator on a blank screen.
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
    // The backend SetupRequest DTO expects the bootstrap token under the key
    // `token` (it may alternatively arrive via the X-Setup-Token header) — NOT
    // `bootstrap_token`. Sending the wrong key makes the backend see no token
    // and reject /setup with 403, blocking first-run setup. (Caught by the live
    // FE-01 auth e2e against the real backend.)
    const body = {
      token: String(data.get("bootstrap_token") ?? ""),
      name: String(data.get("name") ?? ""),
      email: String(data.get("email") ?? ""),
      password: String(data.get("password") ?? ""),
    };
    try {
      await api("/setup", { method: "POST", body: JSON.stringify(body) });
      // The backend does not auto-log-in; route to /login for explicit auth.
      router.replace("/login");
    } catch {
      // The /setup route does not return per-field 422s (bad token → 403,
      // other input → 400), so surface a single generic message. No inline
      // per-field mapping here — that branch would never execute (WR-05).
      setFormError(
        "Setup failed. Please verify the bootstrap token and try again.",
      );
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
        <CardTitle>Set up your console</CardTitle>
        <CardDescription>
          Create the first operator account. Paste the bootstrap token printed in
          the backend logs to authorize setup.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={onSubmit} noValidate className="grid gap-4">
          {formError ? (
            <Alert variant="destructive">
              <AlertTitle>Could not complete setup</AlertTitle>
              <AlertDescription>{formError}</AlertDescription>
            </Alert>
          ) : null}

          <Field
            id="bootstrap_token"
            label="Bootstrap token"
            type="password"
            autoComplete="off"
          />
          <Field id="name" label="Name" type="text" autoComplete="name" />
          <Field
            id="email"
            label="Email"
            type="email"
            autoComplete="username"
          />
          <Field
            id="password"
            label="Password"
            type="password"
            autoComplete="new-password"
          />

          <Button type="submit" disabled={submitting} className="mt-2">
            {submitting ? "Creating…" : "Create operator account"}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}

function Field({
  id,
  label,
  type,
  autoComplete,
}: {
  id: Field;
  label: string;
  type: string;
  autoComplete: string;
}) {
  return (
    <div className="grid gap-2">
      <Label htmlFor={id}>{label}</Label>
      <Input
        id={id}
        name={id}
        type={type}
        autoComplete={autoComplete}
        required
      />
    </div>
  );
}
