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
// never stored in client state beyond the in-flight form. Backend 422
// `{path,message}[]` errors map to inline field errors; other failures surface a
// destructive Alert.

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { api, ApiError } from "@/lib/api";
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
  const [fieldErrors, setFieldErrors] = useState<Partial<Record<Field, string>>>(
    {},
  );
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
    setFieldErrors({});
    setFormError(null);
    const data = new FormData(e.currentTarget);
    const body = {
      bootstrap_token: String(data.get("bootstrap_token") ?? ""),
      name: String(data.get("name") ?? ""),
      email: String(data.get("email") ?? ""),
      password: String(data.get("password") ?? ""),
    };
    try {
      await api("/setup", { method: "POST", body: JSON.stringify(body) });
      // The backend does not auto-log-in; route to /login for explicit auth.
      router.replace("/login");
    } catch (err) {
      if (err instanceof ApiError && err.status === 422) {
        const mapped: Partial<Record<Field, string>> = {};
        for (const { path, message } of err.fieldErrors) {
          if ((FIELDS as readonly string[]).includes(path)) {
            mapped[path as Field] = message;
          }
        }
        setFieldErrors(mapped);
        if (Object.keys(mapped).length === 0) {
          setFormError("Setup failed. Please check your input and try again.");
        }
      } else {
        setFormError(
          "Setup failed. Please verify the bootstrap token and try again.",
        );
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
            error={fieldErrors.bootstrap_token}
          />
          <Field
            id="name"
            label="Name"
            type="text"
            autoComplete="name"
            error={fieldErrors.name}
          />
          <Field
            id="email"
            label="Email"
            type="email"
            autoComplete="username"
            error={fieldErrors.email}
          />
          <Field
            id="password"
            label="Password"
            type="password"
            autoComplete="new-password"
            error={fieldErrors.password}
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
  error,
}: {
  id: Field;
  label: string;
  type: string;
  autoComplete: string;
  error?: string;
}) {
  const errorId = `${id}-error`;
  return (
    <div className="grid gap-2">
      <Label htmlFor={id}>{label}</Label>
      <Input
        id={id}
        name={id}
        type={type}
        autoComplete={autoComplete}
        required
        aria-invalid={error ? true : undefined}
        aria-describedby={error ? errorId : undefined}
      />
      {error ? (
        <p id={errorId} className="text-destructive text-sm">
          {error}
        </p>
      ) : null}
    </div>
  );
}
