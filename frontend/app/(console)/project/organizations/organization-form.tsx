"use client";

// SSO-05/06 — the create-organization form (Phase 14 frontend).
//
// RHF + Zod inside a Card, mirroring the Phase-11 WebhookForm. Captures a label,
// one or more verified email domains, and an optional linked SSO connection
// tenant (selectable from the saml connections this console remembers, or typed
// directly). The login-time routing UI is Phase 15 — this is org management only.
//
// HARD INVARIANTS:
//   - A domain-collision (409) or invalid/ambiguous-domain (422) reject is
//     surfaced VERBATIM via the destructive Alert AND inline at the domains
//     field — NEVER collapsed into a success (T-14-12, mirroring the SAML/SSRF
//     pattern). The backend normalize_domain is authoritative; the Zod check is
//     cosmetic.
//   - No Enterprise/license/requires-Ory copy.
//
// All egress via @/lib/api (attaches X-CSRF-Token on the POST).

import * as React from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm, type Resolver } from "react-hook-form";
import { toast } from "sonner";
import { z } from "zod";

import { api, ApiError } from "@/lib/api";
import {
  Card,
  CardContent,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { readTenantRegistry } from "../../authentication/saml/types";
import type { Organization } from "./types";

type FormValues = {
  label: string;
  domains: string;
  sso_connection_tenant: string;
};

const formSchema = z.object({
  label: z.string().min(1, "An organization label is required."),
  // Domains are validated authoritatively by the backend (registered-domain /
  // IDNA / collision). The Zod check is cosmetic — require at least one entry.
  domains: z.string().min(1, "Enter at least one verified domain."),
  sso_connection_tenant: z.string().optional(),
});

export type OrganizationFormProps = {
  onCreated: (org: Organization) => void;
  onCancel?: () => void;
};

export function OrganizationForm({ onCreated, onCancel }: OrganizationFormProps) {
  const [formError, setFormError] = React.useState<string | null>(null);
  // The saml connections this console remembers — offered as a datalist so the
  // operator can link a known connection without leaving the page.
  const knownTenants = React.useMemo(() => readTenantRegistry(), []);

  const form = useForm<FormValues>({
    resolver: zodResolver(formSchema) as unknown as Resolver<FormValues>,
    mode: "onBlur",
    defaultValues: { label: "", domains: "", sso_connection_tenant: "" },
  });

  const onSubmit = form.handleSubmit(async (values) => {
    setFormError(null);

    const domains = values.domains
      .split(/[\n,]/)
      .map((s) => s.trim())
      .filter(Boolean);

    if (domains.length === 0) {
      form.setError("domains", {
        type: "manual",
        message: "Enter at least one verified domain.",
      });
      return;
    }

    const tenant = values.sso_connection_tenant.trim();
    const body = {
      label: values.label.trim(),
      domains,
      ...(tenant ? { sso_connection_tenant: tenant } : {}),
    };

    try {
      const created = await api<Organization>("/api/organizations", {
        method: "POST",
        body: JSON.stringify(body),
      });
      toast.success("Organization created");
      onCreated(created);
    } catch (e) {
      if (e instanceof ApiError && e.status === 422) {
        // 422 = an invalid/ambiguous domain (normalize_domain rejected it).
        // Surface every field error inline AND the first message verbatim.
        let surfaced = false;
        for (const { path, message } of e.fieldErrors) {
          const field = path === "" ? "domains" : path;
          form.setError(field as never, { type: "server", message });
          if (!surfaced) {
            setFormError(message);
            surfaced = true;
          }
        }
        if (!surfaced) {
          setFormError("The organization was rejected.");
        }
        return;
      }
      if (e instanceof ApiError && e.status === 409) {
        // Domain collision — a verified domain is already claimed by another
        // organization. Surface it verbatim at the domains field + banner.
        const msg =
          "One of these domains is already verified by another organization. Each domain can belong to only one organization.";
        setFormError(msg);
        form.setError("domains", { type: "server", message: msg });
        return;
      }
      if (e instanceof ApiError && e.status === 400) {
        // BadRequest carries a plain message (label/domain bounds, empty label).
        setFormError(
          "The organization was rejected: check the label length and that each domain is a valid registrable domain.",
        );
        return;
      }
      const status = e instanceof ApiError ? ` (${e.status})` : "";
      setFormError(`Could not create the organization${status}.`);
      toast.error(`Failed to create organization${status}`);
    }
  });

  return (
    <Card>
      <form onSubmit={onSubmit} noValidate>
        <CardHeader>
          <CardTitle>Create organization</CardTitle>
        </CardHeader>

        <CardContent className="space-y-5 pt-4">
          <div className="grid gap-2">
            <Label htmlFor="label">Label</Label>
            <Input id="label" placeholder="Acme Corp" {...form.register("label")} />
            <FieldError msg={form.formState.errors.label?.message} />
          </div>

          <div className="grid gap-2">
            <Label htmlFor="domains">Verified domains</Label>
            <Textarea
              id="domains"
              placeholder="One domain per line (or comma-separated), e.g. acme.com"
              className="font-mono text-xs"
              rows={3}
              {...form.register("domains")}
            />
            <p className="text-muted-foreground text-sm">
              Email domains that belong to this organization. Each domain can
              belong to only one organization.
            </p>
            <FieldError msg={form.formState.errors.domains?.message} />
          </div>

          <div className="grid gap-2">
            <Label htmlFor="sso_connection_tenant">
              Linked SSO connection (optional)
            </Label>
            <Input
              id="sso_connection_tenant"
              list="saml-tenant-options"
              placeholder="SAML connection id"
              className="font-mono text-xs"
              {...form.register("sso_connection_tenant")}
            />
            {knownTenants.length ? (
              <datalist id="saml-tenant-options">
                {knownTenants.map((t) => (
                  <option key={t} value={t} />
                ))}
              </datalist>
            ) : null}
            <p className="text-muted-foreground text-sm">
              Route this organization&apos;s sign-ins through a SAML connection.
              Sign-in routing itself is configured separately.
            </p>
          </div>

          {formError ? (
            <Alert variant="destructive" role="alert">
              <AlertTitle>Organization rejected</AlertTitle>
              <AlertDescription>{formError}</AlertDescription>
            </Alert>
          ) : null}
        </CardContent>

        <CardFooter className="mt-4 flex justify-end gap-2 border-t pt-4">
          <Button type="button" variant="outline" onClick={() => onCancel?.()}>
            Cancel
          </Button>
          <Button type="submit" disabled={form.formState.isSubmitting}>
            Create organization
          </Button>
        </CardFooter>
      </form>
    </Card>
  );
}

function FieldError({ msg }: { msg?: string }) {
  if (!msg) return null;
  return (
    <p className="text-destructive text-sm" role="alert">
      {msg}
    </p>
  );
}
