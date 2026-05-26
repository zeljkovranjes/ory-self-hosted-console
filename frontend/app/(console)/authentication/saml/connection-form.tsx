"use client";

// SSO-02/03/04 — the create-SAML-connection form (Phase 14 frontend).
//
// RHF + Zod inside a Card, mirroring the Phase-11 WebhookForm. The operator
// supplies an IdP metadata source — EITHER the uploaded metadata XML (PREFERRED,
// no fetch) OR a metadataUrl — plus the connection id (Polis tenant), an optional
// label, and the required redirect URLs.
//
// HARD INVARIANTS (Phase-14 security crux):
//   - There is NO "skip signature validation" affordance anywhere. The backend
//     runs a MANDATORY signing-cert pre-flight (SSO-02) and an SSRF guard on the
//     metadataUrl (SSO-04); neither can be turned off from here.
//   - A 422 (CA-missing / encryption-only metadata / SSRF reject) — or any other
//     non-2xx — is surfaced VERBATIM via the destructive Alert AND inline at the
//     offending field. A reject is NEVER collapsed into a success toast
//     (T-14-12 / anti-false-green).
//   - The clientSecret is write-only end-to-end: the create response never
//     returns it (Polis mints it into the Kratos provider), so there is no secret
//     input here and nothing to reveal. The page echoes the masked
//     `clientSecret_set` badge from the backend verbatim.
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
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";
import type { CreateConnectionResponse } from "./types";

type MetadataMode = "xml" | "url";

type FormValues = {
  tenant: string;
  name: string;
  metadata_xml: string;
  metadata_url: string;
  default_redirect_url: string;
  redirect_url: string;
};

// The Zod schema is COSMETIC for the metadata/SSRF properties — the authoritative
// signing-cert pre-flight (SSO-02) and SSRF guard (SSO-04) are backend-side and
// may still reject with a 422 that we surface verbatim. We only require the
// always-mandatory fields locally for fast feedback.
const formSchema = z.object({
  tenant: z.string().min(1, "A connection id is required."),
  name: z.string().optional(),
  metadata_xml: z.string().optional(),
  metadata_url: z.string().optional(),
  default_redirect_url: z
    .string()
    .min(1, "A default redirect URL is required.")
    .refine(
      (u) => /^https?:\/\//i.test(u),
      "Must start with http:// or https://.",
    ),
  redirect_url: z.string().min(1, "At least one allowed redirect URL is required."),
});

export type ConnectionFormProps = {
  /** Called on a successful create with the backend response. */
  onCreated: (created: CreateConnectionResponse) => void;
  /** Called when the operator cancels (closes the hosting dialog). */
  onCancel?: () => void;
};

export function ConnectionForm({ onCreated, onCancel }: ConnectionFormProps) {
  const [mode, setMode] = React.useState<MetadataMode>("xml");
  // The verbatim server-reject banner (T-14-12 — a reject is NEVER silent).
  const [formError, setFormError] = React.useState<string | null>(null);

  const form = useForm<FormValues>({
    resolver: zodResolver(formSchema) as unknown as Resolver<FormValues>,
    mode: "onBlur",
    defaultValues: {
      tenant: "",
      name: "",
      metadata_xml: "",
      metadata_url: "",
      default_redirect_url: "",
      redirect_url: "",
    },
  });

  async function onFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    form.setValue("metadata_xml", text, {
      shouldDirty: true,
      shouldValidate: true,
    });
  }

  const onSubmit = form.handleSubmit(async (values) => {
    setFormError(null);

    const xml = values.metadata_xml.trim();
    const url = values.metadata_url.trim();

    // Exactly one metadata source must be present for the selected mode. This is
    // a fast local check; the backend re-validates (signing-cert + SSRF).
    if (mode === "xml" && !xml) {
      form.setError("metadata_xml", {
        type: "manual",
        message: "Upload or paste the IdP metadata XML.",
      });
      return;
    }
    if (mode === "url" && !url) {
      form.setError("metadata_url", {
        type: "manual",
        message: "Enter the IdP metadata URL.",
      });
      return;
    }

    const redirectUrls = values.redirect_url
      .split(/[\n,]/)
      .map((s) => s.trim())
      .filter(Boolean);

    const body = {
      tenant: values.tenant.trim(),
      default_redirect_url: values.default_redirect_url.trim(),
      redirect_url: redirectUrls,
      ...(values.name.trim() ? { name: values.name.trim() } : {}),
      ...(mode === "xml" ? { metadata_xml: xml } : { metadata_url: url }),
    };

    try {
      const created = await api<CreateConnectionResponse>(
        "/api/sso/connections",
        { method: "POST", body: JSON.stringify(body) },
      );
      toast.success("SAML connection created");
      onCreated(created);
    } catch (e) {
      if (e instanceof ApiError && e.status === 422) {
        // 422 = the backend signing-cert pre-flight (SSO-02), the SSRF guard
        // (SSO-04), or a field validation rejected this. Surface EVERY field
        // error inline AND the first message verbatim in the destructive banner.
        let surfaced = false;
        for (const { path, message } of e.fieldErrors) {
          // Map backend field paths onto our form fields where they line up.
          const field =
            path === "metadata_xml" || path === "metadata_url"
              ? mode === "xml"
                ? "metadata_xml"
                : "metadata_url"
              : path;
          if (field) {
            form.setError(field as never, { type: "server", message });
          }
          if (!surfaced) {
            setFormError(message);
            surfaced = true;
          }
        }
        if (!surfaced) {
          setFormError("The SAML connection was rejected.");
        }
        return;
      }
      // 400/502/other — surface the status verbatim; NEVER a success.
      const status = e instanceof ApiError ? e.status : 0;
      const msg =
        status === 502
          ? "The Ory Polis SAML service is not configured or unreachable. Connections cannot be created until it is provisioned."
          : `The SAML connection was rejected${status ? ` (${status})` : ""}.`;
      setFormError(msg);
      toast.error("Failed to create SAML connection");
    }
  });

  return (
    <Card>
      <form onSubmit={onSubmit} noValidate>
        <CardHeader>
          <CardTitle>Create SAML connection</CardTitle>
        </CardHeader>

        <CardContent className="space-y-5 pt-4">
          <div className="grid gap-2">
            <Label htmlFor="tenant">Connection ID</Label>
            <Input
              id="tenant"
              placeholder="e.g. acme-corp"
              className="font-mono text-xs"
              {...form.register("tenant")}
            />
            <p className="text-muted-foreground text-sm">
              A stable identifier for this connection. Link it to an organization
              to route that organization&apos;s sign-ins through this IdP.
            </p>
            <FieldError msg={form.formState.errors.tenant?.message} />
          </div>

          <div className="grid gap-2">
            <Label htmlFor="name">Label (optional)</Label>
            <Input id="name" placeholder="Acme Corp Okta" {...form.register("name")} />
          </div>

          <div className="grid gap-2">
            <Label>IdP metadata</Label>
            <Tabs
              value={mode}
              onValueChange={(v) => {
                setMode(v as MetadataMode);
                setFormError(null);
              }}
            >
              <TabsList>
                <TabsTrigger value="xml">Upload metadata XML</TabsTrigger>
                <TabsTrigger value="url">Metadata URL</TabsTrigger>
              </TabsList>
              <TabsContent value="xml" className="space-y-2 pt-2">
                <Input
                  id="metadata-file"
                  type="file"
                  accept=".xml,application/xml,text/xml"
                  aria-label="Upload IdP metadata XML"
                  onChange={(e) => void onFileChange(e)}
                />
                <Textarea
                  aria-label="IdP metadata XML"
                  placeholder="Or paste the IdP metadata XML here…"
                  className="font-mono text-xs"
                  rows={6}
                  {...form.register("metadata_xml")}
                />
                <p className="text-muted-foreground text-sm">
                  The IdP metadata must include a signing certificate. Metadata
                  with no signing certificate (or encryption-only) is rejected.
                </p>
                <FieldError msg={form.formState.errors.metadata_xml?.message} />
              </TabsContent>
              <TabsContent value="url" className="space-y-2 pt-2">
                <Input
                  id="metadata-url"
                  type="url"
                  placeholder="https://idp.example.com/metadata"
                  className="font-mono text-xs"
                  {...form.register("metadata_url")}
                />
                <p className="text-muted-foreground text-sm">
                  The console fetches this URL server-side. Private, loopback,
                  link-local, and cloud-metadata addresses are rejected.
                </p>
                <FieldError msg={form.formState.errors.metadata_url?.message} />
              </TabsContent>
            </Tabs>
          </div>

          <div className="grid gap-2">
            <Label htmlFor="default_redirect_url">Default redirect URL</Label>
            <Input
              id="default_redirect_url"
              type="url"
              placeholder="https://console.example.com/login/saml"
              className="font-mono text-xs"
              {...form.register("default_redirect_url")}
            />
            <FieldError
              msg={form.formState.errors.default_redirect_url?.message}
            />
          </div>

          <div className="grid gap-2">
            <Label htmlFor="redirect_url">Allowed redirect URLs</Label>
            <Textarea
              id="redirect_url"
              placeholder="One URL per line (or comma-separated)"
              className="font-mono text-xs"
              rows={3}
              {...form.register("redirect_url")}
            />
            <FieldError msg={form.formState.errors.redirect_url?.message} />
          </div>

          {formError ? (
            <Alert variant="destructive" role="alert">
              <AlertTitle>Connection rejected</AlertTitle>
              <AlertDescription>{formError}</AlertDescription>
            </Alert>
          ) : null}
        </CardContent>

        <CardFooter className="mt-4 flex justify-end gap-2 border-t pt-4">
          <Button type="button" variant="outline" onClick={() => onCancel?.()}>
            Cancel
          </Button>
          <Button type="submit" disabled={form.formState.isSubmitting}>
            Create connection
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
