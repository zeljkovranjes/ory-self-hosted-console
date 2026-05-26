"use client";

// AUTH-10 — SMS page (UI-SPEC §9, 07-RESEARCH Page 9).
//
// A single http courier channel (id `sms`, type `http`). The request body is a
// Jsonnet template edited in Monaco (the backend base64 codec handles the
// `base64://` URI). The auth secret (basic_auth.password / api_key.value) is
// write-only: blank = unchanged. Save composes the WHOLE `/courier/channels`
// array (whole-array replace, Pitfall 4) and resends an untouched secret EXACTLY
// as GET returned it (the server sentinel echoed verbatim, Pitfall 3) so the
// backend merge-by-id preserves it.

import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { z } from "zod";

import { api } from "@/lib/api";
import { MonacoEditor } from "@/components/monaco-editor";
import { SettingsForm } from "@/components/settings-form";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { composeSecret } from "../_lib/secret-array";

const CHANNELS_PTR = "/courier/channels";

const AUTH_KINDS = ["none", "basic_auth", "api_key"] as const;
type AuthKind = (typeof AUTH_KINDS)[number];

type ChannelDraft = {
  url: string;
  method: string;
  body: string;
  authKind: AuthKind;
  basicUser: string;
  basicPassword: string;
  apiKeyName: string;
  apiKeyValue: string;
  apiKeyIn: string;
};

// The form value is the single editable channel draft; the array is composed on
// submit. A thin schema (backend draft-07 schema is the source of truth).
const schema = z.object({
  url: z.string(),
  method: z.string(),
  body: z.string(),
  authKind: z.enum(AUTH_KINDS),
  basicUser: z.string(),
  basicPassword: z.string(),
  apiKeyName: z.string(),
  apiKeyValue: z.string(),
  apiKeyIn: z.string(),
}) as unknown as z.ZodType<ChannelDraft, ChannelDraft>;

type StoredAuth = {
  type?: string;
  config?: Record<string, unknown>;
};

function parseChannel(channels: unknown): {
  draft: ChannelDraft;
  originalSecret: string | undefined;
  // WR-01: the auth KIND as stored. originalSecret is bound to THIS kind; if the
  // operator switches kinds, the stored secret belongs to the old kind and must
  // NOT be echoed for the new one (it would be unresolvable on the backend).
  originalKind: AuthKind;
} {
  const arr = Array.isArray(channels) ? channels : [];
  const ch = (arr[0] ?? {}) as Record<string, unknown>;
  const rc = (ch.request_config ?? {}) as Record<string, unknown>;
  const auth = (rc.auth ?? {}) as StoredAuth;
  const cfg = auth.config ?? {};

  const kind: AuthKind =
    auth.type === "basic_auth"
      ? "basic_auth"
      : auth.type === "api_key"
        ? "api_key"
        : "none";

  const originalSecret =
    kind === "basic_auth"
      ? (cfg.password as string | undefined)
      : kind === "api_key"
        ? (cfg.value as string | undefined)
        : undefined;

  return {
    draft: {
      url: (rc.url as string) ?? "",
      method: (rc.method as string) ?? "POST",
      body: (rc.body as string) ?? "",
      authKind: kind,
      basicUser: (cfg.user as string) ?? "",
      basicPassword: "",
      apiKeyName: (cfg.name as string) ?? "",
      apiKeyValue: "",
      apiKeyIn: (cfg.in as string) ?? "header",
    },
    originalSecret,
    originalKind: kind,
  };
}

function composeChannel(
  v: ChannelDraft,
  originalSecret: string | undefined,
  originalKind: AuthKind,
): Record<string, unknown> {
  const request_config: Record<string, unknown> = {
    url: v.url,
    method: v.method || "POST",
    body: v.body,
  };

  // WR-01: only echo the stored secret when the auth KIND is unchanged. On a kind
  // switch the stored secret belongs to the old kind, so we do NOT carry it over
  // (idChanged) — the operator must have typed a new value (the Save guard
  // enforces this for the happy path; the backend fails closed otherwise).
  const kindChanged = v.authKind !== originalKind;

  if (v.authKind === "basic_auth") {
    request_config.auth = {
      type: "basic_auth",
      config: {
        user: v.basicUser,
        password: composeSecret(v.basicPassword, originalSecret, {
          idChanged: kindChanged,
        }),
      },
    };
  } else if (v.authKind === "api_key") {
    request_config.auth = {
      type: "api_key",
      config: {
        name: v.apiKeyName,
        value: composeSecret(v.apiKeyValue, originalSecret, {
          idChanged: kindChanged,
        }),
        in: v.apiKeyIn || "header",
      },
    };
  }

  return { id: "sms", type: "http", request_config };
}

function SmsForm({
  draft,
  originalSecret,
  originalKind,
}: {
  draft: ChannelDraft;
  originalSecret: string | undefined;
  originalKind: AuthKind;
}) {
  return (
    <SettingsForm
      schema={schema}
      title="SMS"
      description="Configure the HTTP SMS courier channel. Auth secrets are write-only — leave blank to keep the stored value."
      submitPath="/api/config/kratos/sms"
      defaultValues={draft as never}
      onSubmit={async (values) => {
        const v = values as ChannelDraft;
        return api<{ status?: "healthy" | "applied" | "failed" }>(
          "/api/config/kratos/sms",
          {
            method: "PUT",
            body: JSON.stringify({
              [CHANNELS_PTR]: [composeChannel(v, originalSecret, originalKind)],
            }),
          },
        );
      }}
    >
      {(form) => {
        const authKind =
          (form.watch("authKind" as never) as unknown as AuthKind) ?? "none";
        // WR-01: a kind switch means the stored secret (bound to the old kind)
        // can't be carried over. If the operator picked a kind needing a secret
        // but hasn't typed one, prompt them — the compose logic will NOT echo the
        // old secret, so the new credential must be entered here.
        const newSecretValue =
          authKind === "basic_auth"
            ? ((form.watch("basicPassword" as never) as unknown as string) ?? "")
            : authKind === "api_key"
              ? ((form.watch("apiKeyValue" as never) as unknown as string) ?? "")
              : "";
        const kindChanged = authKind !== originalKind;
        const needsNewSecret =
          kindChanged && authKind !== "none" && newSecretValue.length === 0;
        return (
          <div className="space-y-4">
            <div className="text-muted-foreground text-sm">
              Channel <code>sms</code> (type <code>http</code>) — the only
              supported SMS channel.
            </div>

            <div className="grid gap-2">
              <Label htmlFor="sms-url">Request URL</Label>
              <Input
                id="sms-url"
                aria-label="Request URL"
                {...form.register("url" as never)}
              />
            </div>

            <div className="grid gap-2">
              <Label htmlFor="sms-method">Method</Label>
              <Input
                id="sms-method"
                aria-label="Method"
                {...form.register("method" as never)}
              />
            </div>

            <MonacoEditor
              language="plaintext"
              ariaLabel="Request body (Jsonnet)"
              value={(form.watch("body" as never) as unknown as string) ?? ""}
              onChange={(val) =>
                form.setValue("body" as never, val as never, {
                  shouldDirty: true,
                })
              }
              height={240}
            />

            <div className="grid gap-2">
              <Label htmlFor="sms-auth">Authentication</Label>
              <Select
                value={authKind}
                onValueChange={(val) =>
                  form.setValue("authKind" as never, val as never, {
                    shouldDirty: true,
                  })
                }
              >
                <SelectTrigger id="sms-auth" aria-label="Authentication">
                  <SelectValue placeholder="Select…" />
                </SelectTrigger>
                <SelectContent>
                  {AUTH_KINDS.map((k) => (
                    <SelectItem key={k} value={k}>
                      {k}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {needsNewSecret ? (
              <p className="text-destructive text-sm" role="alert">
                You changed the authentication type. Enter the new secret below —
                the previously stored secret cannot be reused for a different
                authentication type.
              </p>
            ) : null}

            {authKind === "basic_auth" ? (
              <>
                <div className="grid gap-2">
                  <Label htmlFor="sms-basic-user">Username</Label>
                  <Input
                    id="sms-basic-user"
                    aria-label="Username"
                    {...form.register("basicUser" as never)}
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="sms-basic-pass">Password</Label>
                  <Input
                    id="sms-basic-pass"
                    aria-label="Password"
                    type="password"
                    placeholder="•••••••• (leave blank to keep)"
                    {...form.register("basicPassword" as never)}
                  />
                </div>
              </>
            ) : null}

            {authKind === "api_key" ? (
              <>
                <div className="grid gap-2">
                  <Label htmlFor="sms-key-name">Header/cookie name</Label>
                  <Input
                    id="sms-key-name"
                    aria-label="Header/cookie name"
                    {...form.register("apiKeyName" as never)}
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="sms-key-value">API key value</Label>
                  <Input
                    id="sms-key-value"
                    aria-label="API key value"
                    type="password"
                    placeholder="•••••••• (leave blank to keep)"
                    {...form.register("apiKeyValue" as never)}
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="sms-key-in">In</Label>
                  <Select
                    value={
                      (form.watch("apiKeyIn" as never) as unknown as string) ??
                      "header"
                    }
                    onValueChange={(val) =>
                      form.setValue("apiKeyIn" as never, val as never, {
                        shouldDirty: true,
                      })
                    }
                  >
                    <SelectTrigger id="sms-key-in" aria-label="In">
                      <SelectValue placeholder="Select…" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="header">header</SelectItem>
                      <SelectItem value="cookie">cookie</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </>
            ) : null}
          </div>
        );
      }}
    </SettingsForm>
  );
}

export default function SmsPage() {
  const query = useQuery({
    queryKey: ["config", "kratos", "sms"],
    queryFn: () => api<Record<string, unknown>>("/api/config/kratos/sms"),
  });

  if (query.isPending) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-56" />
        <Skeleton className="h-72 w-full" />
      </div>
    );
  }

  if (query.isError) {
    return (
      <Alert variant="destructive" role="alert">
        <AlertTitle>Failed to load configuration</AlertTitle>
        <AlertDescription>
          The SMS configuration could not be loaded. Try again later.
        </AlertDescription>
      </Alert>
    );
  }

  const { draft, originalSecret, originalKind } = parseChannel(
    (query.data ?? {})[CHANNELS_PTR],
  );

  return (
    <SmsForm
      draft={draft}
      originalSecret={originalSecret}
      originalKind={originalKind}
    />
  );
}
