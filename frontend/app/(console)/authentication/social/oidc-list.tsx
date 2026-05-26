"use client";

// AUTH-04 — Social Sign-In OIDC list editor (UI-SPEC §4, 07-RESEARCH Page 4).
//
// A table of OIDC provider rows + an Add/Edit dialog carrying a Monaco Jsonnet
// mapper. The whole providers array is edited locally and PUT at ONE pointer
// (`/selfservice/methods/oidc/config/providers`) — never per-index (Pitfall 4,
// whole-array replace). client_secret (and apple_private_key) are write-only:
// blank = unchanged. On compose, an untouched secret resends EXACTLY the value
// GET returned (the server sentinel echoed verbatim via `composeSecret`) so the
// backend merge-by-id (07-02) preserves it; a retyped secret sends the new value
// (Pitfall 3). The mapper_url field is the Jsonnet SOURCE — the backend base64
// codec handles the `base64://` URI; the UI edits plaintext.

import * as React from "react";
import { z } from "zod";

import { api } from "@/lib/api";
import { MonacoEditor } from "@/components/monaco-editor";
import { SettingsForm } from "@/components/settings-form";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

import { composeSecret } from "../_lib/secret-array";

const PROVIDERS_PTR = "/selfservice/methods/oidc/config/providers";
const ENABLED_PTR = "/selfservice/methods/oidc/enabled";

// selfServiceOIDCProvider.provider enum (07-RESEARCH Page 4, schema lines
// 441-468). The list-editor select offers exactly these values.
export const OIDC_PROVIDERS = [
  "generic",
  "google",
  "github",
  "github-app",
  "gitlab",
  "microsoft",
  "discord",
  "slack",
  "facebook",
  "auth0",
  "vk",
  "yandex",
  "apple",
  "spotify",
  "netid",
  "dingtalk",
  "linkedin",
  "linkedin_v2",
  "patreon",
  "lark",
  "x",
] as const;

const PKCE_VALUES = ["auto", "never", "force"] as const;

/** A provider as stored/edited locally (mapper_url is the decoded Jsonnet). */
export type OidcProvider = {
  id: string;
  provider: string;
  label?: string;
  client_id: string;
  client_secret?: string;
  issuer_url?: string;
  auth_url?: string;
  token_url?: string;
  mapper_url: string;
  scope?: string[];
  pkce?: string;
  apple_team_id?: string;
  apple_private_key_id?: string;
  apple_private_key?: string;
};

export type OidcDefaults = {
  [PROVIDERS_PTR]: OidcProvider[];
  [ENABLED_PTR]: boolean;
};

// The SettingsForm schema is intentionally a thin pass-through: the structured
// providers array is validated by the backend draft-07 schema (the source of
// truth), and the dialog enforces per-field requirements client-side. We mirror
// only the shape RHF manages.
const schema = z.object({
  [PROVIDERS_PTR]: z.array(z.any()),
  [ENABLED_PTR]: z.boolean(),
}) as unknown as z.ZodType<OidcDefaults, OidcDefaults>;

type DraftState = {
  index: number | null; // null = adding
  values: OidcProvider;
  // The secret as GET returned it (the sentinel) for the row being edited, so an
  // untouched secret round-trips verbatim. Undefined when adding.
  originalSecret?: string;
  originalAppleKey?: string;
};

function blankDraft(): DraftState {
  return {
    index: null,
    values: {
      id: "",
      provider: "github",
      client_id: "",
      mapper_url: "",
    },
  };
}

export function OidcList({ defaultValues }: { defaultValues: OidcDefaults }) {
  return (
    <SettingsForm
      schema={schema}
      title="Social Sign-In"
      description="OpenID Connect / OAuth2 providers. Client secrets are write-only — leave blank to keep the stored value."
      submitPath="/api/config/kratos/oidc"
      defaultValues={defaultValues as never}
      onSubmit={async (values) => {
        const v = values as OidcDefaults;
        return api<{ status?: "healthy" | "applied" | "failed" }>(
          "/api/config/kratos/oidc",
          {
            method: "PUT",
            body: JSON.stringify({
              [PROVIDERS_PTR]: v[PROVIDERS_PTR],
              [ENABLED_PTR]: v[ENABLED_PTR],
            }),
          },
        );
      }}
    >
      {(form) => {
        const providers =
          (form.watch(PROVIDERS_PTR as never) as OidcProvider[]) ?? [];

        function setProviders(next: OidcProvider[]) {
          form.setValue(PROVIDERS_PTR as never, next as never, {
            shouldDirty: true,
          });
        }

        return (
          <OidcTable providers={providers} onChange={setProviders} />
        );
      }}
    </SettingsForm>
  );
}

function OidcTable({
  providers,
  onChange,
}: {
  providers: OidcProvider[];
  onChange: (next: OidcProvider[]) => void;
}) {
  const [draft, setDraft] = React.useState<DraftState | null>(null);

  function openAdd() {
    setDraft(blankDraft());
  }

  function openEdit(index: number) {
    const p = providers[index];
    setDraft({
      index,
      // The secret field starts BLANK in the dialog (write-only); the stored
      // sentinel is held aside so an untouched field round-trips verbatim.
      values: { ...p, client_secret: "", apple_private_key: "" },
      originalSecret: p.client_secret,
      originalAppleKey: p.apple_private_key,
    });
  }

  function remove(index: number) {
    onChange(providers.filter((_, i) => i !== index));
  }

  function commitDraft(next: OidcProvider, original: DraftState) {
    // Compose write-only secrets: untouched -> the verbatim GET value (sentinel);
    // typed -> the new value.
    const composed: OidcProvider = {
      ...next,
      client_secret: composeSecret(
        next.client_secret ?? "",
        original.originalSecret,
      ),
      apple_private_key:
        next.provider === "apple"
          ? composeSecret(next.apple_private_key ?? "", original.originalAppleKey)
          : undefined,
    };
    // Apple forbids client_secret (schema allOf if/then).
    if (composed.provider === "apple") delete composed.client_secret;
    else delete composed.apple_private_key;

    if (original.index === null) {
      onChange([...providers, composed]);
    } else {
      const copy = [...providers];
      copy[original.index] = composed;
      onChange(copy);
    }
    setDraft(null);
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-end">
        <Button type="button" onClick={openAdd}>
          Add provider
        </Button>
      </div>

      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>ID</TableHead>
            <TableHead>Provider</TableHead>
            <TableHead>Client ID</TableHead>
            <TableHead>Secret</TableHead>
            <TableHead className="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {providers.length === 0 ? (
            <TableRow>
              <TableCell colSpan={5} className="text-muted-foreground text-sm">
                No providers configured.
              </TableCell>
            </TableRow>
          ) : (
            providers.map((p, i) => (
              <TableRow key={`${p.id}-${i}`}>
                <TableCell className="font-medium">{p.id}</TableCell>
                <TableCell>{p.provider}</TableCell>
                <TableCell>{p.client_id}</TableCell>
                <TableCell>
                  {p.client_secret || p.apple_private_key ? (
                    <Badge variant="secondary">set</Badge>
                  ) : (
                    <Badge variant="outline">not set</Badge>
                  )}
                </TableCell>
                <TableCell className="space-x-2 text-right">
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    aria-label={`Edit ${p.id}`}
                    onClick={() => openEdit(i)}
                  >
                    Edit
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    aria-label={`Remove ${p.id}`}
                    onClick={() => remove(i)}
                  >
                    Remove
                  </Button>
                </TableCell>
              </TableRow>
            ))
          )}
        </TableBody>
      </Table>

      {draft ? (
        <ProviderDialog
          draft={draft}
          onCancel={() => setDraft(null)}
          onSave={(next) => commitDraft(next, draft)}
        />
      ) : null}
    </div>
  );
}

function ProviderDialog({
  draft,
  onCancel,
  onSave,
}: {
  draft: DraftState;
  onCancel: () => void;
  onSave: (next: OidcProvider) => void;
}) {
  const [v, setV] = React.useState<OidcProvider>(draft.values);
  const isApple = v.provider === "apple";

  function set<K extends keyof OidcProvider>(k: K, val: OidcProvider[K]) {
    setV((prev) => ({ ...prev, [k]: val }));
  }

  return (
    <Dialog open onOpenChange={(o) => (!o ? onCancel() : undefined)}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>
            {draft.index === null ? "Add provider" : "Edit provider"}
          </DialogTitle>
          <DialogDescription>
            Configure an OpenID Connect provider. Secrets are write-only.
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-4">
          <div className="grid gap-2">
            <Label htmlFor="oidc-id">ID</Label>
            <Input
              id="oidc-id"
              aria-label="ID"
              value={v.id}
              onChange={(e) => set("id", e.target.value)}
            />
          </div>

          <div className="grid gap-2">
            <Label htmlFor="oidc-provider">Provider</Label>
            <Select
              value={v.provider}
              onValueChange={(val) => set("provider", val)}
            >
              <SelectTrigger id="oidc-provider" aria-label="Provider">
                <SelectValue placeholder="Select…" />
              </SelectTrigger>
              <SelectContent>
                {OIDC_PROVIDERS.map((p) => (
                  <SelectItem key={p} value={p}>
                    {p}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="grid gap-2">
            <Label htmlFor="oidc-label">Label</Label>
            <Input
              id="oidc-label"
              aria-label="Label"
              value={v.label ?? ""}
              onChange={(e) => set("label", e.target.value)}
            />
          </div>

          <div className="grid gap-2">
            <Label htmlFor="oidc-client-id">Client ID</Label>
            <Input
              id="oidc-client-id"
              aria-label="Client ID"
              value={v.client_id}
              onChange={(e) => set("client_id", e.target.value)}
            />
          </div>

          {!isApple ? (
            <div className="grid gap-2">
              <Label htmlFor="oidc-client-secret">Client secret</Label>
              <Input
                id="oidc-client-secret"
                aria-label="Client secret"
                type="password"
                placeholder={
                  draft.originalSecret ? "•••••••• (leave blank to keep)" : ""
                }
                value={v.client_secret ?? ""}
                onChange={(e) => set("client_secret", e.target.value)}
              />
              <p className="text-muted-foreground text-sm">
                Write-only. Leave blank to keep the stored secret.
              </p>
            </div>
          ) : null}

          {isApple ? (
            <>
              <div className="grid gap-2">
                <Label htmlFor="oidc-apple-team">Apple team ID</Label>
                <Input
                  id="oidc-apple-team"
                  aria-label="Apple team ID"
                  value={v.apple_team_id ?? ""}
                  onChange={(e) => set("apple_team_id", e.target.value)}
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="oidc-apple-key-id">Apple private key ID</Label>
                <Input
                  id="oidc-apple-key-id"
                  aria-label="Apple private key ID"
                  value={v.apple_private_key_id ?? ""}
                  onChange={(e) => set("apple_private_key_id", e.target.value)}
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="oidc-apple-key">Apple private key</Label>
                <Input
                  id="oidc-apple-key"
                  aria-label="Apple private key"
                  type="password"
                  placeholder={
                    draft.originalAppleKey
                      ? "•••••••• (leave blank to keep)"
                      : ""
                  }
                  value={v.apple_private_key ?? ""}
                  onChange={(e) => set("apple_private_key", e.target.value)}
                />
              </div>
            </>
          ) : null}

          <div className="grid gap-2">
            <Label htmlFor="oidc-issuer">Issuer URL</Label>
            <Input
              id="oidc-issuer"
              aria-label="Issuer URL"
              value={v.issuer_url ?? ""}
              onChange={(e) => set("issuer_url", e.target.value)}
            />
          </div>

          <div className="grid gap-2">
            <Label htmlFor="oidc-pkce">PKCE</Label>
            <Select
              value={v.pkce ?? ""}
              onValueChange={(val) => set("pkce", val)}
            >
              <SelectTrigger id="oidc-pkce" aria-label="PKCE">
                <SelectValue placeholder="Select…" />
              </SelectTrigger>
              <SelectContent>
                {PKCE_VALUES.map((p) => (
                  <SelectItem key={p} value={p}>
                    {p}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <MonacoEditor
            language="plaintext"
            ariaLabel="Mapper (Jsonnet)"
            value={v.mapper_url}
            onChange={(val) => set("mapper_url", val)}
            height={240}
          />
          <p className="text-muted-foreground text-sm">
            Jsonnet identity mapper source. Stored inline (base64) by the
            console.
          </p>
        </div>

        <DialogFooter>
          <Button type="button" variant="outline" onClick={onCancel}>
            Cancel
          </Button>
          <Button type="button" onClick={() => onSave(v)}>
            Save provider
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
