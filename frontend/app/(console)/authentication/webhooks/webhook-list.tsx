"use client";

// AUTH-11 / HOOK-04 — Actions & Webhooks list editor (UI-SPEC §10, 07-RESEARCH
// Page 10).
//
// One combined list of Kratos flow `web_hook` entries, each tagged by the flow
// `hooks` array-root pointer it belongs to. Add/Edit opens a dialog (attach
// point + url + method + Monaco Jsonnet body + auth + response). On Save the
// entries are grouped back into per-pointer arrays and PUT as a flat object
// keyed by those pointers (whole-array per pointer, Pitfall 4). Only the
// backend-allowlisted attach points are selectable (default-deny mirrored).
// response.ignore XOR response.parse is enforced in the form (Pitfall 8). An
// untouched auth secret resends EXACTLY the value GET returned (server sentinel
// echoed verbatim, Pitfall 3) so the backend merge preserves it.

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
import { Switch } from "@/components/ui/switch";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

import { composeSecret } from "../_lib/secret-array";

// The allowlisted attach points (the Plan-01 KRATOS_WEBHOOKS subset: each flow's
// default before/after `hooks`). Unlisted pointers are not selectable (a
// server-side 403 backstops anyway). Login/after is the default selection so the
// common case is one click.
export const WEBHOOK_POINTERS = [
  "/selfservice/flows/login/after/hooks",
  "/selfservice/flows/login/before/hooks",
  "/selfservice/flows/registration/after/hooks",
  "/selfservice/flows/registration/before/hooks",
  "/selfservice/flows/recovery/after/hooks",
  "/selfservice/flows/recovery/before/hooks",
  "/selfservice/flows/verification/after/hooks",
  "/selfservice/flows/verification/before/hooks",
  "/selfservice/flows/settings/after/hooks",
  "/selfservice/flows/settings/before/hooks",
] as const;

export type WebhookPointer = (typeof WEBHOOK_POINTERS)[number];

const POINTER_LABEL: Record<string, string> = Object.fromEntries(
  WEBHOOK_POINTERS.map((p) => {
    const m = p.match(/flows\/(\w+)\/(\w+)\/hooks/);
    return [p, m ? `${m[1]} ${m[2]}` : p];
  }),
);

const AUTH_KINDS = ["none", "basic_auth", "api_key"] as const;
type AuthKind = (typeof AUTH_KINDS)[number];

/** A web_hook entry as edited locally (body is decoded Jsonnet source). */
type WebhookEntry = {
  pointer: WebhookPointer;
  url: string;
  method: string;
  body: string;
  authKind: AuthKind;
  basicUser: string;
  basicPassword: string;
  apiKeyName: string;
  apiKeyValue: string;
  apiKeyIn: string;
  ignore: boolean;
  parse: boolean;
  // The secret as GET returned it (sentinel) so an untouched secret round-trips.
  originalSecret?: string;
  // CR-01 / WR-01 / WR-03: webhooks have no stable id — the backend keys merge by
  // `config.url`. We capture the url + auth kind as GET returned them so a rename
  // (or auth-kind switch) can NOT echo the sentinel (the backend would fail closed
  // 422); the operator is prompted to re-enter the secret instead. Undefined on a
  // freshly added entry.
  originalUrl?: string;
  originalKind?: AuthKind;
};

export type WebhookDefaults = Record<string, unknown[]>;

const schema = z.object({
  entries: z.array(z.any()),
}) as unknown as z.ZodType<{ entries: WebhookEntry[] }, { entries: WebhookEntry[] }>;

type StoredAuth = { type?: string; config?: Record<string, unknown> };

// Flatten the per-pointer GET object into a single editable entry list.
function toEntries(defaults: WebhookDefaults): WebhookEntry[] {
  const out: WebhookEntry[] = [];
  for (const pointer of WEBHOOK_POINTERS) {
    const arr = Array.isArray(defaults[pointer]) ? defaults[pointer] : [];
    for (const raw of arr) {
      const item = raw as Record<string, unknown>;
      if (item.hook !== "web_hook") continue; // only web_hook entries
      const cfg = (item.config ?? {}) as Record<string, unknown>;
      const auth = (cfg.auth ?? {}) as StoredAuth;
      const ac = auth.config ?? {};
      const response = (cfg.response ?? {}) as Record<string, unknown>;
      const kind: AuthKind =
        auth.type === "basic_auth"
          ? "basic_auth"
          : auth.type === "api_key"
            ? "api_key"
            : "none";
      out.push({
        pointer,
        url: (cfg.url as string) ?? "",
        method: (cfg.method as string) ?? "POST",
        body: (cfg.body as string) ?? "",
        authKind: kind,
        basicUser: (ac.user as string) ?? "",
        basicPassword: "",
        apiKeyName: (ac.name as string) ?? "",
        apiKeyValue: "",
        apiKeyIn: (ac.in as string) ?? "header",
        ignore: Boolean(response.ignore),
        parse: Boolean(response.parse),
        originalSecret:
          kind === "basic_auth"
            ? (ac.password as string | undefined)
            : kind === "api_key"
              ? (ac.value as string | undefined)
              : undefined,
        originalUrl: (cfg.url as string) ?? "",
        originalKind: kind,
      });
    }
  }
  return out;
}

// Group the editable entries back into the per-pointer flat object.
function toFlat(entries: WebhookEntry[]): Record<string, unknown[]> {
  const flat: Record<string, unknown[]> = {};
  for (const p of WEBHOOK_POINTERS) flat[p] = [];
  for (const e of entries) {
    const config: Record<string, unknown> = {
      url: e.url,
      method: e.method || "POST",
      body: e.body,
      response: { ignore: e.ignore, parse: e.parse },
    };
    // CR-01 / WR-01 / WR-03: the backend keys merge-by-id on config.url. If the url
    // OR the auth kind changed vs. what GET returned, the stored secret can't be
    // preserved by echoing the sentinel — `idChanged` makes composeSecret drop it
    // (the dialog Save guard requires re-entry for the happy path).
    const identityChanged =
      (e.originalUrl !== undefined && e.url !== e.originalUrl) ||
      (e.originalKind !== undefined && e.authKind !== e.originalKind);
    if (e.authKind === "basic_auth") {
      config.auth = {
        type: "basic_auth",
        config: {
          user: e.basicUser,
          password: composeSecret(e.basicPassword, e.originalSecret, {
            idChanged: identityChanged,
          }),
        },
      };
    } else if (e.authKind === "api_key") {
      config.auth = {
        type: "api_key",
        config: {
          name: e.apiKeyName,
          value: composeSecret(e.apiKeyValue, e.originalSecret, {
            idChanged: identityChanged,
          }),
          in: e.apiKeyIn || "header",
        },
      };
    }
    flat[e.pointer].push({ hook: "web_hook", config });
  }
  return flat;
}

function blankEntry(): WebhookEntry {
  return {
    pointer: WEBHOOK_POINTERS[0],
    url: "",
    method: "POST",
    body: "",
    authKind: "none",
    basicUser: "",
    basicPassword: "",
    apiKeyName: "",
    apiKeyValue: "",
    apiKeyIn: "header",
    ignore: false,
    parse: false,
  };
}

export function WebhookList({
  defaultValues,
}: {
  defaultValues: WebhookDefaults;
}) {
  const initialEntries = React.useMemo(
    () => toEntries(defaultValues),
    [defaultValues],
  );

  return (
    <SettingsForm
      schema={schema}
      title="Actions & Webhooks"
      description="Kratos flow web_hook actions. Auth secrets are write-only — leave blank to keep the stored value."
      submitPath="/api/config/kratos/webhooks"
      defaultValues={{ entries: initialEntries } as never}
      onSubmit={async (values) => {
        const entries = (values as { entries: WebhookEntry[] }).entries;
        return api<{ status?: "healthy" | "applied" | "failed" }>(
          "/api/config/kratos/webhooks",
          { method: "PUT", body: JSON.stringify(toFlat(entries)) },
        );
      }}
    >
      {(form) => {
        const entries =
          (form.watch("entries" as never) as unknown as WebhookEntry[]) ?? [];
        function setEntries(next: WebhookEntry[]) {
          form.setValue("entries" as never, next as never, {
            shouldDirty: true,
          });
        }
        return <WebhookTable entries={entries} onChange={setEntries} />;
      }}
    </SettingsForm>
  );
}

function WebhookTable({
  entries,
  onChange,
}: {
  entries: WebhookEntry[];
  onChange: (next: WebhookEntry[]) => void;
}) {
  const [draft, setDraft] = React.useState<{
    index: number | null;
    entry: WebhookEntry;
  } | null>(null);

  function openAdd() {
    setDraft({ index: null, entry: blankEntry() });
  }
  function openEdit(index: number) {
    setDraft({ index, entry: { ...entries[index] } });
  }
  function remove(index: number) {
    onChange(entries.filter((_, i) => i !== index));
  }
  function commit(entry: WebhookEntry, index: number | null) {
    if (index === null) onChange([...entries, entry]);
    else {
      const copy = [...entries];
      copy[index] = entry;
      onChange(copy);
    }
    setDraft(null);
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-end">
        <Button type="button" onClick={openAdd}>
          Add webhook
        </Button>
      </div>

      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Attach point</TableHead>
            <TableHead>URL</TableHead>
            <TableHead>Method</TableHead>
            <TableHead className="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {entries.length === 0 ? (
            <TableRow>
              <TableCell colSpan={4} className="text-muted-foreground text-sm">
                No webhooks configured.
              </TableCell>
            </TableRow>
          ) : (
            entries.map((e, i) => (
              <TableRow key={`${e.pointer}-${i}`}>
                <TableCell>
                  <Badge variant="secondary">{POINTER_LABEL[e.pointer]}</Badge>
                </TableCell>
                <TableCell className="font-mono text-xs">{e.url}</TableCell>
                <TableCell>{e.method}</TableCell>
                <TableCell className="space-x-2 text-right">
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    aria-label={`Edit ${e.url}`}
                    onClick={() => openEdit(i)}
                  >
                    Edit
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    aria-label={`Remove ${e.url}`}
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
        <WebhookDialog
          index={draft.index}
          entry={draft.entry}
          onCancel={() => setDraft(null)}
          onSave={(entry) => commit(entry, draft.index)}
        />
      ) : null}
    </div>
  );
}

function WebhookDialog({
  index,
  entry,
  onCancel,
  onSave,
}: {
  index: number | null;
  entry: WebhookEntry;
  onCancel: () => void;
  onSave: (entry: WebhookEntry) => void;
}) {
  // The secret field starts blank (write-only); originalSecret is preserved.
  const [v, setV] = React.useState<WebhookEntry>({
    ...entry,
    basicPassword: "",
    apiKeyValue: "",
  });

  function set<K extends keyof WebhookEntry>(k: K, val: WebhookEntry[K]) {
    setV((prev) => ({ ...prev, [k]: val }));
  }

  // CR-01 / WR-01 / WR-03: webhooks have no stable id — the backend merges by
  // config.url. If the operator changed the URL or the auth kind, the stored
  // secret can't be carried over (the backend fails closed 422), so require it to
  // be re-entered when one was stored.
  const hadStoredSecret = entry.originalSecret !== undefined;
  const identityChanged =
    (entry.originalUrl !== undefined && v.url !== entry.originalUrl) ||
    (entry.originalKind !== undefined && v.authKind !== entry.originalKind);
  const typedSecret =
    v.authKind === "basic_auth"
      ? v.basicPassword.length > 0
      : v.authKind === "api_key"
        ? v.apiKeyValue.length > 0
        : false;
  // Only block when the (changed) entry still uses an auth kind that needs a
  // secret AND one was previously stored AND the operator hasn't re-typed it.
  const mustReenterSecret =
    identityChanged &&
    hadStoredSecret &&
    v.authKind !== "none" &&
    !typedSecret;

  // response.ignore XOR response.parse (Pitfall 8): enabling one disables the
  // other.
  function setIgnore(on: boolean) {
    setV((prev) => ({ ...prev, ignore: on, parse: on ? false : prev.parse }));
  }
  function setParse(on: boolean) {
    setV((prev) => ({ ...prev, parse: on, ignore: on ? false : prev.ignore }));
  }

  return (
    <Dialog open onOpenChange={(o) => (!o ? onCancel() : undefined)}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>
            {index === null ? "Add webhook" : "Edit webhook"}
          </DialogTitle>
          <DialogDescription>
            Attach a web_hook action to a Kratos flow. Secrets are write-only.
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-4">
          <div className="grid gap-2">
            <Label htmlFor="wh-pointer">Attach point</Label>
            <Select
              value={v.pointer}
              onValueChange={(val) => set("pointer", val as WebhookPointer)}
            >
              <SelectTrigger id="wh-pointer" aria-label="Attach point">
                <SelectValue placeholder="Select…" />
              </SelectTrigger>
              <SelectContent>
                {WEBHOOK_POINTERS.map((p) => (
                  <SelectItem key={p} value={p}>
                    {POINTER_LABEL[p]}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="grid gap-2">
            <Label htmlFor="wh-url">URL</Label>
            <Input
              id="wh-url"
              aria-label="URL"
              value={v.url}
              onChange={(e) => set("url", e.target.value)}
            />
          </div>

          <div className="grid gap-2">
            <Label htmlFor="wh-method">Method</Label>
            <Input
              id="wh-method"
              aria-label="Method"
              value={v.method}
              onChange={(e) => set("method", e.target.value)}
            />
          </div>

          <MonacoEditor
            language="plaintext"
            ariaLabel="Body (Jsonnet)"
            value={v.body}
            onChange={(val) => set("body", val)}
            height={200}
          />

          <div className="grid gap-2">
            <Label htmlFor="wh-auth">Authentication</Label>
            <Select
              value={v.authKind}
              onValueChange={(val) => set("authKind", val as AuthKind)}
            >
              <SelectTrigger id="wh-auth" aria-label="Authentication">
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

          {v.authKind === "basic_auth" ? (
            <>
              <div className="grid gap-2">
                <Label htmlFor="wh-basic-user">Username</Label>
                <Input
                  id="wh-basic-user"
                  aria-label="Username"
                  value={v.basicUser}
                  onChange={(e) => set("basicUser", e.target.value)}
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="wh-basic-pass">Password</Label>
                <Input
                  id="wh-basic-pass"
                  aria-label="Password"
                  type="password"
                  placeholder="•••••••• (leave blank to keep)"
                  value={v.basicPassword}
                  onChange={(e) => set("basicPassword", e.target.value)}
                />
              </div>
            </>
          ) : null}

          {v.authKind === "api_key" ? (
            <>
              <div className="grid gap-2">
                <Label htmlFor="wh-key-name">Header/cookie name</Label>
                <Input
                  id="wh-key-name"
                  aria-label="Header/cookie name"
                  value={v.apiKeyName}
                  onChange={(e) => set("apiKeyName", e.target.value)}
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="wh-key-value">API key value</Label>
                <Input
                  id="wh-key-value"
                  aria-label="API key value"
                  type="password"
                  placeholder="•••••••• (leave blank to keep)"
                  value={v.apiKeyValue}
                  onChange={(e) => set("apiKeyValue", e.target.value)}
                />
              </div>
            </>
          ) : null}

          <div className="flex items-center justify-between gap-4">
            <div className="grid gap-0.5">
              <Label htmlFor="wh-ignore">Ignore response</Label>
              <p className="text-muted-foreground text-sm">
                Fire-and-forget; do not parse the response.
              </p>
            </div>
            <Switch
              id="wh-ignore"
              aria-label="Ignore response"
              checked={v.ignore}
              onCheckedChange={setIgnore}
            />
          </div>

          <div className="flex items-center justify-between gap-4">
            <div className="grid gap-0.5">
              <Label htmlFor="wh-parse">Parse response</Label>
              <p className="text-muted-foreground text-sm">
                Parse the response (may modify the identity or abort the flow).
                Mutually exclusive with “Ignore response”.
              </p>
            </div>
            <Switch
              id="wh-parse"
              aria-label="Parse response"
              checked={v.parse}
              onCheckedChange={setParse}
            />
          </div>
        </div>

        {mustReenterSecret ? (
          <p className="text-destructive text-sm" role="alert">
            You changed this webhook&rsquo;s URL or authentication type. Re-enter
            the secret — the stored secret cannot be carried over when the URL or
            auth type changes.
          </p>
        ) : null}

        <DialogFooter>
          <Button type="button" variant="outline" onClick={onCancel}>
            Cancel
          </Button>
          <Button
            type="button"
            disabled={mustReenterSecret}
            onClick={() => onSave(v)}
          >
            Save webhook
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
