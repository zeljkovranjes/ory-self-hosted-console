"use client";

// OAUTH2-01 — the create/edit OAuth2 client form (08-UI-SPEC §B).
//
// RHF + Zod inside a Card, mirroring the Users identity-form: a 422 from the
// backend maps to inline field errors via form.setError. Repeatable lists
// (redirect_uris / grant_types / scope) use the OIDC whole-array setValue
// (shouldDirty) pattern.
//
// client_secret is WRITE-ONLY (T-08-FE-SECRET, the headline requirement):
//   - create: an optional secret field; if the operator leaves it blank Hydra
//     generates one and returns it ONCE (surfaced by the caller's reveal block).
//   - edit: the field starts BLANK with the "leave blank to keep" placeholder.
//     We use composeSecret so a blank carries the masked/preserve intent — but
//     the canonical preserve here is structural: the backend PUT omits the secret
//     (client_secret=None) when we don't send one, so an untouched edit field
//     sends NOTHING for the secret (#2869). There is NO "show current secret".
//
// All egress via @/lib/api (attaches X-CSRF-Token on mutations).

import * as React from "react";
import { useRouter } from "next/navigation";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm, type Resolver } from "react-hook-form";
import { toast } from "sonner";
import { z } from "zod";
import { Plus, X } from "lucide-react";

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
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { composeSecret } from "../../authentication/_lib/secret-array";
import {
  type OAuth2Client,
  TOKEN_ENDPOINT_AUTH_METHODS,
} from "../_lib/oauth2-types";

type FormValues = {
  client_name: string;
  token_endpoint_auth_method: string;
  scope: string;
  client_uri: string;
  __secret: string;
  redirect_uris: string[];
  grant_types: string[];
};

const formSchema = z.object({
  client_name: z.string().optional().default(""),
  token_endpoint_auth_method: z.string().min(1, "Auth method is required"),
  scope: z.string().optional().default(""),
  client_uri: z.string().optional().default(""),
  __secret: z.string().optional().default(""),
  redirect_uris: z.array(z.string()).optional().default([]),
  grant_types: z.array(z.string()).optional().default([]),
});

export type ClientFormProps =
  | { mode: "create"; client?: undefined; onCreated: (c: OAuth2Client) => void }
  | { mode: "edit"; client: OAuth2Client; onUpdated?: (c: OAuth2Client) => void };

export function ClientForm(props: ClientFormProps) {
  const { mode } = props;
  const router = useRouter();
  const client = mode === "edit" ? props.client : undefined;

  const defaultValues = React.useMemo<FormValues>(
    () => ({
      client_name: client?.client_name ?? "",
      token_endpoint_auth_method:
        client?.token_endpoint_auth_method ?? "client_secret_basic",
      scope: client?.scope ?? "",
      client_uri: client?.client_uri ?? "",
      // The secret field ALWAYS starts blank (write-only). On edit, blank = keep.
      __secret: "",
      redirect_uris: client?.redirect_uris ?? [],
      grant_types: client?.grant_types ?? [],
    }),
    [client],
  );

  const form = useForm<FormValues>({
    resolver: zodResolver(formSchema) as unknown as Resolver<FormValues>,
    mode: "onBlur",
    defaultValues,
  });

  const [formError, setFormError] = React.useState<string | null>(null);

  const onSubmit = form.handleSubmit(async (values) => {
    setFormError(null);

    // Assemble the crate OAuth2Client shape. Omit empty strings/arrays so we
    // never blank a field unintentionally.
    const body: OAuth2Client = {
      token_endpoint_auth_method: values.token_endpoint_auth_method,
    };
    if (values.client_name) body.client_name = values.client_name;
    if (values.scope) body.scope = values.scope;
    if (values.client_uri) body.client_uri = values.client_uri;
    if (values.redirect_uris.length) body.redirect_uris = values.redirect_uris;
    if (values.grant_types.length) body.grant_types = values.grant_types;

    try {
      if (mode === "create") {
        // A typed secret is sent verbatim; blank lets Hydra generate one.
        if (values.__secret) body.client_secret = values.__secret;
        const created = await api<OAuth2Client>("/api/hydra/clients", {
          method: "POST",
          body: JSON.stringify(body),
        });
        toast.success("Client created");
        props.onCreated(created);
      } else {
        // EDIT: resolve the write-only secret via the shared composeSecret
        // contract. The client_id is immutable on edit (idChanged is always
        // false), and there is no stored sentinel to echo for a client secret
        // (the backend strips it on GET), so `original` is undefined. The result:
        //   - typed value -> rotate (send the new secret);
        //   - blank        -> undefined -> OMITTED entirely, so the backend PUT
        //                     preserves the stored secret (#2869 — structural).
        const secret = composeSecret(values.__secret, undefined, {
          idChanged: false,
        });
        if (secret !== undefined && secret !== "") body.client_secret = secret;
        const updated = await api<OAuth2Client>(
          `/api/hydra/clients/${client!.client_id}`,
          { method: "PUT", body: JSON.stringify(body) },
        );
        toast.success("Client updated");
        if (props.onUpdated) props.onUpdated(updated);
        else router.push(`/oauth2/clients/${client!.client_id}`);
        router.refresh();
      }
    } catch (e) {
      if (e instanceof ApiError && e.status === 422) {
        for (const { path, message } of e.fieldErrors) {
          form.setError(path as never, { type: "server", message });
        }
        return;
      }
      const status = e instanceof ApiError ? ` (${e.status})` : "";
      setFormError(`Could not save the client${status}.`);
      toast.error(`Failed to save client${status}`);
    }
  });

  const hadSecret =
    mode === "edit" &&
    (client?.token_endpoint_auth_method ?? "client_secret_basic") !== "none";

  return (
    <Card>
      <form onSubmit={onSubmit} noValidate>
        <CardHeader>
          <CardTitle>
            {mode === "create" ? "Create OAuth2 client" : "Edit OAuth2 client"}
          </CardTitle>
        </CardHeader>

        <CardContent className="space-y-5 pt-4">
          <div className="grid gap-2">
            <Label htmlFor="client_name">Client name</Label>
            <Input id="client_name" {...form.register("client_name")} />
            <FieldError msg={form.formState.errors.client_name?.message} />
          </div>

          <div className="grid gap-2">
            <Label htmlFor="auth_method">Token endpoint auth method</Label>
            <Select
              value={form.watch("token_endpoint_auth_method")}
              onValueChange={(v) =>
                form.setValue("token_endpoint_auth_method", v, {
                  shouldDirty: true,
                })
              }
            >
              <SelectTrigger id="auth_method" aria-label="Token endpoint auth method">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {TOKEN_ENDPOINT_AUTH_METHODS.map((m) => (
                  <SelectItem key={m} value={m}>
                    {m}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <FieldError
              msg={form.formState.errors.token_endpoint_auth_method?.message}
            />
          </div>

          <ArrayField
            label="Redirect URIs"
            ariaLabel="redirect URI"
            placeholder="https://app.example.com/callback"
            values={form.watch("redirect_uris")}
            onChange={(next) =>
              form.setValue("redirect_uris", next, { shouldDirty: true })
            }
          />

          <ArrayField
            label="Grant types"
            ariaLabel="grant type"
            placeholder="authorization_code"
            values={form.watch("grant_types")}
            onChange={(next) =>
              form.setValue("grant_types", next, { shouldDirty: true })
            }
          />

          <div className="grid gap-2">
            <Label htmlFor="scope">Scope</Label>
            <Input
              id="scope"
              placeholder="openid offline_access profile"
              {...form.register("scope")}
            />
            <p className="text-muted-foreground text-sm">
              Space-separated scope values the client may request.
            </p>
          </div>

          <div className="grid gap-2">
            <Label htmlFor="client_uri">Client URI</Label>
            <Input id="client_uri" placeholder="https://app.example.com" {...form.register("client_uri")} />
          </div>

          <div className="grid gap-2">
            <Label htmlFor="client_secret">Client secret</Label>
            <Input
              id="client_secret"
              type="password"
              autoComplete="new-password"
              placeholder={
                mode === "edit" && hadSecret
                  ? "•••••••• (leave blank to keep)"
                  : "Leave blank to auto-generate"
              }
              {...form.register("__secret")}
            />
            <p className="text-muted-foreground text-sm">
              {mode === "edit"
                ? "Leave blank to keep the current secret. The current secret is never displayed."
                : "Leave blank and Hydra generates one, shown once on creation."}
            </p>
          </div>

          {formError ? (
            <Alert variant="destructive" role="alert">
              <AlertTitle>Save failed</AlertTitle>
              <AlertDescription>{formError}</AlertDescription>
            </Alert>
          ) : null}
        </CardContent>

        <CardFooter className="mt-4 flex justify-end gap-2 border-t pt-4">
          <Button
            type="button"
            variant="outline"
            onClick={() => router.push("/oauth2/clients")}
          >
            Cancel
          </Button>
          <Button type="submit" disabled={form.formState.isSubmitting}>
            {mode === "create" ? "Create client" : "Save changes"}
          </Button>
        </CardFooter>
      </form>
    </Card>
  );
}

function FieldError({ msg }: { msg?: string }) {
  if (!msg) return null;
  return <p className="text-destructive text-sm">{msg}</p>;
}

// A repeatable string-list editor: add/remove rows, whole-array replace
// (shouldDirty) — mirrors the OIDC list-editor pattern.
function ArrayField({
  label,
  ariaLabel,
  placeholder,
  values,
  onChange,
}: {
  label: string;
  ariaLabel: string;
  placeholder?: string;
  values: string[];
  onChange: (next: string[]) => void;
}) {
  return (
    <div className="grid gap-2">
      <Label>{label}</Label>
      <div className="space-y-2">
        {values.map((v, i) => (
          <div key={i} className="flex gap-2">
            <Input
              aria-label={`${ariaLabel} ${i + 1}`}
              placeholder={placeholder}
              value={v}
              onChange={(e) => {
                const next = [...values];
                next[i] = e.target.value;
                onChange(next);
              }}
            />
            <Button
              type="button"
              variant="outline"
              size="icon"
              aria-label={`Remove ${ariaLabel} ${i + 1}`}
              onClick={() => onChange(values.filter((_, j) => j !== i))}
            >
              <X />
            </Button>
          </div>
        ))}
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => onChange([...values, ""])}
        >
          <Plus />
          Add {ariaLabel}
        </Button>
      </div>
    </div>
  );
}
