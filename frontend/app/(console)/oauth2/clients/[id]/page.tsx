"use client";

// OAUTH2-01 — the client detail route (08-UI-SPEC §C). Read-mostly: fetches GET
// /api/hydra/clients/{id} via lib/api.ts (sole egress) and renders the client
// metadata. The secret is write-only — the detail shows only a set/not-set badge
// + a "Rotate secret" button, never the value (T-08-FE-SECRET). Actions: Edit,
// Rotate secret, Delete.

import * as React from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { Check, Copy } from "lucide-react";

import { api } from "@/lib/api";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  type OAuth2Client,
  clientAuthMethod,
  usesSharedSecret,
  clientLabel,
} from "../../_lib/oauth2-types";
import { ClientSecretReveal } from "../client-secret-reveal";
import { DeleteClientDialog, RotateSecretDialog } from "../client-dialogs";

function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = React.useState(false);
  return (
    <Button
      type="button"
      variant="ghost"
      size="icon-sm"
      aria-label={label}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        } catch {
          /* clipboard unavailable */
        }
      }}
    >
      {copied ? <Check /> : <Copy />}
    </Button>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid gap-1">
      <span className="text-muted-foreground text-xs">{label}</span>
      <div className="text-sm">{children}</div>
    </div>
  );
}

export default function ClientDetailPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const id = params.id;
  const [revealed, setRevealed] = React.useState<string | null>(null);

  const query = useQuery({
    queryKey: ["oauth2-client", id],
    queryFn: () => api<OAuth2Client>(`/api/hydra/clients/${id}`),
    enabled: Boolean(id),
  });

  if (query.isPending) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-40 w-full" />
      </div>
    );
  }

  if (query.isError || !query.data) {
    return (
      <Alert variant="destructive">
        <AlertTitle>Failed to load client</AlertTitle>
        <AlertDescription>
          The client could not be loaded. It may have been deleted.
        </AlertDescription>
      </Alert>
    );
  }

  const client = query.data;
  const clientId = client.client_id ?? id;

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div className="space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight">
            {clientLabel(client)}
          </h1>
          <p className="text-sm text-muted-foreground">
            Inspect this client. Secret is write-only — rotate to set a new one;
            the current value cannot be displayed.
          </p>
        </div>
        <div className="flex shrink-0 gap-2">
          <Button asChild variant="outline" size="sm">
            <Link href={`/oauth2/clients/${clientId}/edit`}>Edit</Link>
          </Button>
          <DeleteClientDialog
            clientId={clientId}
            onDeleted={() => router.push("/oauth2/clients")}
            trigger={
              <Button
                variant="outline"
                size="sm"
                className="text-destructive hover:text-destructive"
              >
                Delete
              </Button>
            }
          />
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Client</CardTitle>
        </CardHeader>
        <CardContent className="space-y-5 pt-4">
          <Field label="Client ID">
            <span className="flex items-center gap-1">
              <code className="font-mono text-xs break-all">{clientId}</code>
              <CopyButton value={clientId} label="Copy client ID" />
            </span>
          </Field>

          {/* WR-02: show the OBSERVABLE token-endpoint auth method instead of an
              inferred "secret set" claim (the secret value is masked on GET, so
              its presence cannot be observed). The rotate affordance is only
              offered for shared-secret methods — rotating makes no sense for a
              key-based (`private_key_jwt`) or public (`none`) client. */}
          <Field label="Auth method">
            <span className="flex items-center gap-3">
              <Badge variant="secondary" className="font-mono">
                {clientAuthMethod(client)}
              </Badge>
              {usesSharedSecret(client) ? (
                <RotateSecretDialog
                  client={client}
                  onRotated={(secret) => setRevealed(secret)}
                  trigger={
                    <Button
                      variant="outline"
                      size="sm"
                      className="text-destructive hover:text-destructive"
                    >
                      Rotate secret
                    </Button>
                  }
                />
              ) : null}
            </span>
          </Field>

          <Field label="Grant types">
            {(client.grant_types ?? []).join(", ") || "—"}
          </Field>
          <Field label="Token endpoint auth method">
            {client.token_endpoint_auth_method ?? "—"}
          </Field>
          <Field label="Scope">{client.scope || "—"}</Field>
          <Field label="Redirect URIs">
            {(client.redirect_uris ?? []).length ? (
              <ul className="space-y-1">
                {client.redirect_uris!.map((u, i) => (
                  <li key={i} className="font-mono text-xs break-all">
                    {u}
                  </li>
                ))}
              </ul>
            ) : (
              "—"
            )}
          </Field>
          <Field label="Created">
            {client.created_at
              ? new Date(client.created_at).toLocaleString()
              : "—"}
          </Field>
        </CardContent>
      </Card>

      <ClientSecretReveal
        secret={revealed}
        clientId={clientId}
        onDone={() => setRevealed(null)}
      />
    </div>
  );
}
