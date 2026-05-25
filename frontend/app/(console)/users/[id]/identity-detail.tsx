"use client";

// IDENT-01 — the read-only identity detail view (UI-SPEC §2).
//
// Renders the full identity as cards: traits, verifiable/recovery addresses,
// credential TYPE names (chips — NEVER the inner secret config, T-06-20),
// metadata_public, metadata_admin (clearly labeled admin-only), state badge, and
// timestamps. It is a pure presentational component (the data is fetched by the
// page) so it is trivially unit-testable for the no-secrets invariant.

import Link from "next/link";

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  type Identity,
  credentialTypeNames,
  identityIdentifier,
} from "../identity-types";
import { DeleteIdentityDialog } from "../delete-identity-dialog";

function StateBadge({ state }: { state: string }) {
  const active = state === "active";
  return (
    <Badge variant={active ? "default" : "secondary"}>
      {state || "unknown"}
    </Badge>
  );
}

/** Render a JSON-ish value as a readonly preformatted block. */
function JsonBlock({ value }: { value: unknown }) {
  if (value === undefined || value === null) {
    return <p className="text-sm text-muted-foreground">None</p>;
  }
  return (
    <pre className="max-h-64 overflow-auto rounded-md bg-muted p-3 text-xs">
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}

function AddressList({
  addresses,
}: {
  addresses: Identity["verifiable_addresses"];
}) {
  if (!addresses || addresses.length === 0) {
    return <p className="text-sm text-muted-foreground">None</p>;
  }
  return (
    <ul className="space-y-1 text-sm">
      {addresses.map((a, i) => (
        <li key={`${a.value}-${i}`} className="flex items-center gap-2">
          <span className="font-mono">{a.value}</span>
          {a.via ? <Badge variant="outline">{a.via}</Badge> : null}
          {a.verified ? (
            <Badge variant="default">verified</Badge>
          ) : a.status ? (
            <Badge variant="secondary">{a.status}</Badge>
          ) : null}
        </li>
      ))}
    </ul>
  );
}

export function IdentityDetail({ identity }: { identity: Identity }) {
  const identifier = identityIdentifier(identity);
  // TYPE NAMES ONLY — we never read credential values, so no secret can render.
  const credTypes = credentialTypeNames(identity);

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div className="space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight">
            {identifier}
          </h1>
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <StateBadge state={identity.state} />
            <span className="font-mono text-xs">{identity.id}</span>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button asChild variant="outline" size="sm">
            <Link href={`/users/${identity.id}/edit`}>Edit</Link>
          </Button>
          <DeleteIdentityDialog
            id={identity.id}
            identifier={identifier}
            trigger={
              <Button variant="destructive" size="sm">
                Delete
              </Button>
            }
          />
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Traits</CardTitle>
          <CardDescription>
            Schema: <span className="font-mono">{identity.schema_id}</span>
          </CardDescription>
        </CardHeader>
        <CardContent>
          <JsonBlock value={identity.traits} />
        </CardContent>
      </Card>

      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Verifiable addresses</CardTitle>
          </CardHeader>
          <CardContent>
            <AddressList addresses={identity.verifiable_addresses} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Recovery addresses</CardTitle>
          </CardHeader>
          <CardContent>
            <AddressList addresses={identity.recovery_addresses} />
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Credentials</CardTitle>
          <CardDescription>
            Configured credential types only — secret material is never shown.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {credTypes.length === 0 ? (
            <p className="text-sm text-muted-foreground">None</p>
          ) : (
            <div className="flex flex-wrap gap-2">
              {credTypes.map((type) => (
                <Badge key={type} variant="outline">
                  {type}
                </Badge>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Public metadata</CardTitle>
          </CardHeader>
          <CardContent>
            <JsonBlock value={identity.metadata_public} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              Admin metadata
              <Badge variant="destructive">admin-only</Badge>
            </CardTitle>
            <CardDescription>
              Sensitive operator-only metadata. Not visible to the end user.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <JsonBlock value={identity.metadata_admin} />
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Timestamps</CardTitle>
        </CardHeader>
        <CardContent className="space-y-1 text-sm">
          <p>
            <span className="text-muted-foreground">Created: </span>
            {identity.created_at ?? "—"}
          </p>
          <p>
            <span className="text-muted-foreground">Updated: </span>
            {identity.updated_at ?? "—"}
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
