"use client";

// OAUTH2-01 — the create-client route. Renders ClientForm in create mode; on
// success Hydra returns the generated secret ONCE, which we surface via the
// one-time reveal block before navigating to the new client's detail page.

import * as React from "react";
import { useRouter } from "next/navigation";

import { ClientForm } from "../client-form";
import { ClientSecretReveal } from "../client-secret-reveal";
import type { OAuth2Client } from "../../_lib/oauth2-types";

export default function NewClientPage() {
  const router = useRouter();
  const [created, setCreated] = React.useState<OAuth2Client | null>(null);

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">
          Create OAuth2 client
        </h1>
        <p className="text-sm text-muted-foreground">
          Register a new OAuth2 / OIDC client. The client secret is shown once on
          creation and cannot be retrieved later.
        </p>
      </div>

      <ClientForm mode="create" onCreated={(c) => setCreated(c)} />

      <ClientSecretReveal
        secret={created?.client_secret ?? null}
        clientId={created?.client_id}
        onDone={() => {
          const id = created?.client_id;
          setCreated(null);
          router.push(id ? `/oauth2/clients/${id}` : "/oauth2/clients");
        }}
      />
    </div>
  );
}
