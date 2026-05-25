// IDENT-02 — the create-identity route. Renders the schema-driven IdentityForm
// in create mode; the form fetches the active identity schema itself.

import { IdentityForm } from "../identity-form";

export default function NewIdentityPage() {
  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">
          Create identity
        </h1>
        <p className="text-sm text-muted-foreground">
          Fields are generated from the active identity schema.
        </p>
      </div>
      <IdentityForm mode="create" />
    </div>
  );
}
