// FE-01 — console dashboard landing (UI-SPEC §6).
//
// The authenticated "/" lands here inside the guarded (console) shell. Feature
// content (Activity metrics) arrives in Phase 10; this phase ships a concise,
// honest overview placeholder — no fake-working controls.

export default function DashboardPage() {
  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
        <p className="text-muted-foreground text-sm">
          Manage your self-hosted Ory stack from one console.
        </p>
      </div>
      <p className="text-muted-foreground max-w-prose text-sm">
        Use the sidebar to manage identities, authentication methods, OAuth2
        clients, permissions, branding, and project configuration. Activity
        metrics will appear here in a later phase.
      </p>
    </div>
  );
}
