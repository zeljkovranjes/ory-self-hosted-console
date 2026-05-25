import type { ReactNode } from "react";

// FE-01 — auth route-group layout (UI-SPEC §1).
//
// The `(auth)` group renders /setup and /login OUTSIDE the authenticated shell:
// no sidebar, no topbar — a single centered card on a neutral full-height
// background. This deliberately has no `/me` guard (these pages are reachable
// while unauthenticated); the authoritative guard lives in `(console)/layout`.
export default function AuthLayout({ children }: { children: ReactNode }) {
  return (
    <main className="bg-background flex min-h-svh flex-col items-center justify-center gap-6 p-6">
      <div className="flex flex-col items-center gap-1 text-center">
        <h1 className="text-lg font-semibold tracking-tight">
          Ory Console — self-hosted
        </h1>
        <p className="text-muted-foreground text-sm">
          Manage your self-hosted Ory stack.
        </p>
      </div>
      {children}
    </main>
  );
}
