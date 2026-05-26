import type { ReactNode } from "react";
import { Info } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

// Phase 7 — the Authentication subtree layout (UI-SPEC §Pages).
//
// A thin server component wrapping every `/authentication/*` config page. It
// renders the section heading and the standing note that every config save in
// this subtree edits the mounted Kratos YAML and restarts Kratos (no live config
// API in self-hosted Ory). The per-page SettingsForm surfaces the live
// validating→applied→restarting→healthy/failed status banner on Save.

export default function AuthenticationLayout({
  children,
}: {
  children: ReactNode;
}) {
  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">
          Authentication
        </h1>
        <p className="text-muted-foreground text-sm">
          Configure how identities sign up, sign in, and recover access.
        </p>
      </div>
      <Alert role="note">
        <Info aria-hidden />
        <AlertTitle>Saving restarts Kratos</AlertTitle>
        <AlertDescription>
          Saving applies to the mounted Kratos configuration and restarts
          Kratos. The status banner reports when the service is healthy again.
        </AlertDescription>
      </Alert>
      {children}
    </div>
  );
}
