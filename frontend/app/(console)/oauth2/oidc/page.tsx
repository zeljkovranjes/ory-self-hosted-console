"use client";

// OAUTH2-04 — OIDC (08-UI-SPEC §E, 08-RESEARCH Page 2).
//
// Two INDEPENDENT cards (mirrors authentication/smtp/page.tsx):
//   (1) A SettingsForm for the non-secret OIDC keys (subject types, dynamic
//       client registration), saved via /api/config/hydra/oidc.
//   (2) A write-only pairwise.salt card. The salt derives pairwise subject
//       identifiers and is on the dedicated write-only endpoint
//       /api/config/hydra/pairwise-salt. GET returns {set:bool} (the salt is never
//       echoed); a blank submit preserves; an explicit "Remove stored" clears.
//       Changing the salt INVALIDATES every existing pairwise subject ID.

import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { z } from "zod";
import { CheckCircle2Icon, CircleIcon, Loader2Icon } from "lucide-react";

import { api, ApiError } from "@/lib/api";
import { SettingsForm } from "@/components/settings-form";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { ConfigSection, SUBJECT_TYPE_VALUES } from "../_lib/config-section";
import {
  PointerStringList,
  PointerSwitch,
  PointerText,
} from "../../authentication/_lib/controls";

const SUPPORTED_TYPES = "/oidc/subject_identifiers/supported_types";
const DCR_ENABLED = "/oidc/dynamic_client_registration/enabled";
const DCR_DEFAULT_SCOPE = "/oidc/dynamic_client_registration/default_scope";

// Non-secret OIDC keys. pairwise.salt is NOT here (dedicated write-only path).
// supported_types is an array of the enum [public, pairwise]; default_scope is an
// array of scope strings.
const oidcSchema = z.object({
  [SUPPORTED_TYPES]: z.array(z.enum(SUBJECT_TYPE_VALUES)),
  [DCR_ENABLED]: z.boolean(),
  [DCR_DEFAULT_SCOPE]: z.array(z.string()),
}) as unknown as z.ZodType<Record<string, unknown>, Record<string, unknown>>;

const oidcDefaults: Record<string, unknown> = {
  [SUPPORTED_TYPES]: ["public"],
  [DCR_ENABLED]: false,
  [DCR_DEFAULT_SCOPE]: [],
};

function NonSecretCard() {
  return (
    <ConfigSection
      service="hydra"
      section="oidc"
      schema={oidcSchema}
      defaults={oidcDefaults}
      title="OIDC"
      description="Subject identifiers, claims, and dynamic client registration."
    >
      {(form) => (
        <div className="space-y-4">
          <PointerStringList
            form={form}
            pointer={SUPPORTED_TYPES}
            label="Supported subject types"
            description="Allowed values: public, pairwise."
            placeholder="public"
          />
          <PointerSwitch
            form={form}
            pointer={DCR_ENABLED}
            label="Dynamic client registration"
            description="Allow clients to self-register via the OIDC DCR endpoints."
          />
          <PointerStringList
            form={form}
            pointer={DCR_DEFAULT_SCOPE}
            label="DCR default scopes"
            description="Scopes granted to dynamically-registered clients."
            placeholder="openid"
          />
        </div>
      )}
    </ConfigSection>
  );
}

function PairwiseSaltCard() {
  const query = useQuery({
    queryKey: ["config", "hydra", "pairwise-salt"],
    queryFn: () => api<{ set: boolean }>("/api/config/hydra/pairwise-salt"),
  });

  const [salt, setSalt] = React.useState("");
  const [status, setStatus] = React.useState<
    "idle" | "saving" | "saved" | "failed"
  >("idle");
  const [failedKind, setFailedKind] = React.useState<"api" | "network">("api");

  async function save() {
    // Write-only: a blank field is a no-op. Never send a value unless typed.
    if (salt.length === 0) return;
    setStatus("saving");
    try {
      await api("/api/config/hydra/pairwise-salt", {
        method: "PUT",
        body: JSON.stringify({ salt }),
      });
      setStatus("saved");
      setSalt("");
      void query.refetch();
    } catch (e) {
      setFailedKind(e instanceof ApiError ? "api" : "network");
      setStatus("failed");
    }
  }

  // Explicitly REMOVE the stored salt (distinct from a blank save which preserves).
  async function clearSalt() {
    setStatus("saving");
    try {
      await api("/api/config/hydra/pairwise-salt", {
        method: "PUT",
        body: JSON.stringify({ clear: true }),
      });
      setStatus("saved");
      setSalt("");
      void query.refetch();
    } catch (e) {
      setFailedKind(e instanceof ApiError ? "api" : "network");
      setStatus("failed");
    }
  }

  const isSet = query.data?.set ?? false;

  return (
    <Card>
      <CardHeader>
        <CardTitle>Pairwise salt</CardTitle>
        <CardDescription>
          The pairwise salt derives pairwise OIDC subject identifiers and is
          write-only. Leave blank to keep the stored value.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4 pt-4">
        <Alert variant="destructive" role="alert">
          <AlertTitle>Changing the salt is destructive</AlertTitle>
          <AlertDescription>
            Changing the pairwise salt invalidates every existing pairwise subject
            identifier. Clients relying on stable pairwise subjects will see new
            user IDs. Only change it during a deliberate migration.
          </AlertDescription>
        </Alert>

        <div className="flex items-center gap-2 text-sm">
          {query.isPending ? (
            <Skeleton className="h-5 w-32" />
          ) : isSet ? (
            <>
              <CheckCircle2Icon className="size-4 text-green-600" />
              <span>Set</span>
            </>
          ) : (
            <>
              <CircleIcon className="text-muted-foreground size-4" />
              <span className="text-muted-foreground">Not set</span>
            </>
          )}
        </div>

        <div className="grid gap-2">
          <Label htmlFor="pairwise-salt">Pairwise salt</Label>
          <Input
            id="pairwise-salt"
            aria-label="Pairwise salt"
            type="password"
            placeholder={isSet ? "•••••••• (leave blank to keep)" : ""}
            value={salt}
            onChange={(e) => setSalt(e.target.value)}
          />
          <p className="text-muted-foreground text-sm">
            The current value is never displayed. Leave blank to keep it.
          </p>
        </div>

        {status === "saved" ? (
          <Alert role="status">
            <CheckCircle2Icon />
            <AlertTitle>Salt saved</AlertTitle>
            <AlertDescription>
              Hydra is restarting to apply the new pairwise salt.
            </AlertDescription>
          </Alert>
        ) : null}
        {status === "failed" ? (
          <Alert role="alert" variant="destructive">
            <AlertTitle>Save failed</AlertTitle>
            <AlertDescription>
              {failedKind === "api"
                ? "The salt could not be applied and was rolled back to last-known-good."
                : "The request could not reach the server. Check your connection and try again."}
            </AlertDescription>
          </Alert>
        ) : null}
      </CardContent>
      <CardFooter className="mt-4 flex justify-between border-t pt-4">
        <Button
          type="button"
          variant="outline"
          onClick={clearSalt}
          disabled={!isSet || status === "saving"}
        >
          Remove stored
        </Button>
        <Button
          type="button"
          onClick={save}
          disabled={salt.length === 0 || status === "saving"}
        >
          {status === "saving" ? (
            <>
              <Loader2Icon className="animate-spin" />
              Saving…
            </>
          ) : (
            "Save"
          )}
        </Button>
      </CardFooter>
    </Card>
  );
}

export default function OidcPage() {
  return (
    <div className="space-y-6">
      <NonSecretCard />
      <PairwiseSaltCard />
    </div>
  );
}
