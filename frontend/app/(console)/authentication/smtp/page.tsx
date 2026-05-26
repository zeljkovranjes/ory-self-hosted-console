"use client";

// AUTH-09 — Email / SMTP page (UI-SPEC §8, 07-RESEARCH Page 8).
//
// Two INDEPENDENT controls:
//   (1) A write-only connection URI. The URI carries the SMTP password and is on
//       the hard denylist — it is written ONLY via the dedicated endpoint
//       /api/kratos/smtp-connection (07-02). GET returns {set:bool} (the URI is
//       never echoed); a blank submit is a no-op (does not send a real value).
//   (2) A SettingsForm for the non-secret SMTP keys, saved via the generic
//       section path /api/config/kratos/smtp.

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
import { PointerText } from "../_lib/controls";

const FROM_ADDRESS = "/courier/smtp/from_address";
const FROM_NAME = "/courier/smtp/from_name";
const LOCAL_NAME = "/courier/smtp/local_name";
const CLIENT_CERT = "/courier/smtp/client_cert_path";
const CLIENT_KEY = "/courier/smtp/client_key_path";

// Non-secret SMTP keys (07-RESEARCH Page 8). `headers` (object map) is omitted
// from the MVP form surface; connection_uri is NOT here (dedicated path).
const smtpSchema = z.object({
  [FROM_ADDRESS]: z.union([z.literal(""), z.string().email("Enter a valid email address")]),
  [FROM_NAME]: z.string(),
  [LOCAL_NAME]: z.string(),
  [CLIENT_CERT]: z.string(),
  [CLIENT_KEY]: z.string(),
}) as unknown as z.ZodType<Record<string, string>, Record<string, string>>;

const smtpDefaults: Record<string, string> = {
  [FROM_ADDRESS]: "",
  [FROM_NAME]: "",
  [LOCAL_NAME]: "",
  [CLIENT_CERT]: "",
  [CLIENT_KEY]: "",
};

function ConnectionUriCard() {
  const query = useQuery({
    queryKey: ["smtp-connection"],
    queryFn: () => api<{ set: boolean }>("/api/kratos/smtp-connection"),
  });

  const [uri, setUri] = React.useState("");
  const [status, setStatus] = React.useState<
    "idle" | "saving" | "saved" | "failed"
  >("idle");
  // WR-06: distinguish a server/API rejection (rolled back) from a transport/
  // unknown failure (the request may not have reached the server), so the alert
  // can give an accurate message instead of a misleading dead-branch ternary.
  const [failedKind, setFailedKind] = React.useState<"api" | "network">("api");

  async function save() {
    // Write-only: a blank field is a no-op. Never send a real/sentinel value
    // unless the operator typed one.
    if (uri.length === 0) return;
    setStatus("saving");
    try {
      await api("/api/kratos/smtp-connection", {
        method: "PUT",
        body: JSON.stringify({ connection_uri: uri }),
      });
      setStatus("saved");
      setUri("");
      void query.refetch();
    } catch (e) {
      setFailedKind(e instanceof ApiError ? "api" : "network");
      setStatus("failed");
    }
  }

  // WR-05: explicitly REMOVE the stored connection URI (decommission the
  // credential). Distinct from a blank save (which preserves): we send
  // `{ clear: true }`, which the backend writes as an empty connection_uri.
  async function clearConnection() {
    setStatus("saving");
    try {
      await api("/api/kratos/smtp-connection", {
        method: "PUT",
        body: JSON.stringify({ clear: true }),
      });
      setStatus("saved");
      setUri("");
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
        <CardTitle>SMTP connection</CardTitle>
        <CardDescription>
          The SMTP connection URI carries the mail password and is write-only.
          Leave blank to keep the stored value.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4 pt-4">
        <div className="flex items-center gap-2 text-sm">
          {query.isPending ? (
            <Skeleton className="h-5 w-32" />
          ) : isSet ? (
            <>
              <CheckCircle2Icon className="size-4 text-green-600" />
              <span>Configured</span>
            </>
          ) : (
            <>
              <CircleIcon className="text-muted-foreground size-4" />
              <span className="text-muted-foreground">Not set</span>
            </>
          )}
        </div>

        <div className="grid gap-2">
          <Label htmlFor="smtp-connection-uri">Connection URI</Label>
          <Input
            id="smtp-connection-uri"
            aria-label="Connection URI"
            type="password"
            placeholder={isSet ? "•••••••• (leave blank to keep)" : "smtps://…"}
            value={uri}
            onChange={(e) => setUri(e.target.value)}
          />
          <p className="text-muted-foreground text-sm">
            Example: <code>smtps://user:password@smtp.example.com:465</code>.
            Test by triggering a recovery/verification flow after saving.
          </p>
        </div>

        {status === "saved" ? (
          <Alert role="status">
            <CheckCircle2Icon />
            <AlertTitle>Connection saved</AlertTitle>
            <AlertDescription>
              Kratos is restarting to apply the new SMTP connection.
            </AlertDescription>
          </Alert>
        ) : null}
        {status === "failed" ? (
          <Alert role="alert" variant="destructive">
            <AlertTitle>Save failed</AlertTitle>
            <AlertDescription>
              {failedKind === "api"
                ? "The connection URI could not be applied and was rolled back."
                : "The request could not reach the server. Check your connection and try again."}
            </AlertDescription>
          </Alert>
        ) : null}
      </CardContent>
      <CardFooter className="mt-4 flex justify-between border-t pt-4">
        {/* WR-05: explicit "clear" affordance — remove the stored URI (distinct
            from leaving the field blank, which preserves it). */}
        <Button
          type="button"
          variant="outline"
          onClick={clearConnection}
          disabled={!isSet || status === "saving"}
        >
          Remove stored URI
        </Button>
        <Button
          type="button"
          onClick={save}
          disabled={uri.length === 0 || status === "saving"}
        >
          {status === "saving" ? (
            <>
              <Loader2Icon className="animate-spin" />
              Saving…
            </>
          ) : (
            "Save connection URI"
          )}
        </Button>
      </CardFooter>
    </Card>
  );
}

function NonSecretCard() {
  const query = useQuery({
    queryKey: ["config", "kratos", "smtp"],
    queryFn: () => api<Record<string, unknown>>("/api/config/kratos/smtp"),
  });

  if (query.isPending) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-56" />
        <Skeleton className="h-72 w-full" />
      </div>
    );
  }

  if (query.isError) {
    return (
      <Alert variant="destructive" role="alert">
        <AlertTitle>Failed to load configuration</AlertTitle>
        <AlertDescription>
          The SMTP configuration could not be loaded. Try again later.
        </AlertDescription>
      </Alert>
    );
  }

  const merged = { ...smtpDefaults, ...(query.data ?? {}) } as Record<
    string,
    string
  >;

  return (
    <SettingsForm
      schema={smtpSchema}
      title="Sender & transport"
      description="Non-secret SMTP settings (from address, transport hints)."
      submitPath="/api/config/kratos/smtp"
      defaultValues={merged as never}
    >
      {(form) => (
        <div className="space-y-4">
          <PointerText
            form={form}
            pointer={FROM_ADDRESS}
            label="From address"
            type="email"
            placeholder="no-reply@example.com"
          />
          <PointerText form={form} pointer={FROM_NAME} label="From name" />
          <PointerText
            form={form}
            pointer={LOCAL_NAME}
            label="Local name (HELO/EHLO)"
          />
          <PointerText
            form={form}
            pointer={CLIENT_CERT}
            label="Client certificate path (mTLS)"
          />
          <PointerText
            form={form}
            pointer={CLIENT_KEY}
            label="Client key path (mTLS)"
          />
        </div>
      )}
    </SettingsForm>
  );
}

export default function SmtpPage() {
  return (
    <div className="space-y-6">
      <ConnectionUriCard />
      <NonSecretCard />
    </div>
  );
}
