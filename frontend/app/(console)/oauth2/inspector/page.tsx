"use client";

// OAUTH2-02 — Token & Flow Inspector (08-UI-SPEC §D, 08-RESEARCH §B/§C).
//
// A single read-mostly page with two tabs:
//   - Token:  paste a token -> POST /api/hydra/oauth2/introspect -> show
//             active/inactive + subject/client/scopes/expiry. When active, an
//             outline "Revoke" button opens the revoke AlertDialog (the ONLY
//             state-changing action; CSRF-guarded by lib/api — T-08-REVOKE-CSRF).
//   - Flow:   enter a challenge + pick a type (login/consent/logout) ->
//             GET /api/hydra/oauth2/{type}?challenge=… -> render the pending
//             request read-only in a Monaco JSON view.
//
// The console INSPECTS and REVOKES only — it does NOT accept/reject the grant
// (that is the end-user login/consent provider app, out of scope — T-08-GRANT).
// All egress is via @/lib/api; no Ory host is ever called directly.

import * as React from "react";
import { Loader2Icon } from "lucide-react";

import { api, ApiError } from "@/lib/api";
import { MonacoEditor } from "@/components/monaco-editor";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { RevokeTokenDialog } from "./revoke-dialog";

// The introspection response mirrors Hydra's IntrospectedOAuth2Token (RFC 7662).
// `active` is the only required field; everything else is best-effort display.
type IntrospectResult = {
  active: boolean;
  sub?: string;
  client_id?: string;
  scope?: string;
  exp?: number;
  token_type?: string;
  token_use?: string;
  username?: string;
};

type FlowKind = "login" | "consent" | "logout";

function fmtExpiry(exp?: number): string {
  if (!exp) return "—";
  // Hydra reports `exp` as seconds since the Unix epoch.
  return new Date(exp * 1000).toLocaleString();
}

function TokenTab() {
  const [token, setToken] = React.useState("");
  const [result, setResult] = React.useState<IntrospectResult | null>(null);
  const [status, setStatus] = React.useState<"idle" | "loading" | "error">(
    "idle",
  );

  async function introspect() {
    if (token.trim().length === 0) return;
    setStatus("loading");
    setResult(null);
    try {
      const res = await api<IntrospectResult>("/api/hydra/oauth2/introspect", {
        method: "POST",
        body: JSON.stringify({ token: token.trim() }),
      });
      setResult(res);
      setStatus("idle");
    } catch {
      setStatus("error");
    }
  }

  const scopes = (result?.scope ?? "")
    .split(" ")
    .map((s) => s.trim())
    .filter(Boolean);

  return (
    <div className="space-y-4">
      <div className="grid gap-2">
        <Label htmlFor="introspect-token">Access or refresh token</Label>
        <Textarea
          id="introspect-token"
          aria-label="Token to introspect"
          placeholder="Paste an OAuth2 access or refresh token…"
          value={token}
          onChange={(e) => setToken(e.target.value)}
          className="font-mono text-xs"
          rows={3}
        />
        <p className="text-muted-foreground text-sm">
          The token is sent to Hydra for introspection only. It is never stored.
        </p>
      </div>

      <div className="flex justify-end">
        <Button
          type="button"
          onClick={introspect}
          disabled={token.trim().length === 0 || status === "loading"}
        >
          {status === "loading" ? (
            <>
              <Loader2Icon className="animate-spin" />
              Introspecting…
            </>
          ) : (
            "Introspect"
          )}
        </Button>
      </div>

      {status === "error" ? (
        <Alert role="alert" variant="destructive">
          <AlertTitle>Introspection failed</AlertTitle>
          <AlertDescription>
            The token could not be introspected. Try again later.
          </AlertDescription>
        </Alert>
      ) : null}

      {result ? (
        result.active ? (
          <div className="space-y-3 rounded-md border p-4">
            {/* Active state uses the semantic --success color, not a green
                utility (08-UI-SPEC Color). */}
            <p className="text-[--success] font-medium">Active token</p>
            <dl className="grid grid-cols-1 gap-3 text-sm sm:grid-cols-2">
              <div className="space-y-1">
                <dt className="text-muted-foreground">Subject</dt>
                <dd className="font-mono text-xs">{result.sub ?? "—"}</dd>
              </div>
              <div className="space-y-1">
                <dt className="text-muted-foreground">Client</dt>
                <dd className="font-mono text-xs">{result.client_id ?? "—"}</dd>
              </div>
              <div className="space-y-1">
                <dt className="text-muted-foreground">Expires</dt>
                <dd>{fmtExpiry(result.exp)}</dd>
              </div>
              <div className="space-y-1">
                <dt className="text-muted-foreground">Type / use</dt>
                <dd>
                  {[result.token_type, result.token_use]
                    .filter(Boolean)
                    .join(" / ") || "—"}
                </dd>
              </div>
            </dl>
            <div className="space-y-1">
              <dt className="text-muted-foreground text-sm">Scopes</dt>
              <dd className="flex flex-wrap gap-1">
                {scopes.length > 0 ? (
                  scopes.map((s) => (
                    <Badge key={s} variant="secondary">
                      {s}
                    </Badge>
                  ))
                ) : (
                  <span className="text-muted-foreground text-sm">
                    No scopes
                  </span>
                )}
              </dd>
            </div>
            <div className="flex justify-end border-t pt-3">
              <RevokeTokenDialog
                token={token.trim()}
                // WR-05: prefill the client_id from introspection so a
                // confidential-client revoke can authenticate (RFC 7009).
                clientId={result.client_id}
                onRevoked={() => setResult(null)}
                trigger={
                  <Button type="button" variant="outline">
                    Revoke
                  </Button>
                }
              />
            </div>
          </div>
        ) : (
          <div className="rounded-md border p-4">
            <p className="text-muted-foreground text-sm">
              Inactive or unknown token — it may be expired, revoked, or never
              issued.
            </p>
          </div>
        )
      ) : null}
    </div>
  );
}

function FlowTab() {
  const [challenge, setChallenge] = React.useState("");
  const [kind, setKind] = React.useState<FlowKind>("login");
  const [raw, setRaw] = React.useState<string | null>(null);
  const [status, setStatus] = React.useState<
    "idle" | "loading" | "notfound" | "error"
  >("idle");

  async function lookup() {
    if (challenge.trim().length === 0) return;
    setStatus("loading");
    setRaw(null);
    try {
      const qp = new URLSearchParams({ challenge: challenge.trim() });
      const res = await api<Record<string, unknown>>(
        `/api/hydra/oauth2/${kind}?${qp.toString()}`,
      );
      setRaw(JSON.stringify(res, null, 2));
      setStatus("idle");
    } catch (e) {
      // WR-04: ONLY a 404 means "no pending request for that challenge". A 502 is
      // the backend's AppError::Upstream — Hydra was unreachable, timed out, or
      // returned an unmapped error — which is an operational failure, NOT an
      // unknown challenge. Collapsing 502 into "not found" would send the
      // operator chasing a bad challenge when Hydra is actually down/slow.
      if (e instanceof ApiError && e.status === 404) {
        setStatus("notfound");
      } else {
        setStatus("error");
      }
    }
  }

  return (
    <div className="space-y-4">
      <Alert role="status">
        <AlertTitle>Read-only lookup</AlertTitle>
        <AlertDescription>
          This looks up a pending request only. The console does not accept or
          reject the grant — the login and consent screens are served by your
          own provider application.
        </AlertDescription>
      </Alert>

      <div className="grid gap-4 sm:grid-cols-[1fr_auto]">
        <div className="grid gap-2">
          <Label htmlFor="flow-challenge">Challenge</Label>
          <Input
            id="flow-challenge"
            aria-label="Flow challenge"
            placeholder="Paste a login / consent / logout challenge…"
            value={challenge}
            onChange={(e) => setChallenge(e.target.value)}
            className="font-mono text-xs"
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor="flow-kind">Request type</Label>
          <Select value={kind} onValueChange={(v) => setKind(v as FlowKind)}>
            <SelectTrigger id="flow-kind" className="w-40">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="login">Login</SelectItem>
              <SelectItem value="consent">Consent</SelectItem>
              <SelectItem value="logout">Logout</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      <div className="flex justify-end">
        <Button
          type="button"
          onClick={lookup}
          disabled={challenge.trim().length === 0 || status === "loading"}
        >
          {status === "loading" ? (
            <>
              <Loader2Icon className="animate-spin" />
              Looking up…
            </>
          ) : (
            "Look up"
          )}
        </Button>
      </div>

      {status === "notfound" ? (
        <div className="rounded-md border p-4">
          <p className="text-muted-foreground text-sm">
            No pending request found for that challenge.
          </p>
        </div>
      ) : null}
      {status === "error" ? (
        <Alert role="alert" variant="destructive">
          <AlertTitle>Lookup failed</AlertTitle>
          <AlertDescription>
            The request could not be looked up. Try again later.
          </AlertDescription>
        </Alert>
      ) : null}

      {raw ? (
        <div className="space-y-2">
          <Label>Pending request</Label>
          <MonacoEditor
            language="json"
            value={raw}
            onChange={() => {}}
            readOnly
            height={320}
            ariaLabel="Pending flow request (read-only)"
          />
        </div>
      ) : null}
    </div>
  );
}

export default function InspectorPage() {
  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">
          Token &amp; Flow Inspector
        </h1>
        <p className="text-muted-foreground text-sm">
          Introspect or revoke an OAuth2 token, or look up a pending login /
          consent / logout request by challenge. This console inspects and
          revokes only — it does not host the login or consent screens.
        </p>
      </div>

      <Tabs defaultValue="token">
        <TabsList>
          <TabsTrigger value="token">Token</TabsTrigger>
          <TabsTrigger value="flow">Flow request</TabsTrigger>
        </TabsList>
        <TabsContent value="token" className="pt-4">
          <TokenTab />
        </TabsContent>
        <TabsContent value="flow" className="pt-4">
          <FlowTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
