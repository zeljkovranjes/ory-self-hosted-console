"use client";

// AX-04 — Custom Domains editor (replaces the BRAND-05 stub).
//
// A real flag-gated editor for the Account Experience custom domain. It composes
// three panels, all egressing through @/lib/api (the sole backend egress; no
// Ory/AX host literal):
//
//   (a) the public base URL / issuer + allowed return URLs editor — a
//       ConfigSection/SettingsForm over the `kratos`/`ui-urls` section, scoped to
//       the newly-allowlisted `/serve/public/base_url` + `/selfservice/
//       allowed_return_urls`. On save Kratos restarts ONLY (the config-edit path).
//       The full ui_url set is editable on the dedicated UI URLs & Redirects page
//       (linked below); this page surfaces the custom-domain keys specifically.
//   (b) a reverse-proxy guidance snippet panel — GET /api/account-experience/
//       reverse-proxy-snippet?host=… returns an nginx/Caddy/Traefik example string
//       rendered read-only with a copy affordance. NO TLS/DNS provisioning: the
//       operator's reverse proxy owns certificates + DNS.
//   (c) an SSRF-guarded reachability check — POST /api/account-experience/
//       reachability { url }. A 422/400 SSRF rejection is surfaced VERBATIM as a
//       destructive inline error, NEVER collapsed into a reachable result.
//
// Gated by the `account_experience` FeatureGate: flag OFF renders the neutral
// disabled state (the backend routes ALSO 404 — FLAG-01). There is NO "Enterprise
// License" / "requires Ory" copy and NO TLS/DNS provisioning anywhere.

import * as React from "react";
import Link from "next/link";
import { z } from "zod";
import {
  CheckCircle2Icon,
  CircleAlertIcon,
  CopyIcon,
  InfoIcon,
  Loader2Icon,
} from "lucide-react";

import { api, ApiError } from "@/lib/api";
import { FeatureGate } from "@/components/feature-gate";
import { ConfigSection } from "../../authentication/_lib/config-section";
import { PointerStringList, PointerText } from "../../authentication/_lib/controls";
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

const BASE_URL = "/serve/public/base_url";
const ALLOWED_RETURN = "/selfservice/allowed_return_urls";

// The custom-domain subset of the ui-urls section: the public base URL / issuer
// (newly allowlisted) + the allowed return URLs. The keys ARE the allowlisted
// JSON-Pointers (the flat pointer-keyed PUT body). The SettingsForm PUTs ONLY the
// dirty fields, so editing here never blanks the other ui_url pointers.
const schema = z.object({
  [BASE_URL]: z.string(),
  [ALLOWED_RETURN]: z.array(z.string()),
}) as unknown as z.ZodType<Record<string, unknown>, Record<string, unknown>>;

const defaults: Record<string, unknown> = {
  [BASE_URL]: "",
  [ALLOWED_RETURN]: [],
};

// --- (b) Reverse-proxy guidance snippet panel ----------------------------------

type SnippetResponse = { snippet?: string };

function ReverseProxySnippet() {
  const [host, setHost] = React.useState("");
  const [snippet, setSnippet] = React.useState<string | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [copied, setCopied] = React.useState(false);

  async function onGenerate() {
    setLoading(true);
    setError(null);
    setCopied(false);
    try {
      const q = host.trim() ? `?host=${encodeURIComponent(host.trim())}` : "";
      const res = await api<SnippetResponse>(
        `/api/account-experience/reverse-proxy-snippet${q}`,
      );
      setSnippet(res?.snippet ?? "");
    } catch (e) {
      const suffix = e instanceof ApiError ? ` (${e.status})` : "";
      setError(`The reverse-proxy snippet could not be generated${suffix}.`);
    } finally {
      setLoading(false);
    }
  }

  async function onCopy() {
    if (!snippet) return;
    try {
      await navigator.clipboard?.writeText(snippet);
      setCopied(true);
    } catch {
      // Clipboard unavailable (e.g. insecure context): non-fatal, the snippet is
      // visible in the read-only block for manual copy.
      setCopied(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Reverse-proxy snippet</CardTitle>
        <CardDescription>
          Generate an nginx, Caddy, and Traefik example mapping your custom domain
          to the Account Experience service and the Kratos public path. Your
          reverse proxy owns TLS and DNS — this console does not provision
          certificates or DNS records.
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-4 pt-4">
        <div className="grid gap-1.5">
          <Label htmlFor="rp-host">Custom domain</Label>
          <Input
            id="rp-host"
            value={host}
            onChange={(e) => setHost(e.target.value)}
            placeholder="accounts.your-domain.example"
            aria-label="Custom domain for the reverse-proxy snippet"
          />
        </div>

        {error ? (
          <Alert role="alert" variant="destructive">
            <CircleAlertIcon />
            <AlertTitle>Snippet failed</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : null}

        {snippet !== null ? (
          <div className="space-y-2">
            <div className="flex justify-end">
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => void onCopy()}
              >
                <CopyIcon />
                {copied ? "Copied" : "Copy"}
              </Button>
            </div>
            <pre
              className="bg-muted max-h-96 overflow-auto rounded-md p-4 text-xs"
              aria-label="Reverse-proxy guidance snippet"
            >
              <code>{snippet}</code>
            </pre>
          </div>
        ) : null}
      </CardContent>

      <CardFooter className="mt-4 flex justify-end border-t pt-4">
        <Button
          type="button"
          onClick={() => void onGenerate()}
          disabled={loading}
        >
          {loading ? (
            <>
              <Loader2Icon className="animate-spin" />
              Generating…
            </>
          ) : (
            "Generate snippet"
          )}
        </Button>
      </CardFooter>
    </Card>
  );
}

// --- (c) SSRF-guarded reachability check ---------------------------------------

type ReachabilityResponse = { reachable?: boolean; status?: number };

function ReachabilityCheck() {
  const [url, setUrl] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [result, setResult] = React.useState<ReachabilityResponse | null>(null);
  const [rejected, setRejected] = React.useState<string | null>(null);

  async function onCheck() {
    setLoading(true);
    setResult(null);
    setRejected(null);
    try {
      const res = await api<ReachabilityResponse>(
        "/api/account-experience/reachability",
        { method: "POST", body: JSON.stringify({ url: url.trim() }) },
      );
      setResult(res ?? {});
    } catch (e) {
      // An SSRF rejection (422/400) is surfaced VERBATIM as a destructive error,
      // NEVER collapsed into a reachable:false success (anti-false-green,
      // T-15-15 — mirrors the Phase-11 webhook SSRF-reject surfacing).
      if (e instanceof ApiError && (e.status === 422 || e.status === 400)) {
        const fieldMsg = e.fieldErrors[0]?.message;
        setRejected(
          fieldMsg ??
            "This URL was rejected: it resolves to a private, loopback, or otherwise disallowed address.",
        );
      } else {
        const suffix = e instanceof ApiError ? ` (${e.status})` : "";
        setRejected(`The reachability check could not run${suffix}.`);
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Reachability check</CardTitle>
        <CardDescription>
          Probe a custom-domain URL from the backend. Internal, loopback, and
          credentialed targets are refused before any connection is made.
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-4 pt-4">
        <div className="grid gap-1.5">
          <Label htmlFor="reach-url">URL to check</Label>
          <Input
            id="reach-url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://accounts.your-domain.example/health/ready"
            aria-label="URL to check for reachability"
          />
        </div>

        {rejected ? (
          <Alert role="alert" variant="destructive">
            <CircleAlertIcon />
            <AlertTitle>URL rejected</AlertTitle>
            <AlertDescription>{rejected}</AlertDescription>
          </Alert>
        ) : null}

        {result ? (
          result.reachable ? (
            <Alert role="status" aria-live="polite">
              <CheckCircle2Icon className="text-green-600 dark:text-green-500" />
              <AlertTitle>Reachable</AlertTitle>
              <AlertDescription>
                The target responded
                {typeof result.status === "number"
                  ? ` with HTTP ${result.status}`
                  : ""}
                .
              </AlertDescription>
            </Alert>
          ) : (
            <Alert role="status" aria-live="polite">
              <InfoIcon />
              <AlertTitle>Not reachable</AlertTitle>
              <AlertDescription>
                The target passed the safety checks but did not answer. Confirm
                your reverse proxy is serving the domain.
              </AlertDescription>
            </Alert>
          )
        ) : null}
      </CardContent>

      <CardFooter className="mt-4 flex justify-end border-t pt-4">
        <Button
          type="button"
          onClick={() => void onCheck()}
          disabled={loading || !url.trim()}
        >
          {loading ? (
            <>
              <Loader2Icon className="animate-spin" />
              Checking…
            </>
          ) : (
            "Check reachability"
          )}
        </Button>
      </CardFooter>
    </Card>
  );
}

// --- (a) base URL / allowed return URLs editor + the page body -----------------

function CustomDomainsEditor() {
  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Custom Domains</h1>
        <p className="text-sm text-muted-foreground">
          Point the Account Experience at your own domain. Set the public base URL
          / issuer and allowed return URLs, generate a reverse-proxy snippet, and
          verify the domain is reachable. TLS and DNS are owned by your reverse
          proxy — this console does not provision certificates or DNS records.
        </p>
      </div>

      <Alert role="status" aria-live="polite">
        <InfoIcon />
        <AlertTitle>The base URL applies on a Kratos restart</AlertTitle>
        <AlertDescription>
          Saving the public base URL restarts Kratos only. The full set of
          self-service UI URLs is editable on the{" "}
          <Link
            href="/branding/ui-urls"
            className="text-primary hover:underline"
          >
            UI URLs &amp; Redirects
          </Link>{" "}
          page.
        </AlertDescription>
      </Alert>

      <ConfigSection
        section="ui-urls"
        schema={schema}
        defaults={defaults}
        title="Public base URL & allowed returns"
        description="The Kratos public base URL / issuer for your custom domain, plus the allowed return URLs. On save Kratos restarts."
        saveLabel="Save domain config"
      >
        {(form) => (
          <div className="space-y-4">
            <PointerText
              form={form}
              pointer={BASE_URL}
              label="Public base URL (issuer)"
              placeholder="https://accounts.your-domain.example/"
              description="The Kratos public base URL / issuer. Set this to your custom Account Experience domain."
            />
            <PointerStringList
              form={form}
              pointer={ALLOWED_RETURN}
              label="Allowed return URL"
              placeholder="https://your-app.example/after-login"
              description="The allowlist of URLs a flow may redirect back to."
            />
          </div>
        )}
      </ConfigSection>

      <ReverseProxySnippet />
      <ReachabilityCheck />
    </div>
  );
}

export default function CustomDomainsPage() {
  return (
    <FeatureGate flag="account_experience" title="Custom Domains">
      <CustomDomainsEditor />
    </FeatureGate>
  );
}
