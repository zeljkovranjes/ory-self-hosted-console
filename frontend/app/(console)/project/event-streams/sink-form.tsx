"use client";

// EVT-01/03 — the create/edit event-sink form (cloned from the Phase-11
// WebhookForm). RHF + Zod inside a Card. A `kind` select conditionally renders the
// target fields:
//   - webhook: an http(s) URL (the backend MINTS the HMAC secret; no secret input).
//   - nats:    broker URL (nats://host:port) + subject + optional user/credential
//              + TLS toggle.
//   - kafka:   brokers (host:port) + topic + optional SASL username/password + TLS.
// The events multi-select is composed from ALREADY-VENDORED shadcn primitives only
// (a DropdownMenu checkbox list) — never a third-party multiselect.
//
// Credential discipline (T-17-01):
//   - webhook create: the backend mints the secret and returns it ONCE; there is
//     NO secret input on create.
//   - broker create: the operator-supplied credential is write-only (sent on
//     create, never echoed back).
//   - edit: the update route NEVER touches the secret (it structurally cannot be
//     blanked). The form shows only a read-only "Set / Not set" note; the secret
//     is rotated from the list, broker creds re-entered explicitly.
//
// SSRF (CRITICAL — anti-false-green, T-17-08): the Zod shape checks are COSMETIC.
// The authoritative guard is backend-side. A create/edit 422/400 surfaces the
// reason VERBATIM in a destructive Alert (role="alert") AND inline at the target
// field via form.setError — a reject is NEVER collapsed into a success.
//
// All egress via @/lib/api (attaches X-CSRF-Token on mutations).

import * as React from "react";
import { useRouter } from "next/navigation";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm, type Resolver } from "react-hook-form";
import { toast } from "sonner";
import { z } from "zod";
import { ChevronsUpDown } from "lucide-react";

import { api, ApiError } from "@/lib/api";
import {
  Card,
  CardContent,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import type { EventSink, SinkKind } from "./types";
import { SINK_EVENTS, SINK_KINDS, SINK_KIND_LABELS } from "./types";

type FormValues = {
  name: string;
  kind: SinkKind;
  target: string;
  subject: string;
  events: string[];
  /** Broker credential (NATS creds/token / Kafka SASL password). Webhook ignores it. */
  secret: string;
  sasl_username: string;
  tls: boolean;
  enabled: boolean;
};

const formSchema = z
  .object({
    name: z.string().min(1, "Sink name is required."),
    kind: z.enum(SINK_KINDS),
    // target shape checks are COSMETIC — the authoritative SSRF/shape check is
    // backend-side. We only require a non-empty value here for fast feedback.
    target: z.string().min(1, "Target is required."),
    subject: z.string(),
    events: z.array(z.string()).min(1, "Select at least one event."),
    secret: z.string(),
    sasl_username: z.string(),
    tls: z.boolean(),
    enabled: z.boolean(),
  })
  .superRefine((v, ctx) => {
    if (v.kind === "webhook") {
      if (!/^https?:\/\//i.test(v.target)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["target"],
          message: "Webhook URL must start with http:// or https://.",
        });
      }
    } else {
      // nats/kafka — require a host:port broker address + a subject/topic.
      if (!v.subject.trim()) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["subject"],
          message:
            v.kind === "nats"
              ? "A NATS subject is required."
              : "A Kafka topic is required.",
        });
      }
    }
  });

export type SinkFormProps = (
  | { mode: "create"; sink?: undefined; onCreated: (secret: string, name: string) => void }
  | { mode: "edit"; sink: EventSink; onUpdated?: () => void }
) & {
  /** Called when the operator cancels (closes the hosting dialog). */
  onCancel?: () => void;
};

export function SinkForm(props: SinkFormProps) {
  const { mode } = props;
  const router = useRouter();
  const sink = mode === "edit" ? props.sink : undefined;

  const defaultValues = React.useMemo<FormValues>(
    () => ({
      name: sink?.name ?? "",
      kind: (sink?.kind as SinkKind) ?? "webhook",
      target: sink?.target ?? "",
      subject: sink?.subject ?? "",
      events: sink?.events ?? [],
      secret: "",
      sasl_username: "",
      tls: sink?.tls ?? false,
      enabled: sink?.enabled ?? true,
    }),
    [sink],
  );

  const form = useForm<FormValues>({
    resolver: zodResolver(formSchema) as unknown as Resolver<FormValues>,
    mode: "onBlur",
    defaultValues,
  });

  // The verbatim SSRF / save-failure banner (T-17-08 — never silent).
  const [formError, setFormError] = React.useState<string | null>(null);

  const kind = form.watch("kind");
  const events = form.watch("events");
  const enabled = form.watch("enabled");
  const tls = form.watch("tls");
  const isBroker = kind === "nats" || kind === "kafka";

  function toggleEvent(evt: string, checked: boolean) {
    const next = checked
      ? Array.from(new Set([...events, evt]))
      : events.filter((e) => e !== evt);
    form.setValue("events", next, { shouldDirty: true, shouldValidate: true });
  }

  const onSubmit = form.handleSubmit(async (values) => {
    setFormError(null);

    try {
      if (mode === "create") {
        // The create body carries kind + (broker) credential. For webhook the
        // backend mints the secret and ignores any supplied `secret`.
        const body: Record<string, unknown> = {
          name: values.name.trim(),
          kind: values.kind,
          target: values.target,
          events: values.events,
          enabled: values.enabled,
        };
        if (values.kind === "nats" || values.kind === "kafka") {
          body.subject = values.subject.trim();
          body.tls = values.tls;
          if (values.secret) body.secret = values.secret;
          if (values.sasl_username) body.sasl_username = values.sasl_username.trim();
        }
        // The create response carries the minted webhook secret ONCE.
        const created = await api<{ secret?: string; name: string }>(
          "/api/event-sinks",
          { method: "POST", body: JSON.stringify(body) },
        );
        toast.success("Sink created");
        props.onCreated(created.secret ?? "", created.name ?? body.name as string);
      } else {
        // The update body never carries kind or the webhook secret. Broker
        // username/tls remain editable; the password is rotated separately.
        const body: Record<string, unknown> = {
          name: values.name.trim(),
          target: values.target,
          events: values.events,
          enabled: values.enabled,
        };
        if (isBroker) {
          body.subject = values.subject.trim();
          body.tls = values.tls;
          if (values.sasl_username) body.sasl_username = values.sasl_username.trim();
        }
        await api(`/api/event-sinks/${sink!.id}`, {
          method: "PUT",
          body: JSON.stringify(body),
        });
        toast.success("Sink saved");
        if (props.onUpdated) props.onUpdated();
      }
    } catch (e) {
      if (e instanceof ApiError && e.status === 422) {
        // 422 with typed fields → inline. The SSRF reject lands on the `target`
        // field; surface it both inline AND in the destructive banner verbatim.
        let surfaced = false;
        for (const { path, message } of e.fieldErrors) {
          const p = path === "url" ? "target" : path;
          form.setError(p as never, { type: "server", message });
          if (p === "target" || p === "") {
            setFormError(message);
            surfaced = true;
          }
        }
        if (!surfaced) {
          setFormError(e.fieldErrors[0]?.message ?? "The sink was rejected.");
        }
        return;
      }
      if (e instanceof ApiError && e.status === 400) {
        // BadRequest (the SSRF validate_url reject / a broker-shape reject) — the
        // message is plain; surface it verbatim on the target field + banner.
        const msg =
          "The sink target was rejected. It resolves to a private, loopback, link-local, or cloud-metadata address, or is not a valid target for this sink kind.";
        setFormError(msg);
        form.setError("target", { type: "server", message: msg });
        return;
      }
      const status = e instanceof ApiError ? ` (${e.status})` : "";
      setFormError(`Could not save the sink${status}.`);
      toast.error(`Failed to save sink${status}`);
    }
  });

  return (
    <Card>
      <form onSubmit={onSubmit} noValidate>
        <CardHeader>
          <CardTitle>
            {mode === "create" ? "Create event sink" : "Edit event sink"}
          </CardTitle>
        </CardHeader>

        <CardContent className="space-y-5 pt-4">
          <div className="grid gap-2">
            <Label htmlFor="name">Name</Label>
            <Input id="name" {...form.register("name")} />
            <FieldError msg={form.formState.errors.name?.message} />
          </div>

          {/* Kind is chosen on create and immutable on edit. */}
          <div className="grid gap-2">
            <Label htmlFor="kind">Kind</Label>
            {mode === "create" ? (
              <Select
                value={kind}
                onValueChange={(v) =>
                  form.setValue("kind", v as SinkKind, {
                    shouldDirty: true,
                    shouldValidate: true,
                  })
                }
              >
                <SelectTrigger id="kind" aria-label="Sink kind">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SINK_KINDS.map((k) => (
                    <SelectItem key={k} value={k}>
                      {SINK_KIND_LABELS[k]}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            ) : (
              <div>
                <Badge variant="outline">{SINK_KIND_LABELS[kind] ?? kind}</Badge>
                <p className="text-muted-foreground text-sm">
                  The sink kind cannot be changed after creation.
                </p>
              </div>
            )}
          </div>

          {/* Target — labeled per kind. */}
          <div className="grid gap-2">
            <Label htmlFor="target">
              {kind === "webhook"
                ? "URL"
                : kind === "nats"
                  ? "Broker URL"
                  : "Brokers"}
            </Label>
            <Input
              id="target"
              placeholder={
                kind === "webhook"
                  ? "https://hooks.example.com/ory"
                  : kind === "nats"
                    ? "nats://broker.example.com:4222"
                    : "broker.example.com:9092"
              }
              className="font-mono text-xs"
              {...form.register("target")}
            />
            <p className="text-muted-foreground text-sm">
              {kind === "webhook"
                ? "The console POSTs signed deliveries here. Private, loopback, link-local, and cloud-metadata addresses are rejected."
                : "host:port of the broker. Private, loopback, link-local, and cloud-metadata addresses are rejected at delivery."}
            </p>
            <FieldError msg={form.formState.errors.target?.message} />
          </div>

          {/* Subject / Topic — broker kinds only. */}
          {isBroker ? (
            <div className="grid gap-2">
              <Label htmlFor="subject">
                {kind === "nats" ? "Subject" : "Topic"}
              </Label>
              <Input
                id="subject"
                className="font-mono text-xs"
                placeholder={kind === "nats" ? "events.console" : "ory-console-events"}
                {...form.register("subject")}
              />
              <FieldError msg={form.formState.errors.subject?.message} />
            </div>
          ) : null}

          {/* Broker credentials — write-only. */}
          {isBroker ? (
            <div className="grid gap-4 rounded-md border p-4">
              <div className="grid gap-2">
                <Label htmlFor="sasl_username">
                  {kind === "nats" ? "Username (optional)" : "SASL username (optional)"}
                </Label>
                <Input
                  id="sasl_username"
                  autoComplete="off"
                  {...form.register("sasl_username")}
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="secret">
                  {kind === "nats"
                    ? "Credential / token (optional)"
                    : "SASL password (optional)"}
                </Label>
                <Input
                  id="secret"
                  type="password"
                  autoComplete="new-password"
                  placeholder={
                    mode === "edit" && sink?.secret_set ? "•••••• (unchanged)" : ""
                  }
                  {...form.register("secret")}
                />
                <p className="text-muted-foreground text-sm">
                  Write-only. The stored value is never displayed. On edit, leave
                  blank to keep the current credential, or rotate it from the list.
                </p>
              </div>
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label htmlFor="tls">TLS</Label>
                  <p className="text-muted-foreground text-sm">
                    Request a TLS connection to the broker.
                  </p>
                </div>
                <Switch
                  id="tls"
                  checked={tls}
                  onCheckedChange={(v) =>
                    form.setValue("tls", v === true, { shouldDirty: true })
                  }
                  aria-label="TLS"
                />
              </div>
            </div>
          ) : null}

          {/* Events multi-select (shared with the webhook surface). */}
          <div className="grid gap-2">
            <Label>Events</Label>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  type="button"
                  variant="outline"
                  className="justify-between font-normal"
                  aria-label="Select events"
                >
                  {events.length
                    ? `${events.length} selected`
                    : "Select events"}
                  <ChevronsUpDown className="opacity-50" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="start" className="w-72">
                <DropdownMenuLabel>Trigger events</DropdownMenuLabel>
                <DropdownMenuSeparator />
                {SINK_EVENTS.map((evt) => (
                  <DropdownMenuCheckboxItem
                    key={evt}
                    checked={events.includes(evt)}
                    onSelect={(e) => e.preventDefault()}
                    onCheckedChange={(c) => toggleEvent(evt, c === true)}
                    className="font-mono text-xs"
                  >
                    {evt}
                  </DropdownMenuCheckboxItem>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>
            {events.length ? (
              <div className="flex flex-wrap gap-1 pt-1">
                {events.map((evt) => (
                  <Badge
                    key={evt}
                    variant="secondary"
                    className="font-mono text-xs"
                  >
                    {evt}
                    <button
                      type="button"
                      aria-label={`Remove ${evt}`}
                      className="ml-1 text-muted-foreground hover:text-foreground"
                      onClick={() => toggleEvent(evt, false)}
                    >
                      ×
                    </button>
                  </Badge>
                ))}
              </div>
            ) : null}
            <p className="text-muted-foreground text-sm">
              Select which events stream to this sink.
            </p>
            <FieldError msg={form.formState.errors.events?.message} />
          </div>

          <div className="flex items-center justify-between rounded-md border p-4">
            <div className="space-y-0.5">
              <Label htmlFor="enabled">Enabled</Label>
              <p className="text-muted-foreground text-sm">
                Disabled sinks stream nothing (their cursor stays frozen).
              </p>
            </div>
            <Switch
              id="enabled"
              checked={enabled}
              onCheckedChange={(v) =>
                form.setValue("enabled", v === true, { shouldDirty: true })
              }
              aria-label="Enabled"
            />
          </div>

          {/* Webhook signing secret note (write-only; minted server-side). */}
          {kind === "webhook" ? (
            mode === "edit" ? (
              <div className="grid gap-2">
                <Label>Signing secret</Label>
                <div className="flex items-center gap-2">
                  {sink!.secret_set ? (
                    <Badge variant="secondary">Set</Badge>
                  ) : (
                    <Badge variant="outline" className="text-muted-foreground">
                      Not set
                    </Badge>
                  )}
                  <span className="text-muted-foreground text-sm">
                    Write-only. The secret is never displayed — rotate it from the
                    sinks list to mint a new one.
                  </span>
                </div>
              </div>
            ) : (
              <p className="text-muted-foreground text-sm">
                A signing secret is generated automatically and shown once after
                you create the sink. It cannot be retrieved again.
              </p>
            )
          ) : null}

          {formError ? (
            <Alert variant="destructive" role="alert">
              <AlertTitle>Save failed</AlertTitle>
              <AlertDescription>{formError}</AlertDescription>
            </Alert>
          ) : null}
        </CardContent>

        <CardFooter className="mt-4 flex justify-end gap-2 border-t pt-4">
          <Button
            type="button"
            variant="outline"
            onClick={() =>
              props.onCancel
                ? props.onCancel()
                : router.push("/project/event-streams")
            }
          >
            Cancel
          </Button>
          <Button type="submit" disabled={form.formState.isSubmitting}>
            {mode === "create" ? "Create sink" : "Save sink"}
          </Button>
        </CardFooter>
      </form>
    </Card>
  );
}

function FieldError({ msg }: { msg?: string }) {
  if (!msg) return null;
  return (
    <p className="text-destructive text-sm" role="alert">
      {msg}
    </p>
  );
}
