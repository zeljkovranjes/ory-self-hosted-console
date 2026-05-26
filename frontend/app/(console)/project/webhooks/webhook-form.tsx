"use client";

// HOOK-01/02 — the create/edit webhook form (11-UI-SPEC §A).
//
// RHF + Zod inside a Card, mirroring the Phase-8 OAuth2 client-form: a 422 from
// the backend maps to inline field errors via form.setError. The events
// multi-select is composed from ALREADY-VENDORED shadcn primitives only — a
// DropdownMenu checkbox list (DropdownMenuCheckboxItem) — never a third-party
// multiselect.
//
// The signing secret is WRITE-ONLY (T-11-18):
//   - create: the backend ALWAYS mints the secret and returns it ONCE; there is
//     no secret input on create (the operator does not choose it). The caller's
//     reveal block surfaces it once from the create response.
//   - edit: the update route NEVER touches the secret (it structurally cannot be
//     blanked); rotation is a separate explicit action. So the edit form has NO
//     secret field at all — only a read-only "Set / Not set" note + the
//     "leave blank to keep" discipline is moot because there is no field to type.
//
// SSRF (CRITICAL — anti-false-green, T-11-19): the Zod url() check is COSMETIC.
// The authoritative guard is backend-side. A create/edit 422 surfaces the reason
// VERBATIM in a destructive Alert (role="alert") AND inline at the url field via
// form.setError — a reject is NEVER collapsed into a success.
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
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import type { Webhook } from "./types";
import { WEBHOOK_EVENTS } from "./types";

type FormValues = {
  name: string;
  url: string;
  events: string[];
  enabled: boolean;
};

const formSchema = z.object({
  name: z.string().min(1, "Webhook name is required."),
  // url() is COSMETIC — the authoritative SSRF check is backend-side. We only
  // require an http(s) shape for fast local feedback; the backend re-validates
  // the RESOLVED IP and may still reject with a 422.
  url: z
    .string()
    .min(1, "URL is required.")
    .url("Enter a valid http(s) URL.")
    .refine(
      (u) => /^https?:\/\//i.test(u),
      "URL must start with http:// or https://.",
    ),
  events: z.array(z.string()).min(1, "Select at least one event."),
  enabled: z.boolean(),
});

export type WebhookFormProps = (
  | { mode: "create"; webhook?: undefined; onCreated: (secret: string, name: string) => void }
  | { mode: "edit"; webhook: Webhook; onUpdated?: () => void }
) & {
  /** Called when the operator cancels (closes the hosting dialog). */
  onCancel?: () => void;
};

export function WebhookForm(props: WebhookFormProps) {
  const { mode } = props;
  const router = useRouter();
  const webhook = mode === "edit" ? props.webhook : undefined;

  const defaultValues = React.useMemo<FormValues>(
    () => ({
      name: webhook?.name ?? "",
      url: webhook?.url ?? "",
      events: webhook?.events ?? [],
      enabled: webhook?.enabled ?? true,
    }),
    [webhook],
  );

  const form = useForm<FormValues>({
    resolver: zodResolver(formSchema) as unknown as Resolver<FormValues>,
    mode: "onBlur",
    defaultValues,
  });

  // The verbatim SSRF / save-failure banner (T-11-19 — never silent).
  const [formError, setFormError] = React.useState<string | null>(null);

  const events = form.watch("events");
  const enabled = form.watch("enabled");

  function toggleEvent(evt: string, checked: boolean) {
    const next = checked
      ? Array.from(new Set([...events, evt]))
      : events.filter((e) => e !== evt);
    form.setValue("events", next, { shouldDirty: true, shouldValidate: true });
  }

  const onSubmit = form.handleSubmit(async (values) => {
    setFormError(null);

    // The create/update routes (11-01) take name/url/events/enabled. The secret
    // is NEVER part of either body: it is minted server-side on create and only
    // changed via the explicit rotate route.
    const body = {
      name: values.name.trim(),
      url: values.url,
      events: values.events,
      enabled: values.enabled,
    };

    try {
      if (mode === "create") {
        // The create response carries the minted secret ONCE.
        const created = await api<{ secret?: string; name: string }>(
          "/api/webhooks",
          { method: "POST", body: JSON.stringify(body) },
        );
        toast.success("Webhook created");
        // Hand the one-time secret to the caller's reveal block.
        props.onCreated(created.secret ?? "", created.name ?? body.name);
      } else {
        await api(`/api/webhooks/${webhook!.id}`, {
          method: "PUT",
          body: JSON.stringify(body),
        });
        toast.success("Webhook saved");
        if (props.onUpdated) props.onUpdated();
      }
    } catch (e) {
      if (e instanceof ApiError && e.status === 422) {
        // 422 with typed fields → inline. The SSRF reject lands on the `url`
        // field; surface it both inline AND in the destructive banner verbatim.
        let surfaced = false;
        for (const { path, message } of e.fieldErrors) {
          form.setError(path as never, { type: "server", message });
          if (path === "url" || path === "") {
            setFormError(message);
            surfaced = true;
          }
        }
        if (!surfaced) {
          setFormError(
            e.fieldErrors[0]?.message ?? "The webhook was rejected.",
          );
        }
        return;
      }
      if (e instanceof ApiError && e.status === 400) {
        // BadRequest (e.g. the SSRF validate_url reject, or a missing field) is
        // returned as a 400 with a plain message in some paths — surface it.
        setFormError(
          "The webhook URL was rejected. This URL resolves to a private, loopback, link-local, or cloud-metadata address and is not allowed.",
        );
        form.setError("url", {
          type: "server",
          message:
            "This URL resolves to a private, loopback, link-local, or cloud-metadata address and is not allowed.",
        });
        return;
      }
      const status = e instanceof ApiError ? ` (${e.status})` : "";
      setFormError(`Could not save the webhook${status}.`);
      toast.error(`Failed to save webhook${status}`);
    }
  });

  return (
    <Card>
      <form onSubmit={onSubmit} noValidate>
        <CardHeader>
          <CardTitle>
            {mode === "create" ? "Create webhook" : "Edit webhook"}
          </CardTitle>
        </CardHeader>

        <CardContent className="space-y-5 pt-4">
          <div className="grid gap-2">
            <Label htmlFor="name">Name</Label>
            <Input id="name" {...form.register("name")} />
            <FieldError msg={form.formState.errors.name?.message} />
          </div>

          <div className="grid gap-2">
            <Label htmlFor="url">URL</Label>
            <Input
              id="url"
              type="url"
              placeholder="https://hooks.example.com/ory"
              className="font-mono text-xs"
              {...form.register("url")}
            />
            <p className="text-muted-foreground text-sm">
              The console POSTs signed deliveries here. Private, loopback,
              link-local, and cloud-metadata addresses are rejected.
            </p>
            <FieldError msg={form.formState.errors.url?.message} />
          </div>

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
                {WEBHOOK_EVENTS.map((evt) => (
                  <DropdownMenuCheckboxItem
                    key={evt}
                    checked={events.includes(evt)}
                    // Keep the menu open while toggling multiple events.
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
              Select which events trigger this webhook.
            </p>
            <FieldError msg={form.formState.errors.events?.message} />
          </div>

          <div className="flex items-center justify-between rounded-md border p-4">
            <div className="space-y-0.5">
              <Label htmlFor="enabled">Enabled</Label>
              <p className="text-muted-foreground text-sm">
                Disabled webhooks are not delivered.
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

          {mode === "edit" ? (
            <div className="grid gap-2">
              <Label>Signing secret</Label>
              <div className="flex items-center gap-2">
                {webhook!.secret_set ? (
                  <Badge variant="secondary">Set</Badge>
                ) : (
                  <Badge variant="outline" className="text-muted-foreground">
                    Not set
                  </Badge>
                )}
                <span className="text-muted-foreground text-sm">
                  Write-only. The secret is never displayed — rotate it from the
                  webhooks list to mint a new one.
                </span>
              </div>
            </div>
          ) : (
            <p className="text-muted-foreground text-sm">
              A signing secret is generated automatically and shown once after
              you create the webhook. It cannot be retrieved again.
            </p>
          )}

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
                : router.push("/project/webhooks")
            }
          >
            Cancel
          </Button>
          <Button type="submit" disabled={form.formState.isSubmitting}>
            {mode === "create" ? "Create webhook" : "Save webhook"}
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
