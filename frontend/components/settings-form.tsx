"use client";

// FE-03 — the one reusable RHF + Zod SettingsForm every YAML config page
// (P7/P8/P9/P10) composes for per-section save.
//
// Design invariants (05-RESEARCH Pattern 5 + Pitfall 5, UI-SPEC §2/§3/§5):
//   - useForm<z.input<typeof schema>>({ resolver: zodResolver(schema),
//     mode:"onBlur" }) — typed with `z.input` so @hookform/resolvers 5.4 + Zod 4
//     resolve cleanly (Pitfall 5). Invalid input blocks submit (Zod messages
//     render inline via shadcn FormMessage — escaped text, never HTML).
//   - On submit: setStatus("restarting") → api(submitPath, {method:"PUT",
//     body}) through lib/api.ts (which attaches X-CSRF-Token, T-05-20). On
//     success, read the backend `status` field and reflect it in the banner
//     (applied → restarting → healthy). On ApiError(422), iterate fieldErrors
//     → form.setError(path, {type:"server", message}) so they render inline at
//     the offending field. On any other error → setStatus("failed").
//   - The status banner maps the Phase-4 config status machine to a shadcn
//     Alert variant (applied/restarting/healthy → neutral/info; failed →
//     destructive, "rolled back to last-known-good"). A transient success also
//     fires a sonner toast (UI-SPEC §3).
//   - Save is disabled while `!isDirty || isSubmitting`; Discard resets to the
//     last-saved values.

import * as React from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import {
  useForm,
  type DefaultValues,
  type FieldValues,
  type Path,
  type UseFormReturn,
} from "react-hook-form";
import { toast } from "sonner";
import {
  CheckCircle2Icon,
  CircleAlertIcon,
  InfoIcon,
  Loader2Icon,
} from "lucide-react";
import type { z, ZodType } from "zod";

/**
 * A Zod schema whose INPUT type is a RHF-compatible `FieldValues` object. The
 * SettingsForm types its `useForm` with `z.input` (Pitfall 5), so the schema
 * generic is constrained to guarantee that input is an object RHF can manage.
 */
type FieldSchema = ZodType<unknown, FieldValues>;

import { ApiError } from "@/lib/api";
import { api } from "@/lib/api";
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
import { Form } from "@/components/ui/form";

/**
 * The Phase-4 config status machine. The backend's PUT response carries one of
 * these in its `status` field; the submit lifecycle also drives it locally.
 */
export type ConfigStatus =
  | "idle"
  | "applied"
  | "restarting"
  | "healthy"
  | "failed";

type BannerSpec = {
  role: "status" | "alert";
  variant: "default" | "destructive";
  icon: React.ReactNode;
  title: string;
  description: string;
};

const BANNERS: Record<Exclude<ConfigStatus, "idle">, BannerSpec> = {
  applied: {
    role: "status",
    variant: "default",
    icon: <CheckCircle2Icon />,
    title: "Configuration applied",
    description: "Changes were written to the service configuration.",
  },
  restarting: {
    role: "status",
    variant: "default",
    icon: <Loader2Icon className="animate-spin" />,
    title: "Service restarting",
    description: "Applying changes and waiting for the service to come back healthy.",
  },
  healthy: {
    role: "status",
    variant: "default",
    icon: <CheckCircle2Icon className="text-green-600 dark:text-green-500" />,
    title: "Configuration healthy",
    description: "The service restarted cleanly and is healthy.",
  },
  failed: {
    role: "alert",
    variant: "destructive",
    icon: <CircleAlertIcon />,
    title: "Save failed",
    description:
      "The change could not be applied and was rolled back to last-known-good.",
  },
};

/** The shape the backend PUT response may carry. */
type ConfigSaveResponse = { status?: ConfigStatus } | undefined;

export type SettingsFormProps<TSchema extends FieldSchema> = {
  /** Zod schema for this section (mirrors the backend JSON-Schema). */
  schema: TSchema;
  /** Section title (card header). */
  title: string;
  /** One-line section description. */
  description?: string;
  /** Backend PUT target, e.g. `/api/config/{service}/{section}`. */
  submitPath: string;
  /** Initial / last-saved values. */
  defaultValues: DefaultValues<z.input<TSchema>>;
  /** Render-prop for the section's controls; receives the RHF form instance. */
  children: (
    form: UseFormReturn<z.input<TSchema>, unknown, z.output<TSchema>>,
  ) => React.ReactNode;
  /**
   * Optional override of the default submit (e.g. to transform values). When
   * omitted, the form PUTs the values to `submitPath` via lib/api.ts.
   */
  onSubmit?: (values: z.output<TSchema>) => Promise<ConfigSaveResponse>;
  /** Save button label (defaults to "Save"). */
  saveLabel?: string;
};

export function SettingsForm<TSchema extends FieldSchema>({
  schema,
  title,
  description,
  submitPath,
  defaultValues,
  children,
  onSubmit,
  saveLabel = "Save",
}: SettingsFormProps<TSchema>) {
  // @hookform/resolvers 5.4 + Zod 4: Zod distinguishes input vs output types, so
  // the form is parameterized with all three RHF generics — input (field state),
  // context (unused), and the resolver's transformed OUTPUT (Pitfall 5). This
  // makes `zodResolver(schema)` assignable without an `any` cast.
  const form = useForm<z.input<TSchema>, unknown, z.output<TSchema>>({
    resolver: zodResolver(schema),
    mode: "onBlur",
    defaultValues,
  });

  const [status, setStatus] = React.useState<ConfigStatus>("idle");

  const submit = form.handleSubmit(async (values) => {
    setStatus("restarting");
    // WR-01: PUT ONLY the fields the operator actually edited. The config pages
    // bind a FLAT pointer-keyed value object whose untouched fields fall back to
    // their schema default (`""` for a string, `[]` for an array). PUTting the
    // WHOLE `values` object would write those defaults over the on-disk values
    // the operator never touched — blanking every other email-template pointer
    // (the backend turns `""` into an empty `base64://` body) and 422-ing the
    // ui-urls save (an empty `""` violates `format:uri`). We mirror the Phase-8
    // CR-01 philosophy: merge the operator's edits over what is stored, never
    // blank an unspecified field. RHF's `dirtyFields` marks each changed key
    // (truthy: `true` for a scalar, an array of booleans/objects for an array
    // field), so the patch carries exactly the changed pointers. The custom
    // `onSubmit` override still receives the full validated output.
    const dirty = form.formState.dirtyFields as Record<string, unknown>;
    const valuesRecord = values as Record<string, unknown>;
    const patch = Object.fromEntries(
      Object.keys(valuesRecord).filter((k) => Boolean(dirty[k])).map((k) => [
        k,
        valuesRecord[k],
      ]),
    );
    try {
      const res = (await (onSubmit
        ? onSubmit(values)
        : api<ConfigSaveResponse>(submitPath, {
            method: "PUT",
            body: JSON.stringify(patch),
          }))) as ConfigSaveResponse;

      const next: ConfigStatus = res?.status ?? "healthy";
      setStatus(next);
      if (next === "healthy" || next === "applied") {
        // Reset the dirty baseline to the just-saved values (the validated
        // output doubles as the new pristine input snapshot).
        form.reset(values as unknown as DefaultValues<z.input<TSchema>>);
        toast.success(`${title} settings saved`);
      }
    } catch (e) {
      if (e instanceof ApiError && e.status === 422) {
        // Map the backend {path,message}[] to inline field errors. The status
        // stays out of the failed-banner path: validation, not a save failure.
        setStatus("idle");
        for (const { path, message } of e.fieldErrors) {
          form.setError(path as Path<z.input<TSchema>>, {
            type: "server",
            message,
          });
        }
        return;
      }
      setStatus("failed");
    }
  });

  function onDiscard() {
    form.reset(defaultValues);
    setStatus("idle");
  }

  const banner = status === "idle" ? null : BANNERS[status];
  const isSubmitting = form.formState.isSubmitting;
  const isDirty = form.formState.isDirty;

  return (
    <Card>
      <Form {...form}>
        <form onSubmit={submit} noValidate>
          <CardHeader>
            <CardTitle>{title}</CardTitle>
            {description ? (
              <CardDescription>{description}</CardDescription>
            ) : null}
          </CardHeader>

          <CardContent className="space-y-4 pt-4">
            {children(form)}

            {banner ? (
              <Alert
                role={banner.role}
                variant={banner.variant}
                aria-live={banner.role === "alert" ? "assertive" : "polite"}
              >
                {banner.role === "status" && status === "restarting" ? (
                  <InfoIcon />
                ) : (
                  banner.icon
                )}
                <AlertTitle>
                  {banner.title} ({status})
                </AlertTitle>
                <AlertDescription>{banner.description}</AlertDescription>
              </Alert>
            ) : null}
          </CardContent>

          <CardFooter className="mt-4 flex justify-end gap-2 border-t pt-4">
            <Button
              type="button"
              variant="outline"
              onClick={onDiscard}
              disabled={!isDirty || isSubmitting}
            >
              Discard
            </Button>
            <Button type="submit" disabled={!isDirty || isSubmitting}>
              {isSubmitting ? (
                <>
                  <Loader2Icon className="animate-spin" />
                  Saving…
                </>
              ) : (
                saveLabel
              )}
            </Button>
          </CardFooter>
        </form>
      </Form>
    </Card>
  );
}
