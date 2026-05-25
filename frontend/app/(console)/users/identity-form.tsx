"use client";

// IDENT-02 — the schema-driven create/edit identity form (UI-SPEC §3).
//
// On mount it fetches the ACTIVE identity schema (GET /api/kratos/identity-schema)
// and derives the traits fields + a matching Zod schema via buildTraitsForm
// (Pattern 6 — bounded, traits-only). It then renders an RHF + Zod form:
//
//   - traits: text/email/switch/select/number/raw-JSON controls per descriptor
//   - metadata_public / metadata_admin: Monaco JSON editors; an EMPTY/blank
//     editor OMITS the key (never sends null — 06-RESEARCH Pitfall 4); invalid
//     JSON is a form error
//   - create: POST /api/kratos/identities with {schema_id, traits, metadata_*?,
//     credentials?} (optional cleartext password -> credentials.password.config)
//   - edit: PUT /api/kratos/identities/{id} with a REQUIRED `state` select
//     (defaulting to the loaded identity's state — the backend PUT rejects a body
//     without state)
//   - a backend 422 {path,message}[] maps to inline field errors via setError
//
// All network access is through lib/api.ts (sole egress; CSRF on mutations).

import * as React from "react";
import { useRouter } from "next/navigation";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm, type Resolver } from "react-hook-form";
import { useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { z } from "zod";

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
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { MonacoEditor } from "@/components/monaco-editor";
import { buildTraitsForm, type TraitField } from "@/lib/identity-schema-form";
import { type Identity } from "./identity-types";

type FormValues = Record<string, unknown>;

export type IdentityFormProps =
  | { mode: "create"; identity?: undefined }
  | { mode: "edit"; identity: Identity };

/** Default value for a trait field given the (optional) loaded identity value. */
function defaultFor(field: TraitField, current: unknown): unknown {
  if (current !== undefined && current !== null) {
    if (field.input === "json") return JSON.stringify(current);
    return current;
  }
  if (field.input === "switch") return false;
  return "";
}

/** Parse a Monaco JSON editor's text. Blank -> omit; invalid -> throw a marker. */
function parseMetadata(raw: unknown): { omit: boolean; value?: unknown } {
  if (typeof raw !== "string" || raw.trim() === "") return { omit: true };
  return { omit: false, value: JSON.parse(raw) };
}

export function IdentityForm(props: IdentityFormProps) {
  const { mode } = props;
  const router = useRouter();

  const schemaQuery = useQuery({
    queryKey: ["identity-schema"],
    queryFn: () => api<unknown>("/api/kratos/identity-schema"),
  });

  if (schemaQuery.isPending) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (schemaQuery.isError || !schemaQuery.data) {
    return (
      <Alert variant="destructive">
        <AlertTitle>Failed to load the identity schema</AlertTitle>
        <AlertDescription>
          The active identity schema could not be loaded, so the form cannot be
          built. Try again later.
        </AlertDescription>
      </Alert>
    );
  }

  return (
    <IdentityFormInner
      {...props}
      schema={schemaQuery.data}
      router={router}
      key={mode}
    />
  );
}

function IdentityFormInner({
  mode,
  identity,
  schema,
  router,
}: IdentityFormProps & {
  schema: unknown;
  router: ReturnType<typeof useRouter>;
}) {
  const { fields, zodSchema } = React.useMemo(
    () => buildTraitsForm(schema),
    [schema],
  );

  const schemaId =
    (typeof (schema as { $id?: unknown })?.$id === "string"
      ? ((schema as { $id?: string }).$id as string)
      : undefined) ??
    identity?.schema_id ??
    "default";

  // Compose the full form Zod: traits + metadata strings + (edit) state +
  // (create) optional password. Metadata/password JSON is validated on submit.
  const formSchema = React.useMemo(() => {
    const base: Record<string, z.ZodTypeAny> = {
      __metadata_public: z.string().optional(),
      __metadata_admin: z.string().optional(),
    };
    if (mode === "edit") base.__state = z.string().min(1, "State is required");
    if (mode === "create") base.__password = z.string().optional();
    return (zodSchema as unknown as z.ZodObject<z.ZodRawShape>).extend(base);
  }, [zodSchema, mode]);

  const defaultValues = React.useMemo<FormValues>(() => {
    const vals: FormValues = {};
    for (const f of fields) {
      vals[f.name] = defaultFor(f, identity?.traits?.[f.name]);
    }
    vals.__metadata_public = identity?.metadata_public
      ? JSON.stringify(identity.metadata_public, null, 2)
      : "";
    vals.__metadata_admin = identity?.metadata_admin
      ? JSON.stringify(identity.metadata_admin, null, 2)
      : "";
    if (mode === "edit") vals.__state = identity?.state ?? "active";
    if (mode === "create") vals.__password = "";
    return vals;
  }, [fields, identity, mode]);

  const form = useForm<FormValues>({
    resolver: zodResolver(formSchema) as unknown as Resolver<FormValues>,
    mode: "onBlur",
    defaultValues,
  });

  const [formError, setFormError] = React.useState<string | null>(null);

  const onSubmit = form.handleSubmit(async (values) => {
    setFormError(null);

    // Split traits from the synthetic __ control fields.
    const traits: Record<string, unknown> = {};
    for (const f of fields) {
      let v = values[f.name];
      if (f.input === "json") {
        if (typeof v === "string" && v.trim() !== "") {
          try {
            v = JSON.parse(v);
          } catch {
            form.setError(f.name, {
              type: "validate",
              message: "Invalid JSON",
            });
            return;
          }
        } else {
          continue;
        }
      }
      if (v !== "" && v !== undefined) traits[f.name] = v;
    }

    // Metadata editors: blank -> omit; invalid JSON -> form error.
    let metaPublic: { omit: boolean; value?: unknown };
    let metaAdmin: { omit: boolean; value?: unknown };
    try {
      metaPublic = parseMetadata(values.__metadata_public);
    } catch {
      setFormError("Public metadata is not valid JSON.");
      return;
    }
    try {
      metaAdmin = parseMetadata(values.__metadata_admin);
    } catch {
      setFormError("Admin metadata is not valid JSON.");
      return;
    }

    const body: Record<string, unknown> = { schema_id: schemaId, traits };
    if (!metaPublic.omit) body.metadata_public = metaPublic.value;
    if (!metaAdmin.omit) body.metadata_admin = metaAdmin.value;

    try {
      if (mode === "create") {
        const password = values.__password;
        if (typeof password === "string" && password !== "") {
          body.credentials = { password: { config: { password } } };
        }
        await api("/api/kratos/identities", {
          method: "POST",
          body: JSON.stringify(body),
        });
        toast.success("Identity created");
        router.push("/users");
      } else {
        body.state = values.__state;
        await api(`/api/kratos/identities/${identity!.id}`, {
          method: "PUT",
          body: JSON.stringify(body),
        });
        toast.success("Identity updated");
        router.push(`/users/${identity!.id}`);
      }
      router.refresh();
    } catch (e) {
      if (e instanceof ApiError && e.status === 422) {
        for (const { path, message } of e.fieldErrors) {
          // Map backend `traits.email` -> the RHF trait field `email`.
          const field = path.replace(/^traits\./, "");
          form.setError(field as never, { type: "server", message });
        }
        return;
      }
      const status = e instanceof ApiError ? ` (${e.status})` : "";
      setFormError(`Could not save the identity${status}.`);
      toast.error(`Failed to save identity${status}`);
    }
  });

  const errors = form.formState.errors;

  return (
    <Card>
      <form onSubmit={onSubmit} noValidate>
        <CardHeader>
          <CardTitle>
            {mode === "create" ? "Create identity" : "Edit identity"}
          </CardTitle>
        </CardHeader>

        <CardContent className="space-y-5 pt-4">
          {fields.map((field) => (
            <TraitControl
              key={field.name}
              field={field}
              form={form}
              error={errors[field.name]?.message as string | undefined}
            />
          ))}

          {mode === "edit" ? (
            <div className="grid gap-2">
              <Label htmlFor="identity-state">State</Label>
              <Select
                value={(form.watch("__state") as string) ?? "active"}
                onValueChange={(v) =>
                  form.setValue("__state", v, { shouldDirty: true })
                }
              >
                <SelectTrigger id="identity-state" aria-label="State">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="active">active</SelectItem>
                  <SelectItem value="inactive">inactive</SelectItem>
                </SelectContent>
              </Select>
            </div>
          ) : null}

          {mode === "create" ? (
            <div className="grid gap-2">
              <Label htmlFor="identity-password">
                Password (optional)
              </Label>
              <Input
                id="identity-password"
                type="password"
                autoComplete="new-password"
                {...form.register("__password")}
              />
              <p className="text-sm text-muted-foreground">
                Sets an initial password credential. Leave blank to create the
                identity without a password.
              </p>
            </div>
          ) : null}

          <div className="grid gap-2">
            <MonacoEditor
              language="json"
              ariaLabel="Public metadata (JSON)"
              height={160}
              value={(form.watch("__metadata_public") as string) ?? ""}
              onChange={(v) =>
                form.setValue("__metadata_public", v, { shouldDirty: true })
              }
            />
            <p className="text-sm text-muted-foreground">
              Public metadata — leave blank to omit.
            </p>
          </div>

          <div className="grid gap-2">
            <MonacoEditor
              language="json"
              ariaLabel="Admin metadata (JSON, admin-only)"
              height={160}
              value={(form.watch("__metadata_admin") as string) ?? ""}
              onChange={(v) =>
                form.setValue("__metadata_admin", v, { shouldDirty: true })
              }
            />
            <p className="text-sm text-muted-foreground">
              Admin-only metadata — sensitive; leave blank to omit.
            </p>
          </div>

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
            onClick={() => router.push("/users")}
          >
            Cancel
          </Button>
          <Button type="submit" disabled={form.formState.isSubmitting}>
            {mode === "create" ? "Create identity" : "Save changes"}
          </Button>
        </CardFooter>
      </form>
    </Card>
  );
}

function TraitControl({
  field,
  form,
  error,
}: {
  field: TraitField;
  form: ReturnType<typeof useForm<FormValues>>;
  error?: string;
}) {
  const id = `trait-${field.name}`;
  const label = (
    <Label htmlFor={id}>
      {field.label}
      {field.required ? <span className="text-destructive"> *</span> : null}
    </Label>
  );

  let control: React.ReactNode;
  switch (field.input) {
    case "switch":
      control = (
        <Switch
          id={id}
          aria-label={field.label}
          checked={Boolean(form.watch(field.name))}
          onCheckedChange={(v) =>
            form.setValue(field.name, v, { shouldDirty: true })
          }
        />
      );
      break;
    case "select":
      control = (
        <Select
          value={(form.watch(field.name) as string) ?? ""}
          onValueChange={(v) =>
            form.setValue(field.name, v, { shouldDirty: true })
          }
        >
          <SelectTrigger id={id} aria-label={field.label}>
            <SelectValue placeholder="Select…" />
          </SelectTrigger>
          <SelectContent>
            {(field.options ?? []).map((opt) => (
              <SelectItem key={opt} value={opt}>
                {opt}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      );
      break;
    case "json":
      control = (
        <Input
          id={id}
          aria-label={field.label}
          placeholder='{"…": "…"}'
          {...form.register(field.name)}
        />
      );
      break;
    case "number":
      control = (
        <Input
          id={id}
          type="number"
          aria-label={field.label}
          {...form.register(field.name, { valueAsNumber: true })}
        />
      );
      break;
    case "email":
    case "text":
    default:
      control = (
        <Input
          id={id}
          type={field.input === "email" ? "email" : "text"}
          aria-label={field.label}
          {...form.register(field.name)}
        />
      );
      break;
  }

  return (
    <div className="grid gap-2">
      {label}
      {control}
      {error ? <p className="text-sm text-destructive">{error}</p> : null}
    </div>
  );
}
