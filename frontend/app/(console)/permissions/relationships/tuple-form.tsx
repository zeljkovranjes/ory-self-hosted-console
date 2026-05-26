"use client";

// PERM-02 — the create relation-tuple form (09-UI-SPEC §A).
//
// RHF + Zod inside a Card, mirroring the OAuth2 client-form: a 422 from the
// backend maps to inline field errors via form.setError. The headline contract
// is the subject XOR (T-9-fe-xor): a tuple's subject is EITHER a direct
// subject_id OR a complete subject_set (namespace:object#relation), never both
// and never neither — enforced client-side by a Zod `refine` mirroring the
// backend build_create_body guard. On success we invalidate the relationships
// query + toast and call onCreated.
//
// All egress via @/lib/api (attaches X-CSRF-Token on the POST). No Ory host.

import * as React from "react";
import { useQueryClient } from "@tanstack/react-query";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm, type Resolver } from "react-hook-form";
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
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

// The create body the backend POST /api/keto/relationships expects: namespace,
// object, relation, and EITHER subject_id OR subject_set (mutually exclusive).
export type CreateTupleBody = {
  namespace: string;
  object: string;
  relation: string;
  subject_id?: string;
  subject_set?: { namespace: string; object: string; relation: string };
};

type FormValues = {
  namespace: string;
  object: string;
  relation: string;
  subject_id: string;
  subject_set_namespace: string;
  subject_set_object: string;
  subject_set_relation: string;
};

// The subject XOR (T-9-fe-xor): exactly one of a non-blank subject_id OR a
// COMPLETE subject_set (all three fields). Mirrors the backend guard so a bad
// subject is caught before the network call; the error surfaces on subject_id.
const formSchema = z
  .object({
    namespace: z.string().trim().min(1, "Namespace is required"),
    object: z.string().trim().min(1, "Object is required"),
    relation: z.string().trim().min(1, "Relation is required"),
    subject_id: z.string().optional().default(""),
    subject_set_namespace: z.string().optional().default(""),
    subject_set_object: z.string().optional().default(""),
    subject_set_relation: z.string().optional().default(""),
  })
  .superRefine((v, ctx) => {
    const hasId = v.subject_id.trim().length > 0;
    const ssFields = [
      v.subject_set_namespace.trim(),
      v.subject_set_object.trim(),
      v.subject_set_relation.trim(),
    ];
    const ssAny = ssFields.some((s) => s.length > 0);
    const ssAll = ssFields.every((s) => s.length > 0);

    if (hasId && ssAny) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["subject_id"],
        message:
          "Provide exactly one of subject ID or subject set, not both.",
      });
      return;
    }
    if (!hasId && !ssAny) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["subject_id"],
        message:
          "A subject is required: provide a subject ID or a complete subject set.",
      });
      return;
    }
    if (!hasId && ssAny && !ssAll) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["subject_set_relation"],
        message:
          "A subject set needs all three of namespace, object, and relation.",
      });
    }
  });

export type TupleFormProps = {
  onCreated?: () => void;
  onCancel?: () => void;
};

export function TupleForm({ onCreated, onCancel }: TupleFormProps) {
  const queryClient = useQueryClient();

  const form = useForm<FormValues>({
    resolver: zodResolver(formSchema) as unknown as Resolver<FormValues>,
    mode: "onBlur",
    defaultValues: {
      namespace: "",
      object: "",
      relation: "",
      subject_id: "",
      subject_set_namespace: "",
      subject_set_object: "",
      subject_set_relation: "",
    },
  });

  const [formError, setFormError] = React.useState<string | null>(null);

  const onSubmit = form.handleSubmit(async (values) => {
    setFormError(null);

    const body: CreateTupleBody = {
      namespace: values.namespace.trim(),
      object: values.object.trim(),
      relation: values.relation.trim(),
    };
    const id = values.subject_id.trim();
    if (id) {
      body.subject_id = id;
    } else {
      body.subject_set = {
        namespace: values.subject_set_namespace.trim(),
        object: values.subject_set_object.trim(),
        relation: values.subject_set_relation.trim(),
      };
    }

    try {
      await api("/api/keto/relationships", {
        method: "POST",
        body: JSON.stringify(body),
      });
      await queryClient.invalidateQueries({ queryKey: ["keto-relationships"] });
      toast.success("Relationship created");
      onCreated?.();
    } catch (e) {
      if (e instanceof ApiError && e.status === 422) {
        for (const { path, message } of e.fieldErrors) {
          // Backend FieldError paths are JSON pointers ("/subject",
          // "/namespace", …). Map the leaf to the closest form field; an
          // unrecognised subject error lands on subject_id.
          const leaf = path.replace(/^\//, "");
          const field =
            leaf === "subject" || leaf === "subject_set"
              ? "subject_id"
              : (leaf as keyof FormValues);
          form.setError(field as never, { type: "server", message });
        }
        return;
      }
      const status = e instanceof ApiError ? ` (${e.status})` : "";
      setFormError(`Could not create the relationship${status}.`);
      toast.error(`Failed to create relationship${status}`);
    }
  });

  return (
    <Card>
      <form onSubmit={onSubmit} noValidate>
        <CardHeader>
          <CardTitle>Create relationship</CardTitle>
        </CardHeader>

        <CardContent className="space-y-5 pt-4">
          <div className="grid gap-2">
            <Label htmlFor="namespace">Namespace</Label>
            <Input
              id="namespace"
              className="font-mono text-xs"
              placeholder="e.g. documents"
              {...form.register("namespace")}
            />
            <FieldError msg={form.formState.errors.namespace?.message} />
          </div>

          <div className="grid gap-2">
            <Label htmlFor="object">Object</Label>
            <Input
              id="object"
              className="font-mono text-xs"
              placeholder="e.g. doc:readme"
              {...form.register("object")}
            />
            <FieldError msg={form.formState.errors.object?.message} />
          </div>

          <div className="grid gap-2">
            <Label htmlFor="relation">Relation</Label>
            <Input
              id="relation"
              className="font-mono text-xs"
              placeholder="e.g. viewer"
              {...form.register("relation")}
            />
            <FieldError msg={form.formState.errors.relation?.message} />
          </div>

          <div className="grid gap-2">
            <Label htmlFor="subject_id">Subject ID</Label>
            <Input
              id="subject_id"
              className="font-mono text-xs"
              placeholder="e.g. user:alice"
              {...form.register("subject_id")}
            />
            <p className="text-muted-foreground text-sm">
              Provide a subject ID <strong>or</strong> a subject set below — not
              both.
            </p>
            <FieldError msg={form.formState.errors.subject_id?.message} />
          </div>

          <div className="grid gap-2">
            <Label>Subject set</Label>
            <div className="grid gap-2 sm:grid-cols-3">
              <Input
                aria-label="Subject set namespace"
                className="font-mono text-xs"
                placeholder="namespace"
                {...form.register("subject_set_namespace")}
              />
              <Input
                aria-label="Subject set object"
                className="font-mono text-xs"
                placeholder="object"
                {...form.register("subject_set_object")}
              />
              <Input
                aria-label="Subject set relation"
                className="font-mono text-xs"
                placeholder="relation"
                {...form.register("subject_set_relation")}
              />
            </div>
            <p className="text-muted-foreground text-sm">
              A subject set references another relation as{" "}
              <code className="font-mono text-xs">
                namespace:object#relation
              </code>
              . All three fields are required when used.
            </p>
            <FieldError
              msg={form.formState.errors.subject_set_relation?.message}
            />
          </div>

          {formError ? (
            <Alert variant="destructive" role="alert">
              <AlertTitle>Create failed</AlertTitle>
              <AlertDescription>{formError}</AlertDescription>
            </Alert>
          ) : null}
        </CardContent>

        <CardFooter className="mt-4 flex justify-end gap-2 border-t pt-4">
          {onCancel ? (
            <Button type="button" variant="outline" onClick={onCancel}>
              Cancel
            </Button>
          ) : null}
          <Button type="submit" disabled={form.formState.isSubmitting}>
            Create relationship
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
