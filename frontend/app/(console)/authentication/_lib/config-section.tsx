"use client";

// Phase 7 — shared scaffolding for the scalar Kratos auth config pages
// (Methods, Passwordless, MFA, Sessions, Recovery, Verification).
//
// Every page follows the same shape (07-RESEARCH / Plan 03 Task 2):
//   1. GET the section via api() to prefill — the backend returns a FLAT object
//      keyed by RFC-6901 JSON-Pointer (absent pointers omitted).
//   2. Build a Zod object whose KEYS are exactly the section's allowlisted
//      JSON-Pointers (mirror of the Plan-01 backend allowlist).
//   3. Render a SettingsForm whose `submitPath` is /api/config/kratos/<section>;
//      the form values ARE the flat pointer-keyed PUT body (no transform).
//
// `ConfigSection` owns the load/skeleton/error wrapper and merges the GET result
// over the per-section defaults so the SettingsForm gets a complete, typed
// defaultValues object (absent pointers fall back to their schema default).

import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import type { z, ZodType } from "zod";
import type { FieldValues } from "react-hook-form";

import { api } from "@/lib/api";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Skeleton } from "@/components/ui/skeleton";
import {
  SettingsForm,
  type SettingsFormProps,
} from "@/components/settings-form";

// The AAL enum is `aal1` / `highest_available` — NOT `highest_aal`
// (07-RESEARCH Pitfall 1, verified against kratos.config.schema.json:881). This
// single const is shared by the MFA selects and the Sessions whoami select so
// the wrong literal cannot drift in.
export const AAL_VALUES = ["aal1", "highest_available"] as const;
export type AalValue = (typeof AAL_VALUES)[number];

// Kratos duration strings (e.g. `24h`, `1h30m`, `500ms`). Mirrors the schema
// pattern used for session/recovery/verification lifespans.
export const DURATION_REGEX = /^([0-9]+(ns|us|ms|s|m|h))+$/;

/** The `same_site` cookie enum (schema: [Strict, Lax, None]). */
export const SAME_SITE_VALUES = ["Strict", "Lax", "None"] as const;

/** The recovery/verification `use` method enum (schema: [link, code]). */
export const USE_VALUES = ["link", "code"] as const;

type FieldSchema = ZodType<unknown, FieldValues>;

export type ConfigSectionProps<TSchema extends FieldSchema> = Omit<
  SettingsFormProps<TSchema>,
  "defaultValues" | "submitPath"
> & {
  /** Kratos config section name (the URL segment + query key). */
  section: string;
  /**
   * The per-pointer defaults for this section. Keys are the section's
   * JSON-Pointers; the GET result is merged OVER these so every pointer the
   * form binds has a defined value (absent-on-disk -> schema default).
   */
  defaults: z.input<TSchema>;
};

/**
 * Loads `GET /api/config/kratos/<section>`, merges it over `defaults`, and
 * renders the section's {@link SettingsForm}. Shows a Skeleton while loading and
 * a destructive Alert if the section cannot be read.
 */
export function ConfigSection<TSchema extends FieldSchema>({
  section,
  defaults,
  schema,
  children,
  ...rest
}: ConfigSectionProps<TSchema>) {
  const path = `/api/config/kratos/${section}`;
  const query = useQuery({
    queryKey: ["config", "kratos", section],
    queryFn: () => api<Record<string, unknown>>(path),
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
          The {section} configuration could not be loaded. Try again later.
        </AlertDescription>
      </Alert>
    );
  }

  // The GET returns only present pointers; merge over defaults so every bound
  // field has a value. The merged object is the SettingsForm defaultValues AND
  // the basis of the flat pointer-keyed PUT body.
  const merged = {
    ...(defaults as Record<string, unknown>),
    ...(query.data ?? {}),
  } as z.input<TSchema>;

  return (
    <SettingsForm
      {...rest}
      schema={schema}
      submitPath={path}
      defaultValues={merged as never}
    >
      {children}
    </SettingsForm>
  );
}
