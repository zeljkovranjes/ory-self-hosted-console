"use client";

// Phase 8 — shared scaffolding for the scalar Hydra config pages (General, URLs,
// Lifespans, Token Strategies, Cookies; the OIDC page composes this for its
// non-secret keys). Generalized from the Phase-7 Kratos `ConfigSection` by adding
// a `service` prop so the same load/merge/SettingsForm contract serves both the
// Kratos (`/api/config/kratos/<section>`) and Hydra (`/api/config/hydra/<section>`)
// config planes through the one Phase-4 engine.
//
// Every page follows the same shape (08-UI-SPEC §E):
//   1. GET the section via api() to prefill — the backend returns a FLAT object
//      keyed by RFC-6901 JSON-Pointer (absent pointers omitted).
//   2. Build a Zod object whose KEYS are exactly the section's allowlisted
//      JSON-Pointers (mirror of the Task-1 backend allowlist).
//   3. Render a SettingsForm whose `submitPath` is /api/config/<service>/<section>;
//      the form values ARE the flat pointer-keyed PUT body (no transform).
//
// `ConfigSection` owns the load/skeleton/error wrapper and merges the GET result
// over the per-section defaults so the SettingsForm gets a complete, typed
// defaultValues object (absent pointers fall back to their schema default). Egress
// is only via @/lib/api — never an Ory host directly.

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

/** The config services this helper can target (closed set, mirrors the backend). */
export type ConfigService = "kratos" | "hydra";

// ── Hydra config enums (verified against hydra.config.schema.json) ────────────

/** `strategies.access_token` enum. */
export const ACCESS_TOKEN_STRATEGY_VALUES = ["opaque", "jwt"] as const;
/** `strategies.scope` enum. */
export const SCOPE_STRATEGY_VALUES = ["exact", "wildcard"] as const;
/** `strategies.jwt.scope_claim` enum. */
export const SCOPE_CLAIM_VALUES = ["list", "string", "both"] as const;
/** `serve.cookies.same_site_mode` enum. */
export const HYDRA_SAME_SITE_VALUES = ["Strict", "Lax", "None"] as const;
/** `oidc.subject_identifiers.supported_types` member enum. */
export const SUBJECT_TYPE_VALUES = ["public", "pairwise"] as const;

/** Ory duration strings (e.g. `1h`, `30m`, `720h`). Mirrors the schema pattern. */
export const HYDRA_DURATION_REGEX = /^([0-9]+(ns|us|ms|s|m|h))+$/;

type FieldSchema = ZodType<unknown, FieldValues>;

export type ConfigSectionProps<TSchema extends FieldSchema> = Omit<
  SettingsFormProps<TSchema>,
  "defaultValues" | "submitPath"
> & {
  /**
   * Config service (`kratos` | `hydra`). Defaults to `kratos` to keep the
   * Phase-7 call sites backward-compatible; the Hydra pages pass `service="hydra"`.
   */
  service?: ConfigService;
  /** Config section name (the URL segment + query key). */
  section: string;
  /**
   * The per-pointer defaults for this section. Keys are the section's
   * JSON-Pointers; the GET result is merged OVER these so every pointer the
   * form binds has a defined value (absent-on-disk -> schema default).
   */
  defaults: z.input<TSchema>;
};

/**
 * Loads `GET /api/config/<service>/<section>`, merges it over `defaults`, and
 * renders the section's {@link SettingsForm}. Shows a Skeleton while loading and
 * a destructive Alert if the section cannot be read.
 */
export function ConfigSection<TSchema extends FieldSchema>({
  service = "kratos",
  section,
  defaults,
  schema,
  children,
  ...rest
}: ConfigSectionProps<TSchema>) {
  const path = `/api/config/${service}/${section}`;
  const query = useQuery({
    queryKey: ["config", service, section],
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
