"use client";

// FE-01 / WR-01 + WR-02 — deterministic CSRF-token seeding for the console.
//
// The CSRF double-submit half (the readable token) is delivered ONLY on the
// protected `GET /api/console/me` response. Previously it was seeded as an
// incidental side effect of AccountMenu rendering (and during the render phase),
// which meant any OTHER client mutation on a console page (a future SettingsForm
// PUT, a DataTable row DELETE) could fire with `csrfToken === null` and 403 if
// AccountMenu had not yet rendered. It also mutated module state during render,
// violating React render purity under StrictMode/concurrent rendering.
//
// This component is mounted ONCE by the (console) server layout with the
// authoritative `me.csrf_token`. It seeds the client `api` module cache in an
// EFFECT (not during render), so EVERY authenticated page has the token in its
// module cache before any mutation — independent of AccountMenu's render order.

import { useEffect } from "react";
import { setCsrfToken } from "@/lib/api";

type CsrfSeedProps = {
  /** The per-session CSRF token from the server-side `/api/console/me` fetch. */
  token: string;
};

/**
 * Seeds the `lib/api` CSRF-token cache from the server-fetched `/me` token.
 * Renders nothing. Mount once per authenticated layout.
 */
export function CsrfSeed({ token }: CsrfSeedProps) {
  useEffect(() => {
    if (token) setCsrfToken(token);
  }, [token]);
  return null;
}
