"use client";

// OAUTH2-06 — Token Lifespans (08-UI-SPEC §E, 08-RESEARCH Page 4).
//
// Time-to-live durations for access, refresh, ID, and auth-code tokens + the
// login/consent flow. All Ory duration strings (e.g. `1h`, `720h`, `30m`).

import { z } from "zod";

import { ConfigSection, HYDRA_DURATION_REGEX } from "../_lib/config-section";
import { PointerText } from "../../authentication/_lib/controls";

const TTLS = [
  { p: "/ttl/access_token", label: "Access token lifespan", placeholder: "1h" },
  { p: "/ttl/refresh_token", label: "Refresh token lifespan", placeholder: "720h" },
  { p: "/ttl/id_token", label: "ID token lifespan", placeholder: "1h" },
  { p: "/ttl/auth_code", label: "Authorization code lifespan", placeholder: "10m" },
  { p: "/ttl/login_consent_request", label: "Login & consent request lifespan", placeholder: "30m" },
] as const;

// A duration string OR an empty string (unset -> schema default). The exact
// duration grammar mirrors the Hydra schema; an invalid value also 422s server-side.
const durationField = z.union([
  z.literal(""),
  z.string().regex(HYDRA_DURATION_REGEX, "Enter a duration like 1h, 30m, or 720h"),
]);

const schema = z.object(
  Object.fromEntries(TTLS.map((t) => [t.p, durationField])),
) as unknown as z.ZodType<Record<string, string>, Record<string, string>>;

const defaults: Record<string, string> = Object.fromEntries(
  TTLS.map((t) => [t.p, ""]),
);

export default function LifespansPage() {
  return (
    <ConfigSection
      service="hydra"
      section="ttl"
      schema={schema}
      defaults={defaults}
      title="Token Lifespans"
      description="Time-to-live for access, refresh, ID, and auth-code tokens."
    >
      {(form) => (
        <div className="space-y-4">
          {TTLS.map((t) => (
            <PointerText
              key={t.p}
              form={form}
              pointer={t.p}
              label={t.label}
              placeholder={t.placeholder}
            />
          ))}
        </div>
      )}
    </ConfigSection>
  );
}
