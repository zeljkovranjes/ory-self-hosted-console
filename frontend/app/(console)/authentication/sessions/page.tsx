"use client";

// AUTH-06 — Sessions (UI-SPEC §5, 07-RESEARCH Page 5).
//
// Edits the Kratos `session` config: lifespan (duration), cookie persistent /
// same_site / domain / path / name, the whoami required_aal, and the
// earliest-possible-extend window. Bound 1:1 to the section's JSON-Pointers; the
// form values ARE the flat pointer-keyed PUT body.
//
// The whoami `required_aal` is also editable on the MFA page (its canonical UI
// owner per 07-RESEARCH Open Q2); both backend allowlists list the pointer
// harmlessly (the engine merges one doc). It is shown here for completeness.

import { z } from "zod";

import {
  AAL_VALUES,
  DURATION_REGEX,
  SAME_SITE_VALUES,
  ConfigSection,
} from "../_lib/config-section";
import {
  PointerSelect,
  PointerSwitch,
  PointerText,
} from "../_lib/controls";

const LIFESPAN = "/session/lifespan";
const PERSISTENT = "/session/cookie/persistent";
const SAME_SITE = "/session/cookie/same_site";
const DOMAIN = "/session/cookie/domain";
const PATH = "/session/cookie/path";
const NAME = "/session/cookie/name";
const WHOAMI_AAL = "/session/whoami/required_aal";
const EARLIEST = "/session/earliest_possible_extend";

const duration = z
  .string()
  .regex(DURATION_REGEX, "Enter a duration, e.g. 24h, 1h30m or 500ms");

const schema = z.object({
  [LIFESPAN]: duration,
  [PERSISTENT]: z.boolean(),
  [SAME_SITE]: z.enum(SAME_SITE_VALUES),
  [DOMAIN]: z.string(),
  [PATH]: z.string(),
  [NAME]: z.string(),
  [WHOAMI_AAL]: z.enum(AAL_VALUES),
  [EARLIEST]: z.union([
    z.literal(""),
    z.string().regex(DURATION_REGEX, "Use a duration value or leave blank"),
  ]),
}) as unknown as z.ZodType<Record<string, unknown>, Record<string, unknown>>;

const defaults: Record<string, unknown> = {
  [LIFESPAN]: "24h",
  [PERSISTENT]: true,
  [SAME_SITE]: "Lax",
  [DOMAIN]: "",
  [PATH]: "/",
  [NAME]: "ory_kratos_session",
  [WHOAMI_AAL]: "highest_available",
  [EARLIEST]: "",
};

export default function SessionsPage() {
  return (
    <ConfigSection
      section="sessions"
      schema={schema}
      defaults={defaults}
      title="Sessions & cookies"
      description="Control session lifetime and the Kratos session cookie."
    >
      {(form) => (
        <div className="space-y-4">
          <PointerText
            form={form}
            pointer={LIFESPAN}
            label="Session lifespan"
            placeholder="24h"
            description="How long a session stays valid (e.g. 24h, 720h)."
          />
          <PointerSwitch
            form={form}
            pointer={PERSISTENT}
            label="Persistent cookie"
            description="Keep the session cookie across browser restarts."
          />
          <PointerSelect
            form={form}
            pointer={SAME_SITE}
            label="Cookie SameSite"
            options={SAME_SITE_VALUES}
          />
          <PointerText form={form} pointer={DOMAIN} label="Cookie domain" placeholder="example.com" />
          <PointerText form={form} pointer={PATH} label="Cookie path" placeholder="/" />
          <PointerText form={form} pointer={NAME} label="Cookie name" placeholder="ory_kratos_session" />
          <PointerSelect
            form={form}
            pointer={WHOAMI_AAL}
            label="whoami required AAL"
            options={AAL_VALUES}
            description="Also editable on the Two-Factor / MFA page (the canonical owner)."
          />
          <PointerText
            form={form}
            pointer={EARLIEST}
            label="Earliest possible extend"
            placeholder="(leave blank to disable)"
            description="Optional: only extend the session within this window before expiry."
          />
        </div>
      )}
    </ConfigSection>
  );
}
