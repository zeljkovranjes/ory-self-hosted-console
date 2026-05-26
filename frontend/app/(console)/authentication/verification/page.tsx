"use client";

// AUTH-08 — Account Verification (UI-SPEC §7, 07-RESEARCH Page 7).
//
// Verification flow config: enabled, `use` method (link/code), lifespan
// duration, notify-unknown-recipients. `ui_url` is intentionally omitted (owned
// by BRAND-02 / Phase 10). Bound 1:1 to the section JSON-Pointers.

import { z } from "zod";

import {
  DURATION_REGEX,
  USE_VALUES,
  ConfigSection,
} from "../_lib/config-section";
import { PointerSelect, PointerSwitch, PointerText } from "../_lib/controls";

const ENABLED = "/selfservice/flows/verification/enabled";
const USE = "/selfservice/flows/verification/use";
const LIFESPAN = "/selfservice/flows/verification/lifespan";
const NOTIFY = "/selfservice/flows/verification/notify_unknown_recipients";

const schema = z.object({
  [ENABLED]: z.boolean(),
  [USE]: z.enum(USE_VALUES),
  [LIFESPAN]: z
    .string()
    .regex(DURATION_REGEX, "Enter a duration, e.g. 1h, 30m or 90s"),
  [NOTIFY]: z.boolean(),
}) as unknown as z.ZodType<Record<string, unknown>, Record<string, unknown>>;

const defaults: Record<string, unknown> = {
  [ENABLED]: false,
  [USE]: "code",
  [LIFESPAN]: "1h",
  [NOTIFY]: false,
};

export default function VerificationPage() {
  return (
    <ConfigSection
      section="verification"
      schema={schema}
      defaults={defaults}
      title="Account verification"
      description="Require identities to verify their address via a code or magic link."
    >
      {(form) => (
        <div className="space-y-4">
          <PointerSwitch
            form={form}
            pointer={ENABLED}
            label="Enable verification"
            description="Turn the address-verification flow on."
          />
          <PointerSelect
            form={form}
            pointer={USE}
            label="Verification method"
            options={USE_VALUES}
            description="Whether verification uses a one-time code or a magic link."
          />
          <PointerText
            form={form}
            pointer={LIFESPAN}
            label="Verification lifespan"
            placeholder="1h"
            description="How long a verification code/link stays valid."
          />
          <PointerSwitch
            form={form}
            pointer={NOTIFY}
            label="Notify unknown recipients"
            description="Send a notice even when the address is not a known identity."
          />
        </div>
      )}
    </ConfigSection>
  );
}
