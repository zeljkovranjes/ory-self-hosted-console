"use client";

// AUTH-07 — Account Recovery (UI-SPEC §6, 07-RESEARCH Page 6).
//
// Recovery flow config: enabled, `use` method (link/code), lifespan duration,
// notify-unknown-recipients, plus the code/link method enable switches recovery
// depends on. `ui_url` is intentionally omitted (owned by BRAND-02 / Phase 10).
// Bound 1:1 to the section JSON-Pointers.

import { z } from "zod";

import {
  DURATION_REGEX,
  USE_VALUES,
  ConfigSection,
} from "../_lib/config-section";
import { PointerSelect, PointerSwitch, PointerText } from "../_lib/controls";

const ENABLED = "/selfservice/flows/recovery/enabled";
const USE = "/selfservice/flows/recovery/use";
const LIFESPAN = "/selfservice/flows/recovery/lifespan";
const NOTIFY = "/selfservice/flows/recovery/notify_unknown_recipients";
const CODE_ENABLED = "/selfservice/methods/code/enabled";
const LINK_ENABLED = "/selfservice/methods/link/enabled";

const schema = z.object({
  [ENABLED]: z.boolean(),
  [USE]: z.enum(USE_VALUES),
  [LIFESPAN]: z
    .string()
    .regex(DURATION_REGEX, "Enter a duration, e.g. 1h, 30m or 90s"),
  [NOTIFY]: z.boolean(),
  [CODE_ENABLED]: z.boolean(),
  [LINK_ENABLED]: z.boolean(),
}) as unknown as z.ZodType<Record<string, unknown>, Record<string, unknown>>;

const defaults: Record<string, unknown> = {
  [ENABLED]: false,
  [USE]: "code",
  [LIFESPAN]: "1h",
  [NOTIFY]: false,
  [CODE_ENABLED]: true,
  [LINK_ENABLED]: false,
};

export default function RecoveryPage() {
  return (
    <ConfigSection
      section="recovery"
      schema={schema}
      defaults={defaults}
      title="Account recovery"
      description="Let identities recover access via a one-time code or a magic link."
    >
      {(form) => (
        <div className="space-y-4">
          <PointerSwitch
            form={form}
            pointer={ENABLED}
            label="Enable recovery"
            description="Turn the account-recovery flow on."
          />
          <PointerSelect
            form={form}
            pointer={USE}
            label="Recovery method"
            options={USE_VALUES}
            description="Whether recovery uses a one-time code or a magic link."
          />
          <PointerText
            form={form}
            pointer={LIFESPAN}
            label="Recovery lifespan"
            placeholder="1h"
            description="How long a recovery code/link stays valid."
          />
          <PointerSwitch
            form={form}
            pointer={NOTIFY}
            label="Notify unknown recipients"
            description="Send a notice even when the address is not a known identity."
          />
          <PointerSwitch
            form={form}
            pointer={CODE_ENABLED}
            label="Code method enabled"
            description="Recovery via one-time code requires the code method."
          />
          <PointerSwitch
            form={form}
            pointer={LINK_ENABLED}
            label="Link method enabled"
            description="Recovery via magic link requires the link method."
          />
        </div>
      )}
    </ConfigSection>
  );
}
