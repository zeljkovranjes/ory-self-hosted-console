"use client";

// AUTH-03 — Two-Factor / MFA (UI-SPEC §3, 07-RESEARCH Page 3).
//
// 2FA method switches (totp / lookup_secret / webauthn / code-as-2nd-factor),
// the TOTP issuer, and the whoami required_aal select. The AAL enum is
// the shared `AAL_VALUES` const (aal1, highest_available) — NEVER `highest_aal`
// (07-RESEARCH Pitfall 1). This page is the canonical UI owner of required_aal
// (Open Q2). Bound 1:1 to the section JSON-Pointers; the form values ARE the
// flat pointer-keyed PUT body.
//
// NOTE: `selfservice.flows.login.required_aal` is NOT exposed — the Kratos
// v26.2.0 config schema marks `selfservice.flows.login` additionalProperties:false
// with no `required_aal`, so writing it 422s. `session.whoami.required_aal` is the
// schema-valid assurance-level control and is the sole AAL field here.

import { z } from "zod";

import { AAL_VALUES, ConfigSection } from "../_lib/config-section";
import { PointerSelect, PointerSwitch, PointerText } from "../_lib/controls";

const TOTP = "/selfservice/methods/totp/enabled";
const TOTP_ISSUER = "/selfservice/methods/totp/config/issuer";
const LOOKUP = "/selfservice/methods/lookup_secret/enabled";
const WEBAUTHN = "/selfservice/methods/webauthn/enabled";
const CODE_MFA = "/selfservice/methods/code/mfa_enabled";
const WHOAMI_AAL = "/session/whoami/required_aal";

const schema = z.object({
  [TOTP]: z.boolean(),
  [TOTP_ISSUER]: z.string(),
  [LOOKUP]: z.boolean(),
  [WEBAUTHN]: z.boolean(),
  [CODE_MFA]: z.boolean(),
  [WHOAMI_AAL]: z.enum(AAL_VALUES),
}) as unknown as z.ZodType<Record<string, unknown>, Record<string, unknown>>;

const defaults: Record<string, unknown> = {
  [TOTP]: false,
  [TOTP_ISSUER]: "",
  [LOOKUP]: false,
  [WEBAUTHN]: false,
  [CODE_MFA]: false,
  [WHOAMI_AAL]: "highest_available",
};

export default function MfaPage() {
  return (
    <ConfigSection
      section="mfa"
      schema={schema}
      defaults={defaults}
      title="Two-factor authentication"
      description="Configure second-factor methods and the required assurance level."
    >
      {(form) => (
        <div className="space-y-4">
          <PointerSwitch
            form={form}
            pointer={TOTP}
            label="TOTP (authenticator app)"
            description="Time-based one-time passwords as a second factor."
          />
          <PointerText
            form={form}
            pointer={TOTP_ISSUER}
            label="TOTP issuer"
            placeholder="Ory Console"
            description="Shown in the operator's authenticator app."
          />
          <PointerSwitch
            form={form}
            pointer={LOOKUP}
            label="Backup codes (lookup secret)"
            description="One-time recovery codes as a second factor."
          />
          <PointerSwitch
            form={form}
            pointer={WEBAUTHN}
            label="WebAuthn (2FA)"
            description="Hardware security keys as a second factor. RP config lives on the Passwordless page."
          />
          <PointerSwitch
            form={form}
            pointer={CODE_MFA}
            label="One-time code (2FA)"
            description="Email/SMS one-time code as a second factor."
          />
          <PointerSelect
            form={form}
            pointer={WHOAMI_AAL}
            label="Required AAL"
            options={AAL_VALUES}
            description="The assurance level required for an active session (whoami)."
          />
        </div>
      )}
    </ConfigSection>
  );
}
