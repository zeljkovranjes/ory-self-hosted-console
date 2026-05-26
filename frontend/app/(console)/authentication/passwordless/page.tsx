"use client";

// AUTH-02 — Passwordless & Passkeys (UI-SPEC §2, 07-RESEARCH Page 2).
//
// Passkey + WebAuthn relying-party config (rp id / display_name / origins list),
// the WebAuthn passwordless (first-factor) switch, and the code passwordless
// flag. Uses `origins` (array) — NOT the deprecated `origin` (07-RESEARCH State
// of the Art). Bound 1:1 to the section JSON-Pointers; the form values ARE the
// flat pointer-keyed PUT body.
//
// Cross-page note (07-RESEARCH Pitfall): the `code` block enforces an anyOf so
// `passwordless_enabled` and `mfa_enabled` are not both true. `mfa_enabled` is
// owned by the MFA page; this page validates only what it owns (the backend
// full-doc schema is the authoritative gate).

import { z } from "zod";

import { ConfigSection } from "../_lib/config-section";
import {
  PointerStringList,
  PointerSwitch,
  PointerText,
} from "../_lib/controls";

const PK_RP_ID = "/selfservice/methods/passkey/config/rp/id";
const PK_RP_NAME = "/selfservice/methods/passkey/config/rp/display_name";
const PK_RP_ORIGINS = "/selfservice/methods/passkey/config/rp/origins";
const WA_PASSWORDLESS = "/selfservice/methods/webauthn/config/passwordless";
const WA_RP_ID = "/selfservice/methods/webauthn/config/rp/id";
const WA_RP_NAME = "/selfservice/methods/webauthn/config/rp/display_name";
const WA_RP_ORIGINS = "/selfservice/methods/webauthn/config/rp/origins";
const CODE_PASSWORDLESS = "/selfservice/methods/code/passwordless_enabled";

const origins = z.array(z.string());

const schema = z.object({
  [PK_RP_ID]: z.string(),
  [PK_RP_NAME]: z.string(),
  [PK_RP_ORIGINS]: origins,
  [WA_PASSWORDLESS]: z.boolean(),
  [WA_RP_ID]: z.string(),
  [WA_RP_NAME]: z.string(),
  [WA_RP_ORIGINS]: origins,
  [CODE_PASSWORDLESS]: z.boolean(),
}) as unknown as z.ZodType<Record<string, unknown>, Record<string, unknown>>;

const defaults: Record<string, unknown> = {
  [PK_RP_ID]: "",
  [PK_RP_NAME]: "",
  [PK_RP_ORIGINS]: [],
  [WA_PASSWORDLESS]: false,
  [WA_RP_ID]: "",
  [WA_RP_NAME]: "",
  [WA_RP_ORIGINS]: [],
  [CODE_PASSWORDLESS]: false,
};

export default function PasswordlessPage() {
  return (
    <ConfigSection
      section="passwordless"
      schema={schema}
      defaults={defaults}
      title="Passwordless & passkeys"
      description="Relying-party config for passkeys and WebAuthn, plus the code passwordless flag."
    >
      {(form) => (
        <div className="space-y-6">
          <div className="space-y-4">
            <h3 className="text-sm font-medium">Passkey relying party</h3>
            <PointerText
              form={form}
              pointer={PK_RP_ID}
              label="Passkey RP id"
              placeholder="example.com"
              description="A subset of the browser domain (e.g. example.com)."
            />
            <PointerText
              form={form}
              pointer={PK_RP_NAME}
              label="Passkey RP display name"
              placeholder="Ory Console"
            />
            <PointerStringList
              form={form}
              pointer={PK_RP_ORIGINS}
              label="Passkey origin"
              placeholder="https://example.com"
              description="Allowed origins for passkey ceremonies."
            />
          </div>

          <div className="space-y-4">
            <h3 className="text-sm font-medium">WebAuthn relying party</h3>
            <PointerSwitch
              form={form}
              pointer={WA_PASSWORDLESS}
              label="WebAuthn passwordless (first factor)"
              description="Use WebAuthn as a first factor rather than 2FA."
            />
            <PointerText
              form={form}
              pointer={WA_RP_ID}
              label="WebAuthn RP id"
              placeholder="example.com"
            />
            <PointerText
              form={form}
              pointer={WA_RP_NAME}
              label="WebAuthn RP display name"
              placeholder="Ory Console"
            />
            <PointerStringList
              form={form}
              pointer={WA_RP_ORIGINS}
              label="WebAuthn origin"
              placeholder="https://example.com"
              description="Allowed origins for WebAuthn ceremonies."
            />
          </div>

          <div className="space-y-4">
            <h3 className="text-sm font-medium">One-time code</h3>
            <PointerSwitch
              form={form}
              pointer={CODE_PASSWORDLESS}
              label="Code passwordless"
              description="Allow one-time codes as a passwordless first factor (cannot also be a second factor — set on the MFA page)."
            />
          </div>
        </div>
      )}
    </ConfigSection>
  );
}
