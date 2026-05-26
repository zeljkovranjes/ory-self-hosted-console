"use client";

// AUTH-01 — General / Methods (UI-SPEC §1, 07-RESEARCH Page 1).
//
// A labeled switch for each of the 9 Kratos auth methods, bound 1:1 to its
// `/selfservice/methods/<m>/enabled` JSON-Pointer. The form values ARE the flat
// pointer-keyed PUT body the backend's `methods` section expects (no transform).
// GET prefills the current enabled state (absent pointer -> schema default).
//
// Pitfall 6 (07-RESEARCH): enabling webauthn/passkey requires RP config on the
// Passwordless page; a bare enable can 422 — surfaced inline via the existing
// 422 path. We keep section ownership clean and do NOT co-set RP config here.

import { z } from "zod";

import { ConfigSection } from "../_lib/config-section";
import { PointerSwitch } from "../_lib/controls";

// Each method's enabled pointer + UI label + default. Defaults mirror the
// v26.2.0 schema (07-RESEARCH Page 1).
const METHODS = [
  { p: "/selfservice/methods/password/enabled", label: "Password", def: true, desc: "Username/email + password sign-in." },
  { p: "/selfservice/methods/code/enabled", label: "One-time code", def: true, desc: "One-time login/registration codes." },
  { p: "/selfservice/methods/oidc/enabled", label: "Social Sign-In (OIDC)", def: false, desc: "Third-party identity providers. Configure providers on the Social Sign-In page." },
  { p: "/selfservice/methods/totp/enabled", label: "TOTP", def: false, desc: "Authenticator-app one-time passwords (2FA)." },
  { p: "/selfservice/methods/lookup_secret/enabled", label: "Backup codes", def: false, desc: "Lookup-secret recovery/backup codes." },
  { p: "/selfservice/methods/webauthn/enabled", label: "WebAuthn", def: false, desc: "Hardware security keys. Requires RP config on the Passwordless page (a bare enable may fail validation)." },
  { p: "/selfservice/methods/passkey/enabled", label: "Passkey", def: false, desc: "Passkeys. Requires RP config on the Passwordless page (a bare enable may fail validation)." },
  { p: "/selfservice/methods/link/enabled", label: "Magic link", def: false, desc: "Email magic-link recovery/verification." },
  { p: "/selfservice/methods/profile/enabled", label: "Profile", def: true, desc: "Self-service profile management." },
] as const;

const schema = z.object(
  Object.fromEntries(METHODS.map((m) => [m.p, z.boolean()])),
) as z.ZodType<Record<string, boolean>, Record<string, boolean>>;

const defaults: Record<string, boolean> = Object.fromEntries(
  METHODS.map((m) => [m.p, m.def]),
);

export default function MethodsPage() {
  return (
    <ConfigSection
      section="methods"
      schema={schema}
      defaults={defaults}
      title="Authentication methods"
      description="Enable or disable each Kratos sign-in and account method."
    >
      {(form) => (
        <div className="space-y-4">
          {METHODS.map((m) => (
            <PointerSwitch
              key={m.p}
              form={form}
              pointer={m.p}
              label={m.label}
              description={m.desc}
            />
          ))}
        </div>
      )}
    </ConfigSection>
  );
}
