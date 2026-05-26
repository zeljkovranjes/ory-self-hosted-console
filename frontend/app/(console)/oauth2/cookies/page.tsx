"use client";

// OAUTH2-08 — Cookies (08-UI-SPEC §E, 08-RESEARCH Page 6).
//
// Non-secret cookie behavior: SameSite mode, legacy workaround, domain, secure
// flag, and the four cookie names. Cookie SECRETS live under /secrets/cookie
// (server-denylisted) and have NO control here — only behavior keys are editable.

import { z } from "zod";

import { ConfigSection, HYDRA_SAME_SITE_VALUES } from "../_lib/config-section";
import {
  PointerSelect,
  PointerSwitch,
  PointerText,
} from "../../authentication/_lib/controls";

const SAME_SITE = "/serve/cookies/same_site_mode";
const LEGACY = "/serve/cookies/same_site_legacy_workaround";
const DOMAIN = "/serve/cookies/domain";
const SECURE = "/serve/cookies/secure";
const NAME_LOGIN = "/serve/cookies/names/login_csrf";
const NAME_CONSENT = "/serve/cookies/names/consent_csrf";
const NAME_DEVICE = "/serve/cookies/names/device_csrf";
const NAME_SESSION = "/serve/cookies/names/session";

const NAMES = [
  { p: NAME_LOGIN, label: "Login CSRF cookie name", placeholder: "ory_hydra_login_csrf" },
  { p: NAME_CONSENT, label: "Consent CSRF cookie name", placeholder: "ory_hydra_consent_csrf" },
  { p: NAME_DEVICE, label: "Device CSRF cookie name", placeholder: "ory_hydra_device_csrf" },
  { p: NAME_SESSION, label: "Session cookie name", placeholder: "ory_hydra_session" },
] as const;

const schema = z.object({
  [SAME_SITE]: z.enum(HYDRA_SAME_SITE_VALUES),
  [LEGACY]: z.boolean(),
  [DOMAIN]: z.string(),
  [SECURE]: z.boolean(),
  [NAME_LOGIN]: z.string(),
  [NAME_CONSENT]: z.string(),
  [NAME_DEVICE]: z.string(),
  [NAME_SESSION]: z.string(),
}) as unknown as z.ZodType<Record<string, unknown>, Record<string, unknown>>;

const defaults: Record<string, unknown> = {
  [SAME_SITE]: "None",
  [LEGACY]: false,
  [DOMAIN]: "",
  [SECURE]: false,
  [NAME_LOGIN]: "",
  [NAME_CONSENT]: "",
  [NAME_DEVICE]: "",
  [NAME_SESSION]: "",
};

export default function CookiesPage() {
  return (
    <ConfigSection
      service="hydra"
      section="cookies"
      schema={schema}
      defaults={defaults}
      title="Cookies"
      description="Non-secret cookie behavior (SameSite mode, domain, names)."
    >
      {(form) => (
        <div className="space-y-4">
          <PointerSelect
            form={form}
            pointer={SAME_SITE}
            label="SameSite mode"
            options={HYDRA_SAME_SITE_VALUES}
          />
          <PointerSwitch
            form={form}
            pointer={LEGACY}
            label="SameSite legacy workaround"
            description="Store a fallback cookie without SameSite for older browsers."
          />
          <PointerText
            form={form}
            pointer={DOMAIN}
            label="Cookie domain"
            placeholder=".example.com"
            description="Scopes session and CSRF cookies. Use with care."
          />
          <PointerSwitch
            form={form}
            pointer={SECURE}
            label="Secure flag (development mode)"
            description="Cookies always have the secure flag in production."
          />
          {NAMES.map((n) => (
            <PointerText
              key={n.p}
              form={form}
              pointer={n.p}
              label={n.label}
              placeholder={n.placeholder}
            />
          ))}
        </div>
      )}
    </ConfigSection>
  );
}
