"use client";

// OAUTH2-03 — General & Issuer (08-UI-SPEC §E, 08-RESEARCH Page 1).
//
// Public issuer URL + non-sensitive serve.public settings. The form values ARE
// the flat pointer-keyed PUT body the backend's `general` section expects (no
// transform). NO top-level `issuer` key exists — the issuer is `urls.self.issuer`.
// serve.admin.* and serve.public.tls are server-denylisted and have no control.

import { z } from "zod";

import { ConfigSection } from "../_lib/config-section";
import { PointerSwitch, PointerText } from "../../authentication/_lib/controls";

const ISSUER = "/urls/self/issuer";
const PUBLIC_URL = "/urls/self/public";
const HOST = "/serve/public/host";
const PORT = "/serve/public/port";
const CORS_ENABLED = "/serve/public/cors/enabled";

const schema = z.object({
  [ISSUER]: z.string(),
  [PUBLIC_URL]: z.string(),
  [HOST]: z.string(),
  [PORT]: z.union([z.literal(""), z.coerce.number().int().min(1).max(65535)]),
  [CORS_ENABLED]: z.boolean(),
}) as unknown as z.ZodType<Record<string, unknown>, Record<string, unknown>>;

const defaults: Record<string, unknown> = {
  [ISSUER]: "",
  [PUBLIC_URL]: "",
  [HOST]: "",
  [PORT]: "",
  [CORS_ENABLED]: false,
};

export default function GeneralPage() {
  return (
    <ConfigSection
      service="hydra"
      section="general"
      schema={schema}
      defaults={defaults}
      title="General & Issuer"
      description="Public issuer URL and non-sensitive serve settings for Hydra."
    >
      {(form) => (
        <div className="space-y-4">
          <PointerText
            form={form}
            pointer={ISSUER}
            label="Issuer URL"
            description="The OAuth2 / OIDC issuer (urls.self.issuer)."
            placeholder="https://auth.example.com/"
          />
          <PointerText
            form={form}
            pointer={PUBLIC_URL}
            label="Public base URL"
            description="The base location of Hydra's public endpoints."
            placeholder="https://auth.example.com/"
          />
          <PointerText
            form={form}
            pointer={HOST}
            label="Public listen host"
            placeholder="0.0.0.0"
          />
          <PointerText
            form={form}
            pointer={PORT}
            label="Public listen port"
            type="number"
            placeholder="4444"
          />
          <PointerSwitch
            form={form}
            pointer={CORS_ENABLED}
            label="Enable CORS (public endpoint)"
            description="Allow cross-origin requests to the public OAuth2 endpoints."
          />
        </div>
      )}
    </ConfigSection>
  );
}
