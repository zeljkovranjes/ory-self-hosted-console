"use client";

// OAUTH2-05 — URLs (08-UI-SPEC §E, 08-RESEARCH Page 3).
//
// Login, consent, logout, error, and post-logout redirect endpoints + the
// self issuer/public URLs. All strings. The canonical editor for the issuer is
// the General page; it is listed here harmlessly (the engine merges one doc).

import { z } from "zod";

import { ConfigSection } from "../_lib/config-section";
import { PointerText } from "../../authentication/_lib/controls";

const URLS = [
  { p: "/urls/login", label: "Login URL", placeholder: "https://app.example.com/login" },
  { p: "/urls/consent", label: "Consent URL", placeholder: "https://app.example.com/consent" },
  { p: "/urls/logout", label: "Logout URL", placeholder: "https://app.example.com/logout" },
  { p: "/urls/error", label: "Error URL", placeholder: "https://app.example.com/error" },
  { p: "/urls/post_logout_redirect", label: "Post-logout redirect URL", placeholder: "https://app.example.com/" },
  { p: "/urls/self/issuer", label: "Issuer URL (shared with General)", placeholder: "https://auth.example.com/" },
  { p: "/urls/self/public", label: "Public base URL (shared with General)", placeholder: "https://auth.example.com/" },
] as const;

const schema = z.object(
  Object.fromEntries(URLS.map((u) => [u.p, z.string()])),
) as unknown as z.ZodType<Record<string, string>, Record<string, string>>;

const defaults: Record<string, string> = Object.fromEntries(
  URLS.map((u) => [u.p, ""]),
);

export default function UrlsPage() {
  return (
    <ConfigSection
      service="hydra"
      section="urls"
      schema={schema}
      defaults={defaults}
      title="URLs"
      description="Login, consent, logout, error, and post-logout redirect endpoints."
    >
      {(form) => (
        <div className="space-y-4">
          {URLS.map((u) => (
            <PointerText
              key={u.p}
              form={form}
              pointer={u.p}
              label={u.label}
              placeholder={u.placeholder}
            />
          ))}
        </div>
      )}
    </ConfigSection>
  );
}
