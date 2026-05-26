"use client";

// BRAND-02 — UI URLs & Redirects (10-UI-SPEC §D, 10-RESEARCH Pattern 5).
//
// A ConfigSection/SettingsForm page (service=kratos) over the allowlisted
// selfservice flow `ui_url` keys + `allowed_return_urls` (array-root) +
// `default_browser_return_url`. The form keys ARE the section's JSON-Pointers
// (the flat pointer-keyed PUT body, no transform) — a 1:1 mirror of the backend
// `KRATOS_UI_URLS` allowlist. On save Kratos restarts ONLY.
//
// PITFALL 1 (the logout trap): there is NO `logout` ui_url key here — the
// v26.2.0 Kratos schema gives logout no `ui_url`, and including one would brick
// every save (`additionalProperties:false`). The backend allowlist omits it too.

import { z } from "zod";

import { ConfigSection } from "../../authentication/_lib/config-section";
import { PointerStringList, PointerText } from "../../authentication/_lib/controls";

const LOGIN = "/selfservice/flows/login/ui_url";
const REGISTRATION = "/selfservice/flows/registration/ui_url";
const RECOVERY = "/selfservice/flows/recovery/ui_url";
const VERIFICATION = "/selfservice/flows/verification/ui_url";
const SETTINGS = "/selfservice/flows/settings/ui_url";
const ERROR = "/selfservice/flows/error/ui_url";
const DEFAULT_RETURN = "/selfservice/default_browser_return_url";
const ALLOWED_RETURN = "/selfservice/allowed_return_urls";
// AX-04 — the Kratos public base URL / issuer (the custom-domain rebind target).
// Newly allowlisted on the backend ui-urls section; editable here and surfaced on
// the Custom Domains page.
const BASE_URL = "/serve/public/base_url";

// Each flow `ui_url`, the default browser return URL, and the public base URL is
// an optional string; `allowed_return_urls` is an array of strings (add/remove
// rows). The keys ARE the allowlisted JSON-Pointers — there is NO logout ui_url
// key (Pitfall 1).
const schema = z.object({
  [LOGIN]: z.string(),
  [REGISTRATION]: z.string(),
  [RECOVERY]: z.string(),
  [VERIFICATION]: z.string(),
  [SETTINGS]: z.string(),
  [ERROR]: z.string(),
  [DEFAULT_RETURN]: z.string(),
  [ALLOWED_RETURN]: z.array(z.string()),
  [BASE_URL]: z.string(),
}) as unknown as z.ZodType<Record<string, unknown>, Record<string, unknown>>;

const defaults: Record<string, unknown> = {
  [LOGIN]: "",
  [REGISTRATION]: "",
  [RECOVERY]: "",
  [VERIFICATION]: "",
  [SETTINGS]: "",
  [ERROR]: "",
  [DEFAULT_RETURN]: "",
  [ALLOWED_RETURN]: [],
  [BASE_URL]: "",
};

export default function UiUrlsPage() {
  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">
          UI URLs &amp; Redirects
        </h1>
        <p className="text-sm text-muted-foreground">
          Configure the self-service flow UI URLs, allowed return URLs, and the
          default browser return URL. On save Kratos restarts.
        </p>
      </div>

      <ConfigSection
        section="ui-urls"
        schema={schema}
        defaults={defaults}
        title="UI URLs & Redirects"
        description="Point each self-service flow at your own UI and control where returns are allowed."
        saveLabel="Save URL config"
      >
        {(form) => (
          <div className="space-y-4">
            <PointerText
              form={form}
              pointer={LOGIN}
              label="Login UI URL"
              placeholder="https://your-ui.example/login"
              description="Where Kratos sends users to start the login flow."
            />
            <PointerText
              form={form}
              pointer={REGISTRATION}
              label="Registration UI URL"
              placeholder="https://your-ui.example/registration"
              description="Where Kratos sends users to start the registration flow."
            />
            <PointerText
              form={form}
              pointer={RECOVERY}
              label="Recovery UI URL"
              placeholder="https://your-ui.example/recovery"
              description="Where Kratos sends users to recover their account."
            />
            <PointerText
              form={form}
              pointer={VERIFICATION}
              label="Verification UI URL"
              placeholder="https://your-ui.example/verification"
              description="Where Kratos sends users to verify an address."
            />
            <PointerText
              form={form}
              pointer={SETTINGS}
              label="Settings UI URL"
              placeholder="https://your-ui.example/settings"
              description="Where Kratos sends users to manage their account."
            />
            <PointerText
              form={form}
              pointer={ERROR}
              label="Error UI URL"
              placeholder="https://your-ui.example/error"
              description="Where Kratos sends users when a flow fails."
            />
            <PointerText
              form={form}
              pointer={BASE_URL}
              label="Public base URL (issuer)"
              placeholder="https://accounts.your-domain.example/"
              description="The Kratos public base URL / issuer. Set this to your custom Account Experience domain. Also editable from Custom Domains."
            />
            <PointerText
              form={form}
              pointer={DEFAULT_RETURN}
              label="Default browser return URL"
              placeholder="https://your-ui.example/"
              description="Fallback redirect after a completed flow when no return URL is given."
            />
            <PointerStringList
              form={form}
              pointer={ALLOWED_RETURN}
              label="Allowed return URL"
              placeholder="https://your-app.example/after-login"
              description="The allowlist of URLs a flow may redirect back to."
            />
          </div>
        )}
      </ConfigSection>
    </div>
  );
}
