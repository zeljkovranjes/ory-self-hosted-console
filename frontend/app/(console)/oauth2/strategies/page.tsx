"use client";

// OAUTH2-07 — Token Strategies & PKCE (08-UI-SPEC §E, 08-RESEARCH Page 5).
//
// Access-token strategy, scope strategy, JWT scope claim, PKCE enforcement, and
// the JWT-bearer grant options. Enum keys use Selects; booleans use Switches;
// max_ttl is a duration string. Enum-value validity is enforced server-side too.

import { z } from "zod";

import {
  ConfigSection,
  ACCESS_TOKEN_STRATEGY_VALUES,
  SCOPE_STRATEGY_VALUES,
  SCOPE_CLAIM_VALUES,
  HYDRA_DURATION_REGEX,
} from "../_lib/config-section";
import {
  PointerSelect,
  PointerSwitch,
  PointerText,
} from "../../authentication/_lib/controls";

const ACCESS_TOKEN = "/strategies/access_token";
const SCOPE = "/strategies/scope";
const SCOPE_CLAIM = "/strategies/jwt/scope_claim";
const PKCE_ENFORCED = "/oauth2/pkce/enforced";
const PKCE_PUBLIC = "/oauth2/pkce/enforced_for_public_clients";
const JTI_OPTIONAL = "/oauth2/grant/jwt/jti_optional";
const IAT_OPTIONAL = "/oauth2/grant/jwt/iat_optional";
const MAX_TTL = "/oauth2/grant/jwt/max_ttl";

const schema = z.object({
  [ACCESS_TOKEN]: z.enum(ACCESS_TOKEN_STRATEGY_VALUES),
  [SCOPE]: z.enum(SCOPE_STRATEGY_VALUES),
  [SCOPE_CLAIM]: z.enum(SCOPE_CLAIM_VALUES),
  [PKCE_ENFORCED]: z.boolean(),
  [PKCE_PUBLIC]: z.boolean(),
  [JTI_OPTIONAL]: z.boolean(),
  [IAT_OPTIONAL]: z.boolean(),
  [MAX_TTL]: z.union([
    z.literal(""),
    z.string().regex(HYDRA_DURATION_REGEX, "Enter a duration like 1h or 720h"),
  ]),
}) as unknown as z.ZodType<Record<string, unknown>, Record<string, unknown>>;

const defaults: Record<string, unknown> = {
  [ACCESS_TOKEN]: "opaque",
  [SCOPE]: "wildcard",
  [SCOPE_CLAIM]: "list",
  [PKCE_ENFORCED]: false,
  [PKCE_PUBLIC]: false,
  [JTI_OPTIONAL]: false,
  [IAT_OPTIONAL]: false,
  [MAX_TTL]: "",
};

export default function StrategiesPage() {
  return (
    <ConfigSection
      service="hydra"
      section="strategies"
      schema={schema}
      defaults={defaults}
      title="Token Strategies & PKCE"
      description="Access-token strategy, scope strategy, and PKCE enforcement."
    >
      {(form) => (
        <div className="space-y-4">
          <PointerSelect
            form={form}
            pointer={ACCESS_TOKEN}
            label="Access token strategy"
            options={ACCESS_TOKEN_STRATEGY_VALUES}
            description="opaque (introspection) or jwt (self-contained)."
          />
          <PointerSelect
            form={form}
            pointer={SCOPE}
            label="Scope strategy"
            options={SCOPE_STRATEGY_VALUES}
            description="exact matches verbatim; wildcard allows hierarchical scopes."
          />
          <PointerSelect
            form={form}
            pointer={SCOPE_CLAIM}
            label="JWT scope claim format"
            options={SCOPE_CLAIM_VALUES}
            description="How the scope claim is encoded in JWT access tokens."
          />
          <PointerSwitch
            form={form}
            pointer={PKCE_ENFORCED}
            label="Enforce PKCE (all clients)"
          />
          <PointerSwitch
            form={form}
            pointer={PKCE_PUBLIC}
            label="Enforce PKCE for public clients"
          />
          <PointerSwitch
            form={form}
            pointer={JTI_OPTIONAL}
            label="JWT grant: jti optional"
            description="Allow JWT-bearer assertions without a jti claim."
          />
          <PointerSwitch
            form={form}
            pointer={IAT_OPTIONAL}
            label="JWT grant: iat optional"
            description="Allow JWT-bearer assertions without an iat claim."
          />
          <PointerText
            form={form}
            pointer={MAX_TTL}
            label="JWT grant: maximum assertion age"
            placeholder="720h"
            description="Maximum age of a JWT-bearer assertion (duration)."
          />
        </div>
      )}
    </ConfigSection>
  );
}
