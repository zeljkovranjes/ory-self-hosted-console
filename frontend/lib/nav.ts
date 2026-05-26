import type { LucideIcon } from "lucide-react";
import {
  Activity,
  Building2,
  Cookie,
  FileCode2,
  Fingerprint,
  Globe,
  Image,
  Inbox,
  KeyRound,
  Languages,
  LayoutDashboard,
  Link2,
  ListChecks,
  Mail,
  MonitorSmartphone,
  Paintbrush,
  Radio,
  RefreshCw,
  Route,
  RotateCcw,
  ScanSearch,
  ScrollText,
  Settings,
  ShieldCheck,
  ShieldQuestion,
  Smartphone,
  Sliders,
  Timer,
  ToggleLeft,
  Users,
  Webhook,
} from "lucide-react";

// FE-01 — the console navigation model (UI-SPEC §1).
//
// The sidebar groups every console section. Sections whose feature pages land in
// later phases (P6–P11) are marked `built: false`; they still render in the nav
// but route to the `(console)/[section]` "Coming in a later phase" placeholder.
// The dashboard ("/") is the only built landing surface in this phase.
//
// `slug` is the URL segment under the (console) group (`/users`, `/oauth2`, …);
// it is also the lookup key for the catch-all placeholder page.

export type NavItem = {
  slug: string;
  label: string;
  /** Absolute href within the (console) group. */
  href: string;
  icon: LucideIcon;
  /** Whether the destination feature page exists yet (this phase = false). */
  built: boolean;
  /** The phase that delivers the real page (for the placeholder copy). */
  comingIn?: string;
  /**
   * FLAG-02 — when set, the item is HIDDEN from the sidebar while this feature
   * flag is OFF (GET /api/console/features). Items with no `requiresFlag` always
   * render. This is additive cosmetics only; the authoritative gate is the
   * backend FeatureFlagHoop (T-12-08).
   */
  requiresFlag?: string;
};

export type NavGroup = {
  label: string;
  items: NavItem[];
};

export const NAV_GROUPS: NavGroup[] = [
  {
    // Phase 10 — the "Activity" group (10-UI-SPEC §G). Sessions is the Kratos
    // session DataTable (list/filter/detail/revoke); Courier Messages is the
    // read-only courier delivery-log DataTable. Both `built: true`. (The
    // Branding group is owned by Plans 02/03 and stays a placeholder here.)
    label: "Activity",
    items: [
      {
        slug: "activity-sessions",
        label: "Sessions",
        href: "/activity/sessions",
        icon: MonitorSmartphone,
        built: true,
      },
      {
        slug: "activity-courier",
        label: "Courier Messages",
        href: "/activity/courier",
        icon: Inbox,
        built: true,
      },
    ],
  },
  {
    label: "Identity",
    items: [
      {
        slug: "users",
        label: "Users",
        href: "/users",
        icon: Users,
        // Phase 6 delivered the real Users pages (list/detail/create/edit,
        // schema editor, bulk import), so /users routes to the feature, not the
        // "coming in a later phase" placeholder.
        built: true,
      },
    ],
  },
  {
    // Phase 7 — the grouped "Authentication" section (UI-SPEC §Pages). Each item
    // is a SettingsForm page bound to a Kratos config section via the Phase-4
    // engine. All 10 pages are `built: true` (the scalar pages ship in Plan 03;
    // the list/secret pages — social/smtp/sms/webhooks — ship in Plan 04, same
    // wave). Routes live under `/authentication/<slug>`.
    label: "Authentication",
    items: [
      {
        slug: "methods",
        label: "General / Methods",
        href: "/authentication/methods",
        icon: ToggleLeft,
        built: true,
      },
      {
        slug: "passwordless",
        label: "Passwordless & Passkeys",
        href: "/authentication/passwordless",
        icon: Fingerprint,
        built: true,
      },
      {
        slug: "mfa",
        label: "Two-Factor / MFA",
        href: "/authentication/mfa",
        icon: ShieldCheck,
        built: true,
      },
      {
        slug: "social",
        label: "Social Sign-In",
        href: "/authentication/social",
        icon: KeyRound,
        built: true,
      },
      {
        slug: "sessions",
        label: "Sessions",
        href: "/authentication/sessions",
        icon: RefreshCw,
        built: true,
      },
      {
        slug: "recovery",
        label: "Account Recovery",
        href: "/authentication/recovery",
        icon: RotateCcw,
        built: true,
      },
      {
        slug: "verification",
        label: "Account Verification",
        href: "/authentication/verification",
        icon: ShieldQuestion,
        built: true,
      },
      {
        slug: "smtp",
        label: "Email / SMTP",
        href: "/authentication/smtp",
        icon: Mail,
        built: true,
      },
      {
        slug: "sms",
        label: "SMS",
        href: "/authentication/sms",
        icon: Smartphone,
        built: true,
      },
      {
        slug: "webhooks",
        label: "Actions & Webhooks",
        href: "/authentication/webhooks",
        icon: Webhook,
        built: true,
      },
    ],
  },
  {
    // Phase 8 — the grouped "OAuth2" section (08-UI-SPEC §F). Clients is the
    // data-plane DataTable + CRUD; the Token & Flow Inspector and the six config
    // SettingsForm pages land in plans 02/03 (same phase) — the nav entries point
    // at them now so the section shell is complete. All `built: true`.
    label: "OAuth2",
    items: [
      {
        slug: "oauth2",
        label: "Clients",
        href: "/oauth2/clients",
        icon: KeyRound,
        built: true,
      },
      {
        slug: "oauth2-inspector",
        label: "Token & Flow Inspector",
        href: "/oauth2/inspector",
        icon: ScanSearch,
        built: true,
      },
      {
        slug: "oauth2-general",
        label: "General & Issuer",
        href: "/oauth2/general",
        icon: Settings,
        built: true,
      },
      {
        slug: "oauth2-oidc",
        label: "OIDC",
        href: "/oauth2/oidc",
        icon: ShieldCheck,
        built: true,
      },
      {
        slug: "oauth2-urls",
        label: "URLs",
        href: "/oauth2/urls",
        icon: Link2,
        built: true,
      },
      {
        slug: "oauth2-lifespans",
        label: "Token Lifespans",
        href: "/oauth2/lifespans",
        icon: Timer,
        built: true,
      },
      {
        slug: "oauth2-strategies",
        label: "Token Strategies",
        href: "/oauth2/strategies",
        icon: Sliders,
        built: true,
      },
      {
        slug: "oauth2-cookies",
        label: "Cookies",
        href: "/oauth2/cookies",
        icon: Cookie,
        built: true,
      },
    ],
  },
  {
    // Phase 9 — the "Permissions" section (09-UI-SPEC §E). Relationships is the
    // Keto relation-tuple DataTable + create/delete; Check & Expand is the
    // read-only check/expand panel; Permission Model is the OPL Monaco editor;
    // Access Rules is the Oathkeeper rules Monaco editor. All `built: true`.
    label: "Permissions",
    items: [
      {
        slug: "permissions",
        label: "Relationships",
        href: "/permissions/relationships",
        icon: ShieldCheck,
        built: true,
      },
      {
        slug: "permissions-check",
        label: "Check & Expand",
        href: "/permissions/check",
        icon: ScanSearch,
        built: true,
      },
      {
        slug: "permissions-model",
        label: "Permission Model",
        href: "/permissions/model",
        icon: FileCode2,
        built: true,
      },
      {
        slug: "permissions-access-rules",
        label: "Access Rules",
        href: "/permissions/access-rules",
        icon: Route,
        built: true,
      },
    ],
  },
  {
    // Phase 10 — the "Branding" group (10-UI-SPEC §G). Plan 02 shipped the two
    // kratos-config branding pages (Email Templates, UI URLs); Plan 03 appends
    // Console Logo (the console-OWNED asset upload) + the three flag-gated pages
    // (Localization, Custom Domains, Theming). As of Phase 12 (FLAG-02/03) the
    // three are tagged requiresFlag "account_experience": they are HIDDEN while
    // that flag is OFF and render a FeatureGate placeholder when ON.
    // All `built: true`.
    label: "Branding",
    items: [
      {
        slug: "branding-email-templates",
        label: "Email Templates",
        href: "/branding/email-templates",
        icon: Mail,
        built: true,
      },
      {
        slug: "branding-ui-urls",
        label: "UI URLs",
        href: "/branding/ui-urls",
        icon: Link2,
        built: true,
      },
      {
        slug: "branding-logo",
        label: "Console Logo",
        href: "/branding/logo",
        icon: Image,
        built: true,
      },
      {
        slug: "branding-localization",
        label: "Localization",
        href: "/branding/localization",
        icon: Languages,
        built: true,
        requiresFlag: "account_experience",
      },
      {
        slug: "branding-custom-domains",
        label: "Custom Domains",
        href: "/branding/custom-domains",
        icon: Globe,
        built: true,
        requiresFlag: "account_experience",
      },
      {
        slug: "branding-theming",
        label: "Theming",
        href: "/branding/theming",
        icon: Paintbrush,
        built: true,
        requiresFlag: "account_experience",
      },
    ],
  },
  {
    // Phase 11 — the "Project" group (11-UI-SPEC §I). Plan 04 ships the Overview
    // health dashboard, the Members (console-operator) list, Console API keys
    // (issue/reveal/revoke), the derived Activity stub, the read-only Logs &
    // events audit view, and the Event-streams stub. As of Phase 12 the
    // Event-streams and Organizations items are tagged requiresFlag
    // ("event_streams" / "organizations"): HIDDEN while OFF, FeatureGate
    // placeholder when ON. All `built: true`.
    label: "Project",
    items: [
      {
        slug: "project-overview",
        label: "Overview",
        href: "/project/overview",
        icon: LayoutDashboard,
        built: true,
      },
      {
        slug: "project-members",
        label: "Members",
        href: "/project/members",
        icon: Users,
        built: true,
      },
      {
        slug: "project-api-keys",
        label: "API keys",
        href: "/project/api-keys",
        icon: KeyRound,
        built: true,
      },
      {
        slug: "project-activity",
        label: "Activity",
        href: "/project/activity",
        icon: Activity,
        built: true,
      },
      {
        slug: "project-logs",
        label: "Logs & events",
        href: "/project/logs",
        icon: ScrollText,
        built: true,
      },
      {
        slug: "project-event-streams",
        label: "Event streams",
        href: "/project/event-streams",
        icon: Radio,
        built: true,
        requiresFlag: "event_streams",
      },
      {
        slug: "project-organizations",
        label: "Organizations",
        href: "/project/organizations",
        icon: Building2,
        built: true,
        requiresFlag: "organizations",
      },
    ],
  },
  {
    // Phase 11 — the "Actions" group (11-UI-SPEC §I). The console's own webhook
    // dispatcher (Plan 02: Webhooks CRUD + the Delivery log) plus the SAML
    // sign-in entry. As of Phase 12 the SAML item is tagged requiresFlag "saml":
    // HIDDEN while OFF, FeatureGate placeholder when ON. All `built: true`.
    label: "Actions",
    items: [
      {
        slug: "project-webhooks",
        label: "Webhooks",
        href: "/project/webhooks",
        icon: Webhook,
        built: true,
      },
      {
        slug: "project-webhooks-deliveries",
        label: "Delivery log",
        href: "/project/webhooks/deliveries",
        icon: ListChecks,
        built: true,
      },
      {
        slug: "authentication-saml",
        label: "SAML Sign-In",
        href: "/authentication/saml",
        icon: ShieldCheck,
        built: true,
        requiresFlag: "saml",
      },
    ],
  },
];

/** Flat list of every nav item (across groups). */
export const NAV_ITEMS: NavItem[] = NAV_GROUPS.flatMap((g) => g.items);

/** Look up a nav item by its URL slug, or `undefined` if no such section. */
export function findNavItem(slug: string): NavItem | undefined {
  return NAV_ITEMS.find((item) => item.slug === slug);
}
