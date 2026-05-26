import type { LucideIcon } from "lucide-react";
import {
  Cookie,
  FileCode2,
  Fingerprint,
  Inbox,
  KeyRound,
  Link2,
  Mail,
  MonitorSmartphone,
  Palette,
  RefreshCw,
  Route,
  RotateCcw,
  ScanSearch,
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
    label: "Console",
    items: [
      {
        slug: "branding",
        label: "Branding",
        href: "/branding",
        icon: Palette,
        built: false,
        comingIn: "Phase 10",
      },
      {
        slug: "project",
        label: "Project",
        href: "/project",
        icon: Settings,
        built: false,
        comingIn: "Phase 11",
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
