import type { LucideIcon } from "lucide-react";
import {
  Activity,
  Fingerprint,
  KeyRound,
  Mail,
  Palette,
  RefreshCw,
  RotateCcw,
  Settings,
  ShieldCheck,
  ShieldQuestion,
  Smartphone,
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
    label: "Overview",
    items: [
      {
        slug: "activity",
        label: "Activity",
        href: "/activity",
        icon: Activity,
        built: false,
        comingIn: "Phase 10",
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
    label: "Access",
    items: [
      {
        slug: "oauth2",
        label: "OAuth2",
        href: "/oauth2",
        icon: KeyRound,
        built: false,
        comingIn: "Phase 8",
      },
      {
        slug: "permissions",
        label: "Permissions",
        href: "/permissions",
        icon: ShieldCheck,
        built: false,
        comingIn: "Phase 9",
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
