import type { LucideIcon } from "lucide-react";
import {
  Activity,
  Fingerprint,
  KeyRound,
  Palette,
  Settings,
  ShieldCheck,
  Users,
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
        built: false,
        comingIn: "Phase 6",
      },
      {
        slug: "authentication",
        label: "Authentication",
        href: "/authentication",
        icon: Fingerprint,
        built: false,
        comingIn: "Phase 7",
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
