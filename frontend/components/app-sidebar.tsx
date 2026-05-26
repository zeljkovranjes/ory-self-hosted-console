"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar";
import { NAV_GROUPS } from "@/lib/nav";
import { useFeatures } from "@/lib/features";

// FE-01 — the console grouped sidebar (UI-SPEC §1/§5).
//
// Renders NAV_GROUPS (Activity / Users / Authentication / OAuth2 / Permissions
// / Branding / Project). The shadcn Sidebar collapses to a sheet/drawer under
// `md` (handled by SidebarProvider + the trigger in the topbar). The active
// route is highlighted via `isActive` (data-active), driven by usePathname().
// Every item is keyboard-focusable (shadcn renders <a> via asChild + Next Link).
//
// FLAG-02 — items carrying `requiresFlag` are HIDDEN when that flag is OFF
// (GET /api/console/features via useFeatures). While the query is pending
// (`flags` undefined) the UNFILTERED nav renders so there is no layout flash and
// no spinner (UI-SPEC §2 / Pitfall 6). This is additive cosmetics only — the
// authoritative gate is the backend FeatureFlagHoop (T-12-08).

export function AppSidebar() {
  const pathname = usePathname();
  const { data } = useFeatures();
  const flags = data?.features;

  return (
    <Sidebar>
      <SidebarHeader className="px-4 py-3">
        <span className="text-sm font-semibold tracking-tight">
          Ory Console
        </span>
        <span className="text-muted-foreground text-xs">self-hosted</span>
      </SidebarHeader>
      <SidebarContent>
        {NAV_GROUPS.map((group) => (
          <SidebarGroup key={group.label}>
            <SidebarGroupLabel>{group.label}</SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                {group.items
                  .filter(
                    (item) =>
                      !item.requiresFlag ||
                      (flags ? flags[item.requiresFlag]?.enabled : true),
                  )
                  .map((item) => {
                  const active =
                    pathname === item.href ||
                    pathname.startsWith(`${item.href}/`);
                  const Icon = item.icon;
                  return (
                    <SidebarMenuItem key={item.slug}>
                      <SidebarMenuButton
                        asChild
                        isActive={active}
                        tooltip={item.label}
                      >
                        <Link href={item.href}>
                          <Icon aria-hidden />
                          <span>{item.label}</span>
                        </Link>
                      </SidebarMenuButton>
                    </SidebarMenuItem>
                  );
                })}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        ))}
      </SidebarContent>
    </Sidebar>
  );
}
