import type { ReactNode } from "react";
import { redirect } from "next/navigation";
import { getMe } from "@/lib/server-api";
import { AppSidebar } from "@/components/app-sidebar";
import { AccountMenu } from "@/components/account-menu";
import {
  SidebarInset,
  SidebarProvider,
  SidebarTrigger,
} from "@/components/ui/sidebar";

// FE-01 — the authenticated console shell + the AUTHORITATIVE auth guard
// (05-RESEARCH Pattern 3, T-05-14; NOT proxy.ts per Pitfall 4).
//
// This is a server component. Before rendering any console page it fetches
// `GET /api/console/me` (forwarding the incoming HttpOnly session cookie) via
// getMe(); if unauthenticated (null) it `redirect("/login")` BEFORE any UI is
// produced. There is intentionally NO middleware.ts / proxy.ts auth gate — the
// HttpOnly `__Host-console_session` cookie's validity can only be confirmed by
// the backend, so the server-layout fetch is the single source of truth.
//
// On success it renders the UI-SPEC shell: a grouped sidebar (collapses to a
// drawer < md), a topbar (sidebar trigger + console title + account menu with
// logout + theme toggle), and the page content. The operator's csrf_token (from
// /me) is handed to the AccountMenu so the logout mutation can attach it.

export default async function ConsoleLayout({
  children,
}: {
  children: ReactNode;
}) {
  const me = await getMe();
  if (!me) redirect("/login");

  return (
    <SidebarProvider>
      <AppSidebar />
      <SidebarInset>
        <header className="flex h-14 shrink-0 items-center gap-2 border-b px-4">
          <SidebarTrigger className="-ml-1" />
          <span className="text-sm font-medium">Ory Console — self-hosted</span>
          <div className="ml-auto">
            <AccountMenu email={me.email} csrfToken={me.csrf_token} />
          </div>
        </header>
        <main className="mx-auto w-full max-w-6xl flex-1 overflow-auto p-6">
          {children}
        </main>
      </SidebarInset>
    </SidebarProvider>
  );
}
