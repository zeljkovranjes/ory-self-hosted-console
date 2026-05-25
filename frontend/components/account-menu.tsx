"use client";

import { ChevronDown, LogOut } from "lucide-react";
import { useState } from "react";
import { api, setCsrfToken } from "@/lib/api";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { ThemeToggle } from "@/components/theme-toggle";

// FE-01 — topbar account menu (UI-SPEC §1/§4).
//
// Shows the authenticated operator's email, the light/dark theme toggle, and a
// Logout action. Logout POSTs `/logout` via lib/api.ts, which attaches the
// `X-CSRF-Token` header (T-05-18) from the CSRF token seeded after /me. On
// success we clear the cached token and navigate to /login.

type AccountMenuProps = {
  email: string;
  /** CSRF token from the server /me fetch; seeded so logout can mutate. */
  csrfToken: string;
};

export function AccountMenu({ email, csrfToken }: AccountMenuProps) {
  const [busy, setBusy] = useState(false);

  // Seed the CSRF token at render so the logout mutation carries it. The token
  // came from the server-side /me fetch (passed down by the layout); the client
  // wrapper needs it in its module cache.
  if (typeof window !== "undefined" && csrfToken) setCsrfToken(csrfToken);

  async function onLogout() {
    setBusy(true);
    try {
      await api("/logout", { method: "POST" });
    } catch {
      // Even if the call fails, drop the operator at /login (the session may
      // already be gone). The (console) guard re-checks on the next request.
    } finally {
      setCsrfToken(null);
      window.location.assign("/login");
    }
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" className="gap-2" aria-label="Account menu">
          <span className="max-w-[16rem] truncate text-sm">{email}</span>
          <ChevronDown className="size-4 opacity-60" aria-hidden />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-56">
        <DropdownMenuLabel className="font-normal">
          <span className="text-muted-foreground block text-xs">
            Signed in as
          </span>
          <span className="truncate">{email}</span>
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuLabel className="text-muted-foreground text-xs font-normal">
          Theme
        </DropdownMenuLabel>
        <ThemeToggle />
        <DropdownMenuSeparator />
        <DropdownMenuItem
          onSelect={(e) => {
            e.preventDefault();
            void onLogout();
          }}
          disabled={busy}
          variant="destructive"
        >
          <LogOut className="size-4" aria-hidden />
          {busy ? "Signing out…" : "Log out"}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
