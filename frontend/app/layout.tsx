import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";
import { Toaster } from "@/components/ui/sonner";
import { Providers } from "./providers";

export const metadata: Metadata = {
  title: "Ory Self-Hosted Console",
  description:
    "Self-hosted, single-tenant Ory Console — manage identities, OAuth2 clients, permissions, and service config against your own Ory stack.",
};

export default function RootLayout({
  children,
}: {
  children: ReactNode;
}) {
  // `suppressHydrationWarning` is required by next-themes: it writes the theme
  // class onto <html> before React hydrates, which would otherwise trip a
  // hydration mismatch warning. Providers supplies TanStack Query + the theme
  // context (isServer-aware, no cross-request leak); the sonner Toaster is the
  // single app-wide toast surface (UI-SPEC §3 transient success).
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="antialiased">
        <Providers>{children}</Providers>
        <Toaster />
      </body>
    </html>
  );
}
