"use client";

import {
  isServer,
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import { ThemeProvider } from "next-themes";
import type { ReactNode } from "react";

// App-wide client providers (FE-05, 05-RESEARCH Pattern 7).
//
// - TanStack Query: the `isServer`-aware getQueryClient() avoids the
//   cross-request cache-leak pitfall (T-05-09 / Pitfall 6) — a fresh client is
//   made per server render, while the browser reuses a single singleton.
// - next-themes: class-based light/dark with system support (UI-SPEC §4); the
//   account-menu toggle (later plan) calls useTheme() to switch.
//
// Mounted once in the root layout. This component does NOT call lib/api.ts — the
// authenticated /me fetch and CSRF wiring happen in the (console) server layout
// (05-05); the root layout stays auth-agnostic so /setup and /login render too.

function makeQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        // Conservative default; feature pages override per-query as needed.
        staleTime: 60_000,
      },
    },
  });
}

let browserClient: QueryClient | undefined;

function getQueryClient(): QueryClient {
  // Server: always a fresh client (no shared module-level state across
  // requests). Browser: lazily create one singleton and reuse it.
  if (isServer) return makeQueryClient();
  return (browserClient ??= makeQueryClient());
}

export function Providers({ children }: { children: ReactNode }) {
  const queryClient = getQueryClient();
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider
        attribute="class"
        defaultTheme="system"
        enableSystem
        disableTransitionOnChange
      >
        {children}
      </ThemeProvider>
    </QueryClientProvider>
  );
}
