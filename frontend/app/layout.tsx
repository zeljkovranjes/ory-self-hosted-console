import type { Metadata } from "next";
import type { ReactNode } from "react";

export const metadata: Metadata = {
  title: "Ory Self-Hosted Console",
  description:
    "Self-hosted, single-tenant Ory Console (Phase 1 skeleton — real shell lands in Phase 5).",
};

export default function RootLayout({
  children,
}: {
  children: ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
