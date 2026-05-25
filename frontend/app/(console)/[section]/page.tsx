import { notFound } from "next/navigation";
import { Construction } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { findNavItem } from "@/lib/nav";

// FE-01 — placeholder page for known-but-unbuilt console sections (UI-SPEC §6).
//
// Every sidebar item routes within the (console) group. Sections whose feature
// pages land in P6–P11 resolve here: we look the slug up in lib/nav.ts and
// render a clearly-labeled "Coming in a later phase" panel (never a fake-working
// control). Unknown slugs 404 via notFound(). A section that has been built in a
// later phase will have its own route segment, which takes precedence over this
// catch-all.

export default async function SectionPlaceholderPage({
  params,
}: {
  params: Promise<{ section: string }>;
}) {
  const { section } = await params;
  const item = findNavItem(section);
  if (!item) notFound();

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">{item.label}</h1>
        <p className="text-muted-foreground text-sm">
          This section is part of the Ory console.
        </p>
      </div>
      <Alert>
        <Construction aria-hidden />
        <AlertTitle>Coming in a later phase</AlertTitle>
        <AlertDescription>
          The {item.label} page is not built yet
          {item.comingIn ? ` — it arrives in ${item.comingIn}` : ""}. The
          navigation entry is shown so the console shell is complete.
        </AlertDescription>
      </Alert>
    </div>
  );
}
