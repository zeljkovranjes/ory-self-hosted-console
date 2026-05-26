// GatedFeature — the reusable "not a self-hosted OSS console primitive" page
// primitive (10-UI-SPEC §F; BRAND-04/05/06). Reused by Phase 11 for the
// Enterprise/Network gated pages (SAML/Orgs).
//
// SUCCESS CRITERION 3 (hard invariant): a gated page MUST be a clearly-labeled
// EXPLANATION with a link to the real alternative — it must NEVER render a dead
// or disabled CRUD form. This component is built ENTIRELY from already-vendored
// shadcn primitives (Card / Alert / Badge / Button-as-link) and renders NO form
// controls: no input, no select, no textarea, no submit. The accompanying
// `gated-feature.test.tsx` asserts zero form controls.

import Link from "next/link";
import { InfoIcon } from "lucide-react";

import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export type GatedFeatureCta = {
  /** The call-to-action label (e.g. "Edit your email and SMS templates"). */
  label: string;
  /** Where the CTA points — an internal app route or an external docs URL. */
  href: string;
  /**
   * When true the CTA is an external link (renders a plain anchor with
   * `target="_blank"` + `rel="noopener noreferrer"`) instead of a Next `Link`.
   */
  external?: boolean;
};

export type GatedFeatureProps = {
  /** Page heading (also the section title). */
  title: string;
  /** The neutral label on the informational badge (e.g. "Not available in self-hosted Ory"). */
  badgeLabel: string;
  /** Plain-language reason the feature is not a self-hosted OSS console primitive. */
  explanation: string;
  /** The recommended self-hosted approach. */
  recommendation: string;
  /** A single link to the real alternative or external docs. */
  cta: GatedFeatureCta;
};

/**
 * Render a labeled gated-feature explanation page. Composed of the standard page
 * shell (`space-y-6` + `h1`/`p`), an informational `Alert` (default variant —
 * NOT destructive, NOT success), a neutral `Badge`, and a single CTA link
 * rendered as a `Button asChild` wrapping a Next `Link` (internal) or anchor
 * (external). No form controls of any kind.
 */
export function GatedFeature({
  title,
  badgeLabel,
  explanation,
  recommendation,
  cta,
}: GatedFeatureProps) {
  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
          <Badge variant="secondary">{badgeLabel}</Badge>
        </div>
        <p className="text-sm text-muted-foreground">
          This is not a self-hosted Ory console feature.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{title}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4 pt-4">
          <Alert role="status" aria-live="polite">
            <InfoIcon />
            <AlertTitle>{badgeLabel}</AlertTitle>
            <AlertDescription>{explanation}</AlertDescription>
          </Alert>

          <p className="text-sm text-muted-foreground">{recommendation}</p>

          <Button asChild>
            {cta.external ? (
              <a href={cta.href} target="_blank" rel="noopener noreferrer">
                {cta.label}
              </a>
            ) : (
              <Link href={cta.href}>{cta.label}</Link>
            )}
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
