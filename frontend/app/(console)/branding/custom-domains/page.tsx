// BRAND-05 — Custom Domains (GATED). Custom domains are not a self-hosted
// console feature; domains are mapped at the reverse proxy / DNS layer in front
// of the stack. The CTA links to EXTERNAL reverse-proxy / DNS guidance
// (10-UI-SPEC §F). This is a labeled explanation, never a dead CRUD form.

import { GatedFeature } from "@/components/gated-feature";

export default function CustomDomainsPage() {
  return (
    <GatedFeature
      title="Custom Domains"
      badgeLabel="Not available in self-hosted Ory"
      explanation="Custom domains are not a self-hosted console feature. Domains are mapped at your reverse proxy / DNS layer in front of the stack."
      recommendation="Point your domain at the stack by configuring your reverse proxy and DNS records in front of the Ory services."
      cta={{
        label: "Read the reverse-proxy / DNS guidance",
        href: "https://www.ory.sh/docs/self-hosted/deployment",
        external: true,
      }}
    />
  );
}
