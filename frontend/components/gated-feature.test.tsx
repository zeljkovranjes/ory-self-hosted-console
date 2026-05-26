import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

// Component test for the GatedFeature primitive (BRAND-04/05/06, 10-UI-SPEC §F).
//
// The load-bearing invariant (success criterion 3) is that a gated page is a
// labeled EXPLANATION with a real-alternative link — NEVER a dead/disabled CRUD
// form. So beyond asserting the copy + CTA render, we assert there are ZERO form
// controls of any kind (no textbox, combobox, checkbox, spinbutton, or submit
// button). The CTA must be a LINK, not a submit button.

import { GatedFeature } from "./gated-feature";

const PROPS = {
  title: "Localization",
  badgeLabel: "Not available in self-hosted Ory",
  explanation:
    "Self-hosted Ory has no central localization API. Localization is handled per message through the courier email and SMS templates.",
  recommendation: "Edit your courier templates to localize copy.",
  cta: {
    label: "Edit your email and SMS templates",
    href: "/branding/email-templates",
  },
};

describe("GatedFeature", () => {
  it("renders the explanation and recommendation copy", () => {
    render(<GatedFeature {...PROPS} />);
    expect(screen.getByText(PROPS.explanation)).toBeInTheDocument();
    expect(screen.getByText(PROPS.recommendation)).toBeInTheDocument();
    // The neutral "not available" label appears (badge + alert title).
    expect(screen.getAllByText(PROPS.badgeLabel).length).toBeGreaterThan(0);
  });

  it("renders an internal CTA link with the correct href", () => {
    render(<GatedFeature {...PROPS} />);
    const link = screen.getByRole("link", { name: PROPS.cta.label });
    expect(link).toBeInTheDocument();
    expect(link).toHaveAttribute("href", "/branding/email-templates");
    // Internal links do not open a new tab.
    expect(link).not.toHaveAttribute("target", "_blank");
  });

  it("renders an external CTA as an anchor with safe rel/target", () => {
    render(
      <GatedFeature
        {...PROPS}
        cta={{
          label: "Read the reverse-proxy / DNS guidance",
          href: "https://www.ory.sh/docs",
          external: true,
        }}
      />,
    );
    const link = screen.getByRole("link", {
      name: "Read the reverse-proxy / DNS guidance",
    });
    expect(link).toHaveAttribute("href", "https://www.ory.sh/docs");
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", expect.stringContaining("noopener"));
  });

  it("renders NO form controls (never a dead/disabled CRUD form)", () => {
    render(<GatedFeature {...PROPS} />);
    // Zero inputs / selects / textareas / checkboxes / number spinners.
    expect(screen.queryByRole("textbox")).toBeNull();
    expect(screen.queryByRole("combobox")).toBeNull();
    expect(screen.queryByRole("checkbox")).toBeNull();
    expect(screen.queryByRole("spinbutton")).toBeNull();
    expect(screen.queryByRole("switch")).toBeNull();
    // No raw form elements either.
    const { container } = render(<GatedFeature {...PROPS} />);
    expect(container.querySelector("form")).toBeNull();
    expect(container.querySelector("input")).toBeNull();
    expect(container.querySelector("select")).toBeNull();
    expect(container.querySelector("textarea")).toBeNull();
    expect(container.querySelector('button[type="submit"]')).toBeNull();
    // The only interactive control is the CTA link (a button styled as a link
    // via asChild renders as an <a>, so there is no <button> at all).
    expect(container.querySelector("button")).toBeNull();
  });
});
