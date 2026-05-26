import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

// FLAG-03 — FeatureGate component test (carries the retired license-gate
// invariant).
//
// The load-bearing invariant (carried verbatim from the retired license-gate
// test) is that the OFF state is a calm EXPLANATION with a single navigational
// link — NEVER a dead/disabled CRUD form. WR-03: we enforce this with an
// ALLOWLIST — the ONLY interactive element in the OFF body must be exactly the
// one link to /project/features — rather than a denylist of forbidden control
// types (which any new control type would silently slip past). The ON state
// renders children; the pending state renders nothing.

const featuresMock = vi.fn();
vi.mock("@/lib/features", () => ({
  useFeatures: () => featuresMock(),
}));

import { FeatureGate } from "./feature-gate";

afterEach(() => {
  vi.clearAllMocks();
});

describe("FeatureGate", () => {
  it("OFF: renders the neutral disabled state with ZERO form controls", () => {
    featuresMock.mockReturnValue({
      data: { features: { saml: { enabled: false, label: "SAML Sign-In" } } },
    });
    const { container } = render(
      <FeatureGate flag="saml" title="SAML Sign-In">
        <form>
          <input aria-label="child input" />
        </form>
      </FeatureGate>,
    );

    // The neutral copy renders; NO license/Enterprise language.
    expect(screen.getByText("This feature is disabled")).toBeInTheDocument();
    expect(screen.queryByText(/enterprise/i)).toBeNull();
    expect(screen.queryByText(/license/i)).toBeNull();

    // WR-03 — ALLOWLIST, not a denylist. The hard FLAG-03 invariant is "the OFF
    // state is a calm explanation whose ONLY interactive element is the single
    // navigational link." Rather than enumerate specific control types to forbid
    // (a denylist any new control type — role="slider", a <details> disclosure, a
    // shadcn Toggle, an <a> styled as a button — would silently pass), we
    // POSITIVELY assert that EVERY interactive element in the rendered OFF body is
    // exactly the one expected link to /project/features. Any added control of any
    // kind makes this length check fail.
    const interactive = container.querySelectorAll(
      [
        "a",
        "button",
        "input",
        "select",
        "textarea",
        "[contenteditable='true']",
        '[role="button"]',
        '[role="link"]',
        '[role="textbox"]',
        '[role="combobox"]',
        '[role="checkbox"]',
        '[role="radio"]',
        '[role="spinbutton"]',
        '[role="switch"]',
        '[role="slider"]',
        '[role="menuitem"]',
        '[role="tab"]',
        '[tabindex]:not([tabindex="-1"])',
      ].join(","),
    );
    expect(interactive).toHaveLength(1);
    expect(interactive[0].tagName).toBe("A");
    expect(interactive[0]).toHaveAttribute("href", "/project/features");

    // And, specifically, the gated child <form>/<input> are absent entirely (the
    // body is rebuilt from neutral primitives, never the disabled child controls).
    expect(container.querySelector("form")).toBeNull();
    expect(container.querySelector("input")).toBeNull();
  });

  it("OFF: the only interactive element is a single link to /project/features", () => {
    featuresMock.mockReturnValue({
      data: { features: { saml: { enabled: false, label: "SAML Sign-In" } } },
    });
    render(
      <FeatureGate flag="saml" title="SAML Sign-In">
        <div>real body</div>
      </FeatureGate>,
    );
    const links = screen.getAllByRole("link");
    expect(links).toHaveLength(1);
    expect(links[0]).toHaveAttribute("href", "/project/features");
    expect(links[0]).not.toHaveAttribute("target", "_blank");
  });

  it("ON: renders children (the real feature body)", () => {
    featuresMock.mockReturnValue({
      data: { features: { saml: { enabled: true, label: "SAML Sign-In" } } },
    });
    render(
      <FeatureGate flag="saml" title="SAML Sign-In">
        <div>real saml body</div>
      </FeatureGate>,
    );
    expect(screen.getByText("real saml body")).toBeInTheDocument();
    // No disabled-state copy when ON.
    expect(screen.queryByText("This feature is disabled")).toBeNull();
  });

  it("pending: renders nothing (no flash of the disabled card)", () => {
    featuresMock.mockReturnValue({ data: undefined });
    const { container } = render(
      <FeatureGate flag="saml" title="SAML Sign-In">
        <div>real saml body</div>
      </FeatureGate>,
    );
    expect(container).toBeEmptyDOMElement();
    expect(screen.queryByText("This feature is disabled")).toBeNull();
    expect(screen.queryByText("real saml body")).toBeNull();
  });
});
