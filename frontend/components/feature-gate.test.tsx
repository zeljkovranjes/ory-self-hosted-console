import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

// FLAG-03 — FeatureGate component test (carries the retired license-gate
// invariant).
//
// The load-bearing invariant (carried verbatim from the retired license-gate
// test) is that the OFF state is a calm EXPLANATION with a single navigational
// link — NEVER a dead/disabled CRUD form. We assert ZERO form controls of any
// kind (no textbox/combobox/checkbox/spinbutton/switch, no form/input/select/
// textarea/button[type=submit]) and exactly one link to /project/features. The
// ON state renders children; the pending state renders nothing.

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

    // ZERO form controls (the child form is gated out entirely).
    expect(screen.queryByRole("textbox")).toBeNull();
    expect(screen.queryByRole("combobox")).toBeNull();
    expect(screen.queryByRole("checkbox")).toBeNull();
    expect(screen.queryByRole("spinbutton")).toBeNull();
    expect(screen.queryByRole("switch")).toBeNull();
    expect(container.querySelector("form")).toBeNull();
    expect(container.querySelector("input")).toBeNull();
    expect(container.querySelector("select")).toBeNull();
    expect(container.querySelector("textarea")).toBeNull();
    expect(container.querySelector('button[type="submit"]')).toBeNull();
    expect(container.querySelector("button")).toBeNull();
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
