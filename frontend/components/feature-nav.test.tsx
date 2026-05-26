import { render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

// FLAG-02 — the sidebar nav-filter contract (UI-SPEC §2):
//   - an item carrying `requiresFlag` is HIDDEN when that flag is OFF;
//   - an item with no `requiresFlag` is ALWAYS present;
//   - while the features query is PENDING (`data` undefined) the requiresFlag
//     item is STILL shown — the unfiltered nav renders to avoid a layout flash
//     (no spinner).
//
// We stub `@/lib/features` per-case and assert by each item's unique href, since
// labels collide across groups (see app-sidebar.test.tsx). The flag-gated probe
// is "/authentication/saml" (requiresFlag "saml"); a no-flag control is
// "/users".

vi.mock("next/navigation", () => ({
  usePathname: () => "/users",
}));

const featuresMock = vi.fn();
vi.mock("@/lib/features", () => ({
  useFeatures: () => featuresMock(),
}));

import { AppSidebar } from "./app-sidebar";
import { SidebarProvider } from "@/components/ui/sidebar";

const SAML_HREF = "/authentication/saml"; // requiresFlag: "saml"
const NO_FLAG_HREF = "/users"; // no requiresFlag — always renders

function renderSidebar() {
  return render(
    <SidebarProvider>
      <AppSidebar />
    </SidebarProvider>,
  );
}

afterEach(() => {
  vi.clearAllMocks();
});

describe("Sidebar feature-flag nav filtering", () => {
  it("HIDES a requiresFlag item when its flag is OFF", () => {
    featuresMock.mockReturnValue({
      data: {
        features: {
          saml: { enabled: false, label: "SAML Sign-In" },
        },
      },
    });
    const { container } = renderSidebar();
    expect(container.querySelector(`a[href="${SAML_HREF}"]`)).toBeNull();
    // A no-flag item is unaffected and still renders.
    expect(
      container.querySelector(`a[href="${NO_FLAG_HREF}"]`),
    ).toBeInTheDocument();
  });

  it("SHOWS a requiresFlag item when its flag is ON", () => {
    featuresMock.mockReturnValue({
      data: {
        features: {
          saml: { enabled: true, label: "SAML Sign-In" },
        },
      },
    });
    const { container } = renderSidebar();
    expect(
      container.querySelector(`a[href="${SAML_HREF}"]`),
    ).toBeInTheDocument();
  });

  it("ALWAYS shows an item with no requiresFlag (even when flags are loaded)", () => {
    featuresMock.mockReturnValue({
      data: {
        features: {
          saml: { enabled: false, label: "SAML Sign-In" },
        },
      },
    });
    const { container } = renderSidebar();
    expect(
      container.querySelector(`a[href="${NO_FLAG_HREF}"]`),
    ).toBeInTheDocument();
  });

  it("renders the requiresFlag item while the query is PENDING (no flash)", () => {
    // data undefined → pending → unfiltered nav (UI-SPEC §2).
    featuresMock.mockReturnValue({ data: undefined });
    const { container } = renderSidebar();
    expect(
      container.querySelector(`a[href="${SAML_HREF}"]`),
    ).toBeInTheDocument();
    expect(
      container.querySelector(`a[href="${NO_FLAG_HREF}"]`),
    ).toBeInTheDocument();
  });
});
