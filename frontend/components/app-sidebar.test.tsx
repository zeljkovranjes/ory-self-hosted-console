import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { AppSidebar } from "./app-sidebar";
import { SidebarProvider } from "@/components/ui/sidebar";
import { NAV_ITEMS } from "@/lib/nav";

// FE-01 shell test: the grouped sidebar renders every UI-SPEC nav section and
// highlights the active route (data-active) via usePathname().

vi.mock("next/navigation", () => ({
  usePathname: () => "/users",
}));

function renderSidebar() {
  return render(
    <SidebarProvider>
      <AppSidebar />
    </SidebarProvider>,
  );
}

describe("AppSidebar", () => {
  it("renders every nav section from the model", () => {
    renderSidebar();
    for (const item of NAV_ITEMS) {
      expect(
        screen.getByRole("link", { name: new RegExp(item.label, "i") }),
      ).toBeInTheDocument();
    }
  });

  it("renders the UI-SPEC core sections (Users, Authentication, OAuth2, Permissions, Branding, Project, Activity)", () => {
    renderSidebar();
    for (const label of [
      "Activity",
      "Users",
      "Authentication",
      "OAuth2",
      "Permissions",
      "Branding",
      "Project",
    ]) {
      expect(
        screen.getByRole("link", { name: new RegExp(label, "i") }),
      ).toBeInTheDocument();
    }
  });

  it("marks the active route with data-active", () => {
    renderSidebar();
    const usersLink = screen.getByRole("link", { name: /users/i });
    // SidebarMenuButton sets data-active on the rendered anchor (asChild).
    expect(usersLink).toHaveAttribute("data-active", "true");
    const oauthLink = screen.getByRole("link", { name: /oauth2/i });
    expect(oauthLink).toHaveAttribute("data-active", "false");
  });
});
