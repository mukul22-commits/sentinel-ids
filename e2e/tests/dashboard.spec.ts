import { expect, test } from "@playwright/test";
import { appBaseUrl, createAuthenticatedUser, seedTokens } from "./helpers/auth";

test.describe("dashboard", () => {
  test("renders the app shell and stat cards for an authenticated user", async ({
    page,
    request,
  }) => {
    const { tokens } = await createAuthenticatedUser(request, appBaseUrl(test.info()));
    await seedTokens(page, tokens);

    await page.goto("/");

    await expect(page.getByRole("heading", { name: "Operations dashboard" })).toBeVisible();

    const nav = page.getByRole("navigation");
    await expect(nav).toBeVisible();
    for (const label of ["Dashboard", "Incidents", "Fleet", "Policies", "System", "Detection"]) {
      await expect(nav.getByRole("link", { name: label, exact: true })).toBeVisible();
    }

    await expect(page.getByText("Total incidents", { exact: true })).toBeVisible();
    await expect(page.getByText("Unread alerts", { exact: true })).toBeVisible();
  });
});
