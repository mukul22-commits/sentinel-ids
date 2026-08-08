import { expect, test } from "@playwright/test";
import { appBaseUrl, createAuthenticatedUser, seedTokens } from "./helpers/auth";

/**
 * There is no dedicated /alerts route in the frontend (see App.tsx), so the
 * alerts surface is exercised on the dashboard: the "Unread alerts" KPI widget
 * and the "Recent incidents" feed (which renders an empty state or rows).
 */
test.describe("alerts", () => {
  test("renders the alerts widget with an empty state or incident feed", async ({
    page,
    request,
  }) => {
    const { tokens } = await createAuthenticatedUser(request, appBaseUrl(test.info()));
    await seedTokens(page, tokens);

    await page.goto("/");

    await expect(page.getByRole("heading", { name: "Operations dashboard" })).toBeVisible();

    await expect(page.getByText("Unread alerts", { exact: true })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Recent incidents" })).toBeVisible();

    const emptyState = page.getByText("No incidents yet. Create one from the Incidents page.");
    const recentRows = page
      .locator("ul")
      .filter({ has: page.locator("a[href^='/incidents/']") });

    await expect(emptyState.or(recentRows.first())).toBeVisible();
  });
});
