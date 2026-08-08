import { expect, test } from "@playwright/test";
import {
  appBaseUrl,
  createAuthenticatedUser,
  createIncidentViaApi,
  seedTokens,
} from "./helpers/auth";

test.describe("incidents", () => {
  test("lists incidents and opens the detail page from a row", async ({ page, request }) => {
    const base = appBaseUrl(test.info());
    const { tokens } = await createAuthenticatedUser(request, base);

    const title = `e2e incident ${Date.now()} ${Math.random().toString(36).slice(2, 6)}`;
    const created = await createIncidentViaApi(request, base, tokens.access_token, title);

    await seedTokens(page, tokens);
    await page.goto("/incidents");

    await expect(page.getByRole("heading", { name: "Incidents" })).toBeVisible();
    await expect(page.getByText("ID", { exact: true })).toBeVisible();
    await expect(page.getByText("Title", { exact: true })).toBeVisible();

    if (created) {
      const row = page.getByRole("link", { name: title });
      await expect(row.first()).toBeVisible();
      await row.first().click();

      await expect(page).toHaveURL(new RegExp(`/incidents/${created.id}$`));
      await expect(page.getByRole("heading", { name: "Timeline" })).toBeVisible();
      await expect(page.getByRole("heading", { name: "Response actions" })).toBeVisible();
    } else {
      await expect(page.getByText("No incidents match the current filters.")).toBeVisible();
    }
  });
});
