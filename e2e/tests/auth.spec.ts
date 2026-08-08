import { expect, test } from "@playwright/test";
import {
  DEFAULT_PASSWORD,
  appBaseUrl,
  randomEmail,
  randomUsername,
  registerUser,
} from "./helpers/auth";

test.describe("authentication", () => {
  test("logs in with an API-registered user using email", async ({ page, request }) => {
    const user = await registerUser(request, appBaseUrl(test.info()));

    await page.goto("/login");
    await expect(page.getByRole("heading", { name: "SENTINEL IDS" })).toBeVisible();

    await page.getByLabel("Email or username").fill(user.email);
    await page.getByLabel("Password", { exact: true }).fill(user.password);
    await page.locator("form").getByRole("button", { name: "Sign in" }).click();

    await expect(page).toHaveURL(/\/$/);
    await expect(page.getByRole("heading", { name: "Operations dashboard" })).toBeVisible();
  });

  test("logs in with an API-registered user using username", async ({ page, request }) => {
    const user = await registerUser(request, appBaseUrl(test.info()));

    await page.goto("/login");
    await page.getByLabel("Email or username").fill(user.username);
    await page.getByLabel("Password", { exact: true }).fill(user.password);
    await page.locator("form").getByRole("button", { name: "Sign in" }).click();

    await expect(page.getByRole("heading", { name: "Operations dashboard" })).toBeVisible();
  });

  test("registers a new account through the signup form", async ({ page }) => {
    await page.goto("/login");
    await page.getByRole("button", { name: "Create account" }).click();

    await page.getByLabel("Email", { exact: true }).fill(randomEmail());
    await page.getByLabel("Username", { exact: true }).fill(randomUsername());
    await page.getByLabel("Password", { exact: true }).fill(DEFAULT_PASSWORD);
    await page.locator("form").getByRole("button", { name: "Create account" }).click();

    await expect(page.getByRole("heading", { name: "Operations dashboard" })).toBeVisible();
  });

  test("shows an error for invalid credentials and stays on the login page", async ({
    page,
    request,
  }) => {
    const user = await registerUser(request, appBaseUrl(test.info()));

    await page.goto("/login");
    await page.getByLabel("Email or username").fill(user.email);
    await page.getByLabel("Password", { exact: true }).fill("definitely-not-the-password");
    await page.locator("form").getByRole("button", { name: "Sign in" }).click();

    await expect(page.getByText("Invalid credentials")).toBeVisible();
    await expect(page).toHaveURL(/\/login/);
    await expect(page.getByRole("heading", { name: "SENTINEL IDS" })).toBeVisible();
  });
});
