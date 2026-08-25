import { expect, test } from "@playwright/test";

test.describe("KaiMS Simple and Detail views", () => {
  test.beforeEach(async ({ page }) => {
    await page.addInitScript(() => window.localStorage.removeItem("kaims.experience.view.v1"));
    await page.goto("/");
  });

  test("defaults to Simple View and exposes an accessible view switch", async ({ page }) => {
    await expect(page.locator("html")).toHaveAttribute("data-kai-view", "simple");
    const switcher = page.getByRole("group", { name: "Information density" });
    await expect(switcher).toBeVisible();
    await expect(switcher.getByRole("button", { name: "Simple" })).toHaveAttribute("aria-pressed", "true");
    await expect(switcher.getByRole("button", { name: "Detail" })).toHaveAttribute("aria-pressed", "false");
  });

  test("switches to Detail View and persists the preference", async ({ page }) => {
    const detail = page.getByRole("button", { name: "Detail" });
    await detail.click();
    await expect(page.locator("html")).toHaveAttribute("data-kai-view", "detail");
    await page.reload();
    await expect(page.locator("html")).toHaveAttribute("data-kai-view", "detail");
    await expect(page.getByRole("button", { name: "Detail" })).toHaveAttribute("aria-pressed", "true");
  });
});
