/** 自動通報原本の再認証前後の案内・フォーム表示と送信を隔離ブラウザーで確認する。 */
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { mkdir } from "node:fs/promises";

const { chromium } = createRequire(import.meta.url)(process.env.OIMO_PLAYWRIGHT);
const browser = await chromium.launch({ headless: true, executablePath: process.env.OIMO_CHROMIUM, args: ["--no-sandbox"] });
try {
  const context = await browser.newContext();
  const page = await context.newPage();
  const target = process.env.OIMO_REPORT_REVIEW_URL;
  const origin = new URL(target).origin;
  await page.goto(`${origin}/login`);
  await page.locator('[name="login"]').fill("owner");
  await page.locator('[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
  await Promise.all([page.waitForURL(`${origin}/`), page.locator('button[type="submit"]').click()]);
  await page.goto(target);
  assert.equal(await page.locator('form[action$="/inspect"]').count(), 0);
  const reauth = page.getByRole("link", { name: "原本の閲覧・規制の適用には再認証が必要です。再認証してこの画面へ戻る" });
  assert.ok(await reauth.isVisible());
  for (const width of [320, 1024]) {
    await page.setViewportSize({ width, height: 900 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    if (process.env.OIMO_REPORT_REVIEW_SCREENSHOTS) {
      await mkdir(process.env.OIMO_REPORT_REVIEW_SCREENSHOTS, { recursive: true });
      await page.screenshot({ path: `${process.env.OIMO_REPORT_REVIEW_SCREENSHOTS}/reauth-${width}.png`, fullPage: true });
    }
  }
  await reauth.click();
  await page.locator('[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
  await Promise.all([page.waitForURL(target), page.locator('button[type="submit"]').click()]);
  const inspect = page.locator('form[action$="/inspect"] button');
  assert.ok(await inspect.isVisible());
  const [response] = await Promise.all([page.waitForNavigation(), inspect.click()]);
  assert.equal(response.status(), 200);
  assert.ok((await page.locator("main").textContent()).includes("保持されていない"));
  console.log("PASS: auto-report reauthentication link at 320/1024px, protected form and return/inspect flow");
} finally {
  await browser.close();
}
