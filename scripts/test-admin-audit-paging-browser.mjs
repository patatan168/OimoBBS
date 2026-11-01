/** 大量の管理操作を未選択で開き、既定50件の表示と次ページへの実移動を検証する。 */
import assert from "node:assert/strict";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const { chromium } = require(process.env.OIMO_PLAYWRIGHT);
const browser = await chromium.launch({ headless: true, executablePath: process.env.OIMO_CHROMIUM, args: ["--no-sandbox"] });
try {
  const page = await browser.newPage();
  const errors = [];
  page.on("pageerror", error => errors.push(error.message));
  const base = process.env.OIMO_AUDIT_URL;
  await page.goto(`${base}/login`);
  await page.locator('input[name="login"]').fill("owner");
  await page.locator('input[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
  await Promise.all([page.waitForURL(`${base}/`), page.locator('button[type="submit"]').click()]);
  const response = await page.goto(`${base}/audit`);
  assert.equal(response.status(), 200);
  assert.equal(await page.locator(".audit-table tbody tr").count(), 50);
  assert.equal(await page.locator('select[name="actor"]').inputValue(), "");
  assert.equal(await page.locator('input[name="board"]:checked').count(), 0);
  assert.ok((await page.locator("#audit-results-heading").textContent()).includes(`全${process.env.OIMO_AUDIT_TOTAL}件`));
  const first = await page.locator('.audit-details dt:text-is("操作ID") + dd code').allTextContents();
  assert.equal(first.length, 50);
  await Promise.all([page.waitForURL(url => url.searchParams.has("cursor")), page.getByRole("link", { name: "次のページ", exact: true }).click()]);
  const second = await page.locator('.audit-details dt:text-is("操作ID") + dd code').allTextContents();
  assert.equal(second.length, 50);
  assert.equal(second.some(id => first.includes(id)), false);
  assert.equal(await page.locator('[role="alert"]').count(), 0);
  await page.setViewportSize({ width: 390, height: 900 });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  assert.deepEqual(errors, []);
  console.log("PASS: unfiltered 2000+ entries, 50 rows/page, distinct next page, no error or 390px overflow");
} finally {
  await browser.close();
}
