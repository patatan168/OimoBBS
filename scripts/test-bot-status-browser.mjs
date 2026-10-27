/** Bot対策の現在値・累計・未保存の選択・入力エラーを、隔離管理画面の実操作で検証する。 */
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { mkdir } from "node:fs/promises";
const require = createRequire(import.meta.url);
const { chromium } = require(process.env.OIMO_PLAYWRIGHT);
const browser = await chromium.launch({ headless: true, executablePath: process.env.OIMO_CHROMIUM, args: ["--no-sandbox"] });
try {
  const page = await browser.newPage();
  const errors = [];
  page.on("pageerror", error => errors.push(error.message));
  const base = process.env.OIMO_BOT_URL;
  await page.goto(`${base}/login`);
  await page.locator('input[name="login"]').fill("owner");
  await page.locator('input[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
  await Promise.all([page.waitForURL(`${base}/`), page.locator('button[type="submit"]').click()]);
  await page.goto(`${base}/abuse-guard`);
  const bot = page.locator("fieldset").first();
  const status = bot.locator(".bot-status");
  assert.equal(await status.locator(".bot-mode").textContent(), "自動で一時停止");
  assert.match(await status.textContent(), /停止中のCookie\s*1/);
  assert.match(await status.textContent(), /有効な違反履歴のCookie\s*2/);
  assert.match(await status.locator(".bot-totals").textContent(), /異なる違反9件停止条件の成立1回投稿の拒否1件/);
  await bot.locator('select[name="bot_mode"]').selectOption("observe");
  assert.equal(await status.locator(".bot-mode").textContent(), "自動で一時停止", "unsaved selection changed current mode");
  // ほかの項目の入力エラーでも、稼働中の値をゼロや未保存として表示しない。
  await page.getByText("類似文を検出する条件（詳細設定）", {exact:true}).click();
  await page.locator('input[name="similar_matches"]').fill("128");
  const rejected = page.waitForResponse(response => response.url() === `${base}/abuse-guard` && response.request().method() === "POST");
  await page.getByRole("button", { name: "全板共通の設定を保存", exact: true }).click();
  assert.equal((await rejected).status(), 422);
  await page.waitForLoadState("load");
  assert.equal(await status.count(), 0);
  assert.equal(await bot.locator('select[name="bot_mode"]').inputValue(), "observe");
  assert.ok((await bot.textContent()).includes("稼働状況を表示していません"));
  assert.ok(!(await page.locator("main").textContent()).includes("共通設定は未保存です"));
  await page.getByRole("link", { name: "最新の設定を読み直す", exact: true }).click();
  if (process.env.OIMO_BOT_SCREENSHOTS) await mkdir(process.env.OIMO_BOT_SCREENSHOTS, { recursive: true });
  for (const mode of ["reject", "observe", "off"]) {
    await bot.locator('select[name="bot_mode"]').selectOption(mode);
    await Promise.all([page.waitForResponse(response => response.url() === `${base}/abuse-guard` && response.status() === 303), page.getByRole("button", { name: "全板共通の設定を保存", exact: true }).click()]);
    await page.waitForLoadState("load");
    await page.waitForSelector(`.bot-mode-${mode}`);
    if (mode !== "reject") {
      assert.ok((await status.textContent()).includes("停止条件に該当するCookie"));
      assert.ok((await status.textContent()).includes("現在のモードでは停止しません"));
    }
    for (const width of [320, 390, 1024]) {
      await page.setViewportSize({ width, height: 1000 });
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `overflow: ${mode}/${width}`);
      assert.equal(await status.locator(".bot-metric").count(), 3);
      await bot.locator("summary").click();
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
      await bot.locator("summary").click();
      if (process.env.OIMO_BOT_SCREENSHOTS) await bot.screenshot({ path: `${process.env.OIMO_BOT_SCREENSHOTS}/bot-${mode}-${width}.png` });
    }
  }
  assert.deepEqual(errors, []);
  console.log("PASS: saved/unsaved modes, current/cumulative values, invalid form, and 320/390/1024px layouts");
} finally { await browser.close(); }
