/** 隔離サーバーでWebの一時パスワード発行から本人の変更・再ログインまで確認する。 */
import assert from "node:assert/strict";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const { chromium } = require(process.env.OIMO_PLAYWRIGHT);
const browser = await chromium.launch({ headless: true, executablePath: process.env.OIMO_CHROMIUM, args: ["--no-sandbox"] });
const base = process.env.OIMO_PASSKEY_URL;
try {
  const owner = await browser.newPage();
  const errors = [];
  owner.on("pageerror", error => errors.push(error.message));
  await owner.goto(`${base}/login`);
  await owner.locator('input[name="login"]').fill("owner");
  await owner.locator('input[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
  await Promise.all([owner.waitForURL(`${base}/`), owner.locator('button[type="submit"]').click()]);
  await owner.goto(`${base}/reauth?return_to=%2Fadministrators`);
  await owner.locator('input[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
  await Promise.all([owner.waitForURL(`${base}/administrators`), owner.locator('button[type="submit"]').click()]);
  const target = await owner.evaluate(async base => {
    const list = await fetch(`${base}/api/v1/administrators`);
    const response = await fetch(`${base}/api/v1/administrators`, { method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": list.headers.get("X-CSRF-Token"), "If-Match": list.headers.get("ETag"), "Idempotency-Key": crypto.randomUUID() }, body: JSON.stringify({ login_name: "browser.recover", display_name: "ブラウザ復旧試験", password: "initial-browser-recovery-password", access: { role: "moderator", board_ids: [], extra_permissions: [], enabled: true } }) });
    const result = await response.json();
    if (!response.ok) throw new Error(`create status ${response.status}`);
    return result.data.id;
  }, base);
  await owner.goto(`${base}/administrators/${target}`);
  await owner.getByRole("button", { name: "一時パスワードを発行" }).click();
  await owner.locator("[data-temporary-password]").waitFor();
  await owner.setViewportSize({ width: 320, height: 900 });
  assert.equal(await owner.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  const temporary = await owner.locator("[data-temporary-password]").textContent();
  assert.match(temporary, /^[A-Za-z0-9_-]{32}$/);
  const person = await browser.newPage();
  person.on("pageerror", error => errors.push(error.message));
  await person.goto(`${base}/login`);
  await person.locator('input[name="login"]').fill("browser.recover");
  await person.locator('input[name="password"]').fill(temporary);
  await Promise.all([person.waitForURL(`${base}/password`), person.locator('button[type="submit"]').click()]);
  assert.equal((await person.context().request.get(`${base}/api/v1/reauth`)).status(), 403);
  await person.locator('input[name="current_password"]').fill(temporary);
  await person.locator('input[name="new_password"]').fill("new-browser-user-chosen-password");
  await Promise.all([person.waitForURL(`${base}/login`), person.locator('button[type="submit"]').click()]);
  await person.locator('input[name="login"]').fill("browser.recover");
  await person.locator('input[name="password"]').fill("new-browser-user-chosen-password");
  await Promise.all([person.waitForURL(`${base}/auto-reports`), person.locator('button[type="submit"]').click()]);
  assert.equal((await person.context().request.get(`${base}/api/v1/reauth`)).status(), 200);
  assert.deepEqual(errors, []);
  console.log("PASS: temporary password issued once, restricted session, mandatory change, recovery login and admin access");
} finally { await browser.close(); }
