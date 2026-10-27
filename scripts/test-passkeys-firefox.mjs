/** 隔離サーバーで再認証への案内、登録開始、期限切れの回復導線をFirefoxで検証する。端末認証器は使わない。 */
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { mkdir } from "node:fs/promises";
const require = createRequire(import.meta.url);
const { firefox } = require(process.env.OIMO_PLAYWRIGHT);
const browser = await firefox.launch({ headless: true });
try {
  const page = await browser.newPage();
  const errors = [];
  page.on("pageerror", error => errors.push(error.message));
  // 認証器の代わりに入力オプションを記録し、明示的にキャンセルする。
  await page.addInitScript(() => {
    navigator.credentials.get = async ({ publicKey }) => {
      window.passkeyLoginTestOptions = {
        challenge: publicKey.challenge instanceof Uint8Array,
        verification: publicKey.userVerification,
        allowed: publicKey.allowCredentials?.length || 0,
      };
      throw new DOMException("test cancellation", "NotAllowedError");
    };
    navigator.credentials.create = async ({ publicKey }) => {
      window.passkeyTestOptions = {
        challenge: publicKey.challenge instanceof Uint8Array,
        user: publicKey.user.id instanceof Uint8Array,
        verification: publicKey.authenticatorSelection.userVerification,
        residentKey: publicKey.authenticatorSelection.residentKey,
        requireResidentKey: publicKey.authenticatorSelection.requireResidentKey,
      };
      throw new DOMException("test cancellation", "NotAllowedError");
    };
  });
  const base = process.env.OIMO_PASSKEY_URL;
  await page.goto(`${base}/login`);
  assert.equal(await page.locator("[data-passkey-login] svg").count(), 1);
  assert.equal(await page.locator('input[name="login"]').inputValue(), "");
  const loginBegin = page.waitForResponse(response => response.url().endsWith("/passkey/login/begin"));
  await page.locator("[data-passkey-login]").click();
  const loginResponse = await loginBegin;
  assert.equal(loginResponse.status(), 200);
  assert.deepEqual(loginResponse.request().postDataJSON(), {});
  await page.waitForFunction(() => document.querySelector("[data-passkey-status]").textContent.includes("キャンセル"));
  assert.deepEqual(await page.evaluate(() => window.passkeyLoginTestOptions), { challenge: true, verification: "required", allowed: 0 });
  await page.reload();
  await page.locator('input[name="login"]').fill("owner");
  await page.locator('input[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
  await Promise.all([page.waitForURL(`${base}/`), page.locator('button[type="submit"]').click()]);
  await page.goto(`${base}/passkeys`);
  assert.equal(await page.locator("[data-passkey-register]").count(), 0);
  const guide = page.locator("[data-passkey-reauth-required] a");
  assert.equal(await guide.isVisible(), true);
  // 直接送信でも再認証必須の境界は維持される。
  const rejected = await page.evaluate(async base => {
    const response = await fetch(`${base}/api/v1/passkey/register/begin`, {
      method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": document.querySelector("[data-passkey-manager]").dataset.csrf },
      body: JSON.stringify({ name: "Firefox試験" }),
    });
    return { status: response.status, code: (await response.json()).error.code };
  }, base);
  assert.deepEqual(rejected, { status: 403, code: "REAUTHENTICATION_REQUIRED" });
  await guide.click();
  assert.equal(await page.locator("[data-passkey-reauth] svg").count(), 1);
  await page.locator('input[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
  await Promise.all([page.waitForURL(`${base}/passkeys`), page.locator('button[type="submit"]').click()]);
  assert.equal(await page.locator("[data-passkey-register] button svg").count(), 1);
  assert.equal(await page.locator("[data-passkey-reauth-required]").isVisible(), false);
  await page.locator('input[name="name"]').fill("Firefox試験");
  const begin = page.waitForResponse(response => response.url().endsWith("/passkey/register/begin"));
  await page.locator("[data-passkey-register] button").click();
  assert.equal((await begin).status(), 200);
  await page.waitForFunction(() => document.querySelector("[data-passkey-status]").textContent.includes("キャンセル"));
  assert.deepEqual(await page.evaluate(() => window.passkeyTestOptions), { challenge: true, user: true, verification: "required", residentKey: "required", requireResidentKey: true });
  for (const [code, message] of [
    ["ORIGIN_REJECTED", "接続元を確認できません"],
    ["CSRF_REJECTED", "ページを再読み込み"],
    ["REAUTHENTICATION_REQUIRED", "再認証の有効期限が切れました"],
  ]) {
    await page.route("**/passkey/register/begin", route => route.fulfill({ status: 403, contentType: "application/json", body: JSON.stringify({ error: { code } }) }));
    await page.locator("[data-passkey-register] button").click();
    await page.waitForFunction(message => document.querySelector("[data-passkey-status]").textContent.includes(message), message);
    await page.unroute("**/passkey/register/begin");
  }
  assert.equal(await guide.isVisible(), true);
  if (process.env.OIMO_PASSKEY_SCREENSHOTS) {
    await mkdir(process.env.OIMO_PASSKEY_SCREENSHOTS, { recursive: true });
    for (const width of [390, 2400]) {
      await page.setViewportSize({ width, height: 900 });
      if (width === 390) await page.locator(".admin-menu summary").click();
      const nav = page.locator(width === 390 ? ".admin-menu" : ".admin-nav-wide");
      assert.equal(await nav.locator('a[href$="/passkeys"] svg').isVisible(), true);
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
      await page.screenshot({ path: `${process.env.OIMO_PASSKEY_SCREENSHOTS}/firefox-passkeys-${width}.png`, fullPage: true });
      if (width === 390) await page.locator(".admin-menu summary").click();
    }
  }
  assert.deepEqual(errors, []);
  console.log("PASS: Firefox reauthentication guide, registration begin, authenticator options, cancellation, error recovery and icons (device authenticator not tested)");
} finally {
  await browser.close();
}
