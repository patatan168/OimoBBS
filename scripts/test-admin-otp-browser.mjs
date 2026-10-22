/** 隔離サーバーで認証アプリ互換OTP・パスワード禁止・パスキー復旧を画面操作で検証する。 */
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { createHmac } from "node:crypto";
import { mkdirSync } from "node:fs";
import { join } from "node:path";
const require = createRequire(import.meta.url);
const { chromium } = require(process.env.OIMO_PLAYWRIGHT);
const browser = await chromium.launch({ headless: true, executablePath: process.env.OIMO_CHROMIUM, args: ["--no-sandbox"] });
const base = process.env.OIMO_PASSKEY_URL;
const password = process.env.OIMO_TEST_PASSWORD;
/** 手動登録用Base32をアプリ側の共有鍵へ復号する。秘密を出力しない。 */
function decodeSecret(text) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const char of text) bits += alphabet.indexOf(char).toString(2).padStart(5, "0");
  return Buffer.from(bits.match(/.{8}/g).map(byte => Number.parseInt(byte, 2)));
}
/** 認証アプリ側として独立にHMACを計算する。 */
function code(secret, delta) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000) + delta));
  const mac = createHmac("sha1", secret).update(counter).digest();
  return String((mac.readUInt32BE(mac[19] & 15) & 0x7fffffff) % 1000000).padStart(6, "0");
}
/** 再認証前は設定状態だけを表示し、変更用の入力・送信操作を出さないことを確認する。 */
async function assertPolicyReadOnly(page, enabled) {
  const panel = page.locator("[data-auth-policy]");
  assert.equal(await panel.locator("input, button, form").count(), 0);
  assert.match(await panel.locator("[data-auth-policy-state]").textContent(), enabled ? /現在の設定：有効/ : /現在の設定：無効/);
  for (const width of [320, 1024]) {
    await page.setViewportSize({ width, height: 1000 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    if (process.env.OIMO_UI_OUTPUT) {
      mkdirSync(process.env.OIMO_UI_OUTPUT, { recursive: true, mode: 0o700 });
      const mount = new URL(base).pathname.includes("admin") ? "admin" : "root";
      await page.screenshot({ path: join(process.env.OIMO_UI_OUTPUT, `policy-${mount}-${enabled ? "enabled" : "disabled"}-${width}.png`), fullPage: true });
    }
  }
}
try {
  const context = await browser.newContext();
  const page = await context.newPage();
  const errors = [];
  page.on("pageerror", error => errors.push(error.message));
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  await page.goto(`${base}/login`);
  assert.equal(await page.locator('button[type="submit"]').count(), 1);
  assert.equal(await page.locator('[data-otp-login]').getAttribute("type"), "submit");
  for (const width of [320, 1024]) {
    await page.setViewportSize({ width, height: 1000 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    const positions = await page.evaluate(() => ["[data-passkey-login]", 'input[name="password"]', "[data-otp-code]", "[data-otp-login]"].map(selector => document.querySelector(selector).getBoundingClientRect().top));
    assert.deepEqual(positions, [...positions].sort((a,b) => a-b));
    if (process.env.OIMO_UI_OUTPUT) {
      mkdirSync(process.env.OIMO_UI_OUTPUT, { recursive:true, mode:0o700 });
      const mount = new URL(base).pathname.includes("admin") ? "admin" : "root";
      await page.screenshot({ path:join(process.env.OIMO_UI_OUTPUT, `login-${mount}-${width}.png`), fullPage:true });
    }
  }

  await page.locator('input[name="login"]').fill("owner");
  await page.locator('input[name="password"]').fill(password);
  await Promise.all([page.waitForURL(`${base}/`), page.locator('button[type="submit"]').click()]);
  await page.goto(`${base}/passkeys`);
  await assertPolicyReadOnly(page, false);
  await page.goto(`${base}/reauth?return_to=%2Fpasskeys`);
  await page.locator('input[name="password"]').fill(password);
  await Promise.all([page.waitForURL(`${base}/passkeys`), page.locator('button[type="submit"]').click()]);
  await assertPolicyReadOnly(page, false);
  await page.locator('input[name="name"]').fill("復旧試験パスキー");
  const registered = page.waitForResponse(response => response.url().endsWith("/passkey/register/finish"));
  await page.locator('[data-passkey-register] button').click();
  assert.equal((await registered).status(), 200);
  await page.waitForLoadState("networkidle");
  await page.setViewportSize({ width: 320, height: 900 });
  await page.locator("[data-otp-begin]").click();
  await page.locator("[data-otp-setup]").waitFor({ state: "visible" });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  assert.equal(await page.locator("[data-otp-secret]").evaluate(node => node.scrollWidth <= node.clientWidth), true);
  const encoded = await page.locator("[data-otp-secret]").textContent();
  assert.match(encoded, /^[A-Z2-7]{32}$/);
  const secret = decodeSecret(encoded);
  const uri = new URL(await page.locator("[data-otp-uri]").getAttribute("href"));
  assert.equal(uri.protocol, "otpauth:");
  assert.equal(uri.searchParams.get("digits"), "6");
  assert.equal(uri.searchParams.get("period"), "30");
  const qr = page.locator("[data-otp-qr]");
  await qr.evaluate(image => image.decode());
  assert.equal(await qr.evaluate(image => image.naturalWidth > 0), true);
  assert.equal(await qr.evaluate(image => image.getBoundingClientRect().right <= innerWidth), true);
  if (process.env.OIMO_QR_JSQR && process.env.OIMO_QR_PNGJS) {
    const jsQR = require(process.env.OIMO_QR_JSQR);
    const { PNG } = require(process.env.OIMO_QR_PNGJS);
    const image = PNG.sync.read(await qr.screenshot());
    const decoded = jsQR(new Uint8ClampedArray(image.data), image.width, image.height);
    assert.equal(decoded?.data, uri.href);
  }

  await page.locator('[data-otp-finish] input[name="code"]').fill(code(secret, -1));
  await Promise.all([page.waitForURL(`${base}/login`), page.locator("[data-otp-finish] button").click()]);
  await page.locator('input[name="login"]').fill("owner");
  await Promise.all([page.waitForURL(`${base}/`), page.locator("[data-passkey-login]").click()]);
  await page.goto(`${base}/reauth?return_to=%2Fpasskeys`);
  await Promise.all([page.waitForURL(`${base}/passkeys`), page.locator("[data-passkey-reauth]").click()]);
  await page.locator('[data-auth-policy] input[name="password_disabled"]').check();
  await Promise.all([page.waitForURL(`${base}/login`), page.locator("[data-auth-policy] button").click()]);
  await page.locator('input[name="login"]').fill("owner");
  await page.locator('input[name="password"]').fill(password);
  const denied = page.waitForResponse(response => response.url().endsWith("/login") && response.request().method() === "POST");
  await page.locator('button[type="submit"]').click();
  assert.equal((await denied).status(), 401);
  await page.locator('input[name="login"]').fill("owner");
  await page.locator('input[name="password"]').fill(password);
  await page.locator("[data-otp-code]").fill(code(secret, 0));
  await Promise.all([page.waitForURL(`${base}/`), page.locator("[data-otp-code]").press("Enter")]);
  await page.goto(`${base}/passkeys`);
  await assertPolicyReadOnly(page, true);
  await page.goto(`${base}/reauth?return_to=%2Fpasskeys`);
  assert.equal(await page.locator('input[name="password"]').count(), 1);
  await page.locator('input[name="password"]').fill(password);
  await page.locator("[data-otp-code]").fill(code(secret, 1));
  await Promise.all([page.waitForURL(`${base}/passkeys`), page.locator("[data-otp-code]").press("Enter")]);
  await page.locator('[data-auth-policy] input[name="password_disabled"]').uncheck();
  await Promise.all([page.waitForURL(`${base}/login`), page.locator("[data-auth-policy] button").click()]);
  await page.locator('input[name="login"]').fill("owner");
  await page.locator('input[name="password"]').fill(password);
  const stillDenied = page.waitForResponse(response => response.url().endsWith("/login") && response.request().method() === "POST");
  await page.locator('button[type="submit"]').click();
  assert.equal((await stillDenied).status(), 401);
  await page.locator('input[name="login"]').fill("owner");
  await Promise.all([page.waitForURL(`${base}/`), page.locator("[data-passkey-login]").click()]);
  await page.goto(`${base}/reauth?return_to=%2Fpasskeys`);
  await Promise.all([page.waitForURL(`${base}/passkeys`), page.locator("[data-passkey-reauth]").click()]);
  page.once("dialog", dialog => dialog.accept());
  await Promise.all([page.waitForURL(`${base}/login`), page.locator("[data-otp-remove]").click()]);
  assert.deepEqual(errors, []);
  console.log("PASS: OTP registration, passkey or password+OTP access, password denial, OTP login and reauthentication, policy reversal and removal");
} finally { await browser.close(); }
