/** 隔離HTTP試験サーバー上で仮想認証器による登録・ログイン・再認証・削除を確認する。 */
import { createRequire } from "node:module";
import assert from "node:assert/strict";
import { mkdir } from "node:fs/promises";
import { createHash, createPrivateKey, sign } from "node:crypto";
const require = createRequire(import.meta.url);
const { chromium } = require(process.env.OIMO_PLAYWRIGHT);
const browser = await chromium.launch({ headless: true, executablePath: process.env.OIMO_CHROMIUM, args: ["--no-sandbox"] });
try {
  const context = await browser.newContext();
  const page = await context.newPage();
  const errors = [];
 page.on("response", response => { if (response.status() >= 400) console.log("HTTP",response.status(),new URL(response.url()).pathname); });
 page.on("console", msg => { if(msg.type()==="error") console.log("browser error",msg.text()); });
  page.on("pageerror", error => errors.push(error.message));
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
    protocol: "ctap2", transport: "internal", hasResidentKey: true,
    hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true,
  }});
  const base = process.env.OIMO_PASSKEY_URL;
  await page.goto(`${base}/login`);
  if (process.env.OIMO_PASSKEY_SCREENSHOTS && !process.env.OIMO_PASSKEY_NEGATIVE) {
    await mkdir(process.env.OIMO_PASSKEY_SCREENSHOTS, { recursive: true });
    for (const width of [320, 390, 1024]) {
      await page.setViewportSize({ width, height: 900 });
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
      const colors = await page.locator("[data-passkey-login]").evaluate(button => ({ background: getComputedStyle(button).backgroundColor, color: getComputedStyle(button).color }));
      assert.notEqual(colors.background, "rgb(37, 99, 235)");
      await page.screenshot({ path: `${process.env.OIMO_PASSKEY_SCREENSHOTS}/login-${width}.png`, fullPage: true });
    }
  }
  await page.locator('input[name="login"]').fill("owner");
  await page.locator('input[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
  await Promise.all([page.waitForURL(`${base}/`), page.locator('button[type="submit"]').click()]);
  await page.goto(`${base}/reauth?return_to=%2Fpasskeys`);
  await page.locator('input[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
  await Promise.all([page.waitForURL(`${base}/passkeys`), page.locator('button[type="submit"]').click()]);
  await page.locator('input[name="name"]').fill("試験用パスキー");
  const registration = page.waitForResponse(response => response.url().endsWith("/passkey/register/finish"));
  await page.locator('[data-passkey-register] button').click();
  let registered;
 try { registered = await registration; } catch(error) { console.log("status:",await page.locator("[data-passkey-status]").textContent(),"errors",errors); throw error; }
  assert.equal(registered.status(), 200);
  await page.waitForLoadState("networkidle");
  assert.equal(await page.locator("[data-passkey-remove]").count(), 1);
  assert.ok((await page.locator(".passkey-row-copy p").textContent()).includes("登録日"));
  if (process.env.OIMO_PASSKEY_SCREENSHOTS && !process.env.OIMO_PASSKEY_NEGATIVE) {
    for (const width of [320, 390, 1024]) {
      await page.setViewportSize({ width, height: 900 });
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
      await page.screenshot({ path: `${process.env.OIMO_PASSKEY_SCREENSHOTS}/list-${width}.png`, fullPage: true });
    }
  }

  if (process.env.OIMO_PASSKEY_NEGATIVE) {
    const mode = process.env.OIMO_PASSKEY_NEGATIVE;
    const { credentials } = await cdp.send("WebAuthn.getCredentials", { authenticatorId });
    const key = createPrivateKey({ key: Buffer.from(credentials[0].privateKey, "base64"), format: "der", type: "pkcs8" });
    const loginNegative = mode.startsWith("login-");
    if (loginNegative) {
      await page.goto(`${base}/`);
      await Promise.all([page.waitForURL(`${base}/login`), page.locator('form[action$="/logout"] button').click()]);
      assert.equal(await page.locator('input[name="login"]').inputValue(), "");
    } else {
      await page.goto(`${base}/reauth?return_to=%2Fpasskeys`);
    }
    const finishPath = `/passkey/${loginNegative ? "login" : "reauth"}/finish`;
    await page.route(`**${finishPath}`, async route => {
      const body = route.request().postDataJSON();
      let clientData = Buffer.from(body.response.clientDataJSON, "base64url");
      const authData = Buffer.from(body.response.authenticatorData, "base64url");
      if (mode === "origin" || mode === "challenge") {
        const data = JSON.parse(clientData);
        if (mode === "origin") data.origin = "https://other.example";
        else data.challenge = Buffer.alloc(32, 7).toString("base64url");
        clientData = Buffer.from(JSON.stringify(data));
      }
      if (mode === "verification" || mode === "login-verification") authData[32] &= ~4;
      if (mode === "rp") authData[0] ^= 1;
      const signed = Buffer.concat([authData, createHash("sha256").update(clientData).digest()]);
      let signature = sign("sha256", signed, key);
      if (mode === "signature") signature[signature.length - 1] ^= 1;
      body.response.clientDataJSON = clientData.toString("base64url");
      body.response.authenticatorData = authData.toString("base64url");
      body.response.signature = signature.toString("base64url");
      if (mode === "login-handle") body.response.userHandle = Buffer.alloc(16, 7).toString("base64url");
      if (mode === "login-key") body.id = body.rawId = Buffer.alloc(32, 7).toString("base64url");
      await route.continue({ postData: JSON.stringify(body) });
    });
    const rejection = page.waitForResponse(response => response.url().endsWith(finishPath));
    await page.locator(loginNegative ? "[data-passkey-login]" : "[data-passkey-reauth]").click();
    assert.equal((await rejection).status(), 401);
    assert.deepEqual(errors, []);
    console.log(`PASS: signed assertion rejected for ${mode}`);
  } else {
  // 別端末の独立したパスワードセッションも削除時の失効対象にする。
  const otherContext = await browser.newContext();
  const otherPage = await otherContext.newPage();
  await otherPage.goto(`${base}/login`);
  await otherPage.locator('input[name="login"]').fill("owner");
  await otherPage.locator('input[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
  await Promise.all([otherPage.waitForURL(`${base}/`), otherPage.locator('button[type="submit"]').click()]);
  assert.equal((await otherContext.request.get(`${base}/api/v1/site`)).status(), 200);
  // 一度発行した応答の再送を拒否する。
  const request = registered.request();
  const replay = await context.request.post(request.url(), { data: request.postData(), headers: { "Content-Type": "application/json", "Origin": new URL(base).origin, "X-CSRF-Token": request.headers()["x-csrf-token"] }});
  assert.equal(replay.status(), 401);
  await page.goto(`${base}/`);
  await Promise.all([page.waitForURL(`${base}/login`), page.locator('form[action$="/logout"] button').click()]);
  assert.equal(await page.locator('input[name="login"]').inputValue(), "");
  assert.equal(await page.locator('input[name="password"]').inputValue(), "");
  const loginBegin = page.waitForRequest(request => request.url().endsWith("/passkey/login/begin"));
  await Promise.all([page.waitForURL(`${base}/`), page.locator("[data-passkey-login]").click()]);
  assert.deepEqual((await loginBegin).postDataJSON(), {});
  await page.goto(`${base}/reauth?return_to=%2Fpasskeys`);
  await Promise.all([page.waitForURL(`${base}/passkeys`), page.locator("[data-passkey-reauth]").click()]);
  const { credentials } = await cdp.send("WebAuthn.getCredentials", { authenticatorId });
  assert.equal(credentials.length, 1);
  assert(credentials[0].signCount >= 2);
  // パスキー再認証済みのCookieを別ブラウザへ複製し、削除後に使えないことも確認する。
  const copiedContext = await browser.newContext();
  await copiedContext.addCookies(await context.cookies());
  assert.equal((await copiedContext.request.get(`${base}/api/v1/site`)).status(), 200);
  page.once("dialog", dialog => dialog.accept());
  const deletion = page.waitForResponse(response => response.url().endsWith("/passkey/remove/finish"));
  await page.locator("[data-passkey-remove]").click();
  assert.equal((await deletion).status(), 200);
  await page.waitForURL(`${base}/login`);
  for (const session of [context, otherContext, copiedContext]) {
    assert.equal((await session.request.get(`${base}/api/v1/site`)).status(), 401);
  }
  await page.locator('input[name="login"]').fill("owner");
  await page.locator('input[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
  await Promise.all([page.waitForURL(`${base}/`), page.locator('button[type="submit"]').click()]);
  await page.goto(`${base}/passkeys`);
  assert.equal(await page.locator("[data-passkey-remove]").count(), 0);
  const plainContext = await browser.newContext({ javaScriptEnabled: false });
  const plain = await plainContext.newPage();
  await plain.goto(`${base}/login`);
  await plain.locator('input[name="login"]').fill("owner");
  await plain.locator('input[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
  await Promise.all([plain.waitForURL(`${base}/`), plain.locator('button[type="submit"]').click()]);
  assert.equal((await plainContext.request.get(`${base}/api/v1/site`)).status(), 200);
  await plainContext.close();
  await otherContext.close();
  await copiedContext.close();
  assert.deepEqual(errors, []);
  console.log("PASS: browser registration, replay rejection, passkey login, reauthentication, deletion, all-session revocation and recovery login");
  }
} finally { await browser.close(); }
