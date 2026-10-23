/** OWASP WSTGの保存型XSS・DOM注入・CSRFを隔離サーバーの実画面で検証する。 */
import assert from "node:assert/strict";
import {createRequire} from "node:module";

const {chromium} = createRequire(import.meta.url)(process.env.OIMO_PLAYWRIGHT);
const browser = await chromium.launch({headless: true, executablePath: process.env.OIMO_CHROMIUM, args: ["--no-sandbox"]});
try {
  const base = process.env.OIMO_ASSETS_PUBLIC_URL;
  const context = await browser.newContext();
  await context.addInitScript(() => { window.__wstgXSS = 0; });
  const page = await context.newPage();
  page.setDefaultTimeout(10000);
  const errors = [];
  page.on("pageerror", error => errors.push(error.message));
  const title = '"><svg/onload=window.__wstgXSS=1>';
  const payload = '</textarea><img data-wstg-injected src="https://attacker.invalid/x" onerror="window.__wstgXSS=1">\n<script data-wstg-injected>window.__wstgXSS=1</script>\n<svg onload="window.__wstgXSS=1"></svg>\n>>1';
  let foreignRequests = 0;
  // 攻撃文字列が誤って解釈されても、外部への通信を発生させない。
  await context.route("https://attacker.invalid/**", async route => { foreignRequests++; await route.abort(); });

  /** CSPだけに依存せず、攻撃文字列から実行可能なDOMが作られていないことも確認する。 */
  async function assertInert(label) {
    await page.waitForLoadState("networkidle");
    assert.equal(await page.evaluate(() => window.__wstgXSS), 0, `${label}: code executed`);
    assert.equal(await page.locator("[data-wstg-injected], [onload], [onerror]").count(), 0, `${label}: active DOM injected`);
    assert.equal(foreignRequests, 0, `${label}: external request attempted`);
  }

  await page.goto(`${base}/web/post?bbs=reports`);
  await page.locator('[name="subject"]').fill(title);
  await page.locator('[name="FROM"]').fill("WSTG tester");
  await page.locator('[name="MESSAGE"]').fill(payload);
  await Promise.all([page.waitForNavigation(), page.getByRole("button", {name: "書き込む", exact: true}).click()]);
  assert.ok(await page.getByRole("button", {name: "Cookieと利用規約に同意して書き込む", exact: true}).isVisible());
  assert.ok((await page.locator("main").textContent()).includes("<svg"));
  await assertInert("confirmation");
  await Promise.all([page.waitForNavigation(), page.getByRole("button", {name: "Cookieと利用規約に同意して書き込む", exact: true}).click()]);
  assert.match(new URL(page.url()).pathname, /^\/test\/read\.cgi\/reports\/[0-9]+\//);
  const threadURL = page.url();
  const thread = new URL(threadURL).pathname.split("/")[4];
  assert.ok((await page.locator(".response-body").first().textContent()).includes("<script"));
  assert.ok(await page.locator('.response-body a[href="#1"]').count());
  await assertInert("stored thread and response-link enhancement");
  await page.reload();
  await assertInert("stored thread reload");
  await page.goto(`${base}/reports?board=reports&thread=${thread}&ranges=1`);
  await page.locator('[name="reason"]').fill(payload);
  await page.locator('[name="contact"]').fill(title);
  const [accepted] = await Promise.all([page.waitForNavigation(), page.getByRole("button", {name: "依頼を送る", exact: true}).click()]);
  assert.equal(accepted.status(), 201);
  const codes = await page.locator("main code").allTextContents();
  assert.equal(codes.length, 2);
  await page.goto(`${base}/admin/login`);
  await page.locator('[name="login"]').fill("owner");
  await page.locator('[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
  await Promise.all([page.waitForNavigation(), page.getByRole("button", {name: "パスワードでログイン", exact: true}).click()]);
  await page.goto(`${base}/admin/reports/${codes[0]}`);
  assert.ok((await page.locator("main").textContent()).includes("<script"));
  await assertInert("stored private report in administrator page");
  await page.goto(`${base}/reports`);
  assert.ok(!(await page.locator("main").textContent()).includes(codes[1]), "lookup secret repeated by GET");

  const beforeResponse = await page.request.get(`${base}/admin/api/v1/site`);
  assert.equal(beforeResponse.status(), 200);
  const before = await beforeResponse.json();
  const csrf = beforeResponse.headers()["x-csrf-token"];
  // 実際に異なるOriginから送信する。攻撃用ページはブラウザ内で返し、外部サーバーへ接続しない。
  const attacker = await context.newPage();
  await attacker.route("https://attacker.invalid/**", route => route.fulfill({
    contentType: "text/html",
    body: `<form method="post" action="${base}/admin/site"><input name="name" value="CSRF unwanted"><input name="csrf"><input name="revision"><input name="request_id" value="wstg-browser-csrf"><button>attack</button></form>`,
  }));
  await attacker.goto("https://attacker.invalid/");
  await attacker.locator('[name="csrf"]').fill(csrf);
  await attacker.locator('[name="revision"]').fill(beforeResponse.headers()["etag"]);
  const [denied] = await Promise.all([attacker.waitForNavigation(), attacker.getByRole("button", {name: "attack"}).click()]);
  assert.equal(denied.status(), 403);
  const afterResponse = await page.request.get(`${base}/admin/api/v1/site`);
  assert.equal(afterResponse.status(), 200);
  assert.deepEqual((await afterResponse.json()).data, before.data, "cross-origin request changed site");
  assert.deepEqual(errors, []);
  await context.close();
  console.log("PASS: confirmed/stored post XSS, DOM response links, stored private-report XSS, lookup-secret non-reflection, real cross-origin CSRF rejection and unchanged site");
} finally {
  await browser.close();
}
