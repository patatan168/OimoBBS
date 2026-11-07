/** 規制対象のURLと自動リンクの宛先を実Chromiumで照合し、日本語説明を付けた投稿の拒否を確認する。 */
import assert from "node:assert/strict";
import {createRequire} from "node:module";
import {randomUUID} from "node:crypto";

const {chromium} = createRequire(import.meta.url)(process.env.OIMO_PLAYWRIGHT);
const browser = await chromium.launch({headless: true, executablePath: process.env.OIMO_CHROMIUM, args: ["--no-sandbox"]});
try {
  const base = process.env.OIMO_ASSETS_PUBLIC_URL;
  const board = process.env.OIMO_LAYOUT_BOARD;
  const context = await browser.newContext();
  const page = await context.newPage();
  page.setDefaultTimeout(10000);
  const errors = [];
  page.on("pageerror", error => errors.push(error.message));
  await context.route("https://example.test/**", route => route.abort());
  const separators = ["「", "」", "『", "』", "【", "】", "〈", "〉", "《", "》", "（", "）", "、", "。", "！", "？", "\u00a0", "\u1680", "\u2000", "\u2028", "\u2029", "\u202f", "\u205f", "\u3000", "\ufeff"];
  const payloads = separators.map(separator => `https://example.test${separator}案内`);

  /** 実フォームから新規投稿し、必要な場合は同意確認を経由する。 */
  async function submit(body, title, thread = "") {
    await page.goto(`${base}/web/post?bbs=reports${thread ? `&key=${thread}` : ""}`);
    if (!thread) await page.locator('[name="subject"]').fill(title);
    await page.locator('[name="MESSAGE"]').fill(body);
    let [response] = await Promise.all([page.waitForNavigation(), page.getByRole("button", {name: "書き込む", exact: true}).click()]);
    const confirmation = page.getByRole("button", {name: "Cookieと利用規約に同意して書き込む", exact: true});
    if (await confirmation.isVisible()) {
      [response] = await Promise.all([page.waitForNavigation(), confirmation.click()]);
    }
    return response;
  }

  const control = await submit(payloads.join("\n"), "リンク境界の正常対照");
  assert.equal(control.status(), 200);
  assert.match(new URL(page.url()).pathname, /^\/test\/read\.cgi\/reports\/[0-9]+\//);
  const hosts = await page.locator("[data-response-body] a").evaluateAll(links => links.map(link => new URL(link.href).hostname));
  assert.equal(hosts.length, payloads.length);
  assert.ok(hosts.every(host => host === "example.test"));
  const thread = new URL(page.url()).pathname.split("/")[4];

  await page.goto(`${base}/admin/login`);
  await page.locator('[name="login"]').fill("owner");
  await page.locator('[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
  await Promise.all([page.waitForNavigation(), page.getByRole("button", {name: "パスワードでログイン", exact: true}).click()]);
  const path = `${base}/admin/api/v1/boards/${board}/rules`;
  const rules = await page.request.get(path);
  assert.equal(rules.status(), 200);
  const saved = await page.request.post(path, {
    headers: {"Content-Type": "application/json", "Origin": base, "X-CSRF-Token": rules.headers()["x-csrf-token"], "If-Match": rules.headers().etag, "Idempotency-Key": randomUUID()},
    data: JSON.stringify({target: "example.test", operations: ["create", "reply"], duration_minutes: 60, reason_code: "spam", match: {field: "domain", operator: "suffix", effect: "deny"}, extra_conditions: [], allow_rule_ids: [], rate_override: null}),
  });
  assert.equal(saved.status(), 200, await saved.text());
  for (const [index, body] of [payloads[0], payloads[16], "https://unrelated.test「https://example.test」"].entries()) {
    const denied = await submit(body, `規制境界${index}`, thread);
    assert.equal(denied.status(), 403, `rendered domain bypass: ${JSON.stringify(body)}`);
    assert.equal(await page.getByRole("heading", {name: "投稿が規制されています", exact: true}).count(), 1);
  }
  const allowed = await submit("https://unrelated.test/ 許可された対照", "許可対照", thread);
  assert.equal(allowed.status(), 200);
  assert.match(new URL(page.url()).pathname, /^\/test\/read\.cgi\/reports\/[0-9]+\//);
  assert.deepEqual(errors, []);
  await context.close();
  console.log("PASS: 25 rendered URL boundaries target the blocked host; Japanese brackets, nonbreaking space and nested URLs rejected by actual Web posting");
} finally {
  await browser.close();
}
