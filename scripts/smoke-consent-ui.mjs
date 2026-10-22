/** Goで描画した規約管理フォームのアイコン・幅・平文送信を隔離Chromiumで確認する。 */
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFile, mkdir } from 'node:fs/promises';
import { createServer } from 'node:http';
import path from 'node:path';
const require = createRequire(import.meta.url);
const { chromium } = require(process.env.OIMO_PLAYWRIGHT_MODULE || 'playwright');
assert.ok(process.env.OIMO_CONSENT_PAGE_OUTPUT, 'OIMO_CONSENT_PAGE_OUTPUT is required');
const output = process.env.OIMO_UI_OUTPUT || 'var/consent-ui';
await mkdir(output, { recursive: true, mode: 0o700 });
const html = (await readFile(process.env.OIMO_CONSENT_PAGE_OUTPUT, 'utf8')).replaceAll(/\/web\/assets\/[a-f0-9]+\/([^" ]+)/g, '/assets/$1');
let submitted;
const server = createServer(async (request, response) => {
  if (request.method === 'POST') {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    submitted = new URLSearchParams(Buffer.concat(chunks).toString());
    response.end('saved');
    return;
  }
  const asset = request.url?.match(/^\/assets\/(ui\.css|ui\.js|admin\.js)$/)?.[1];
  response.setHeader('Content-Type', asset ? asset.endsWith('.css') ? 'text/css' : 'text/javascript' : 'text/html; charset=utf-8');
  response.end(asset ? await readFile('internal/webui/assets/' + asset) : html);
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
let browser;
try {
  browser = await chromium.launch({ headless: true, executablePath: process.env.OIMO_CHROME, args: ['--no-sandbox'] });
  for (const javaScriptEnabled of [true, false]) {
    const context = await browser.newContext({ javaScriptEnabled });
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.goto(`http://127.0.0.1:${server.address().port}/terms`);
    assert.equal(await page.locator('nav a[href$="/terms"] svg').count(), 2);
    assert.ok(await page.locator('[name=terms_text]').inputValue());
    for (const width of [320, 1024]) {
      await page.setViewportSize({ width, height: 1000 });
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
      await page.screenshot({ path: path.join(output, `consent-${width}-js-${javaScriptEnabled}.png`), fullPage: true });
    }
    await page.locator('[name=cookie_notice]').fill('Cookieの使用について\n次の行');
    await page.locator('[name=terms_text]').fill('利用規約の本文\n<script>文字として送信</script>');
    await Promise.all([page.waitForNavigation(), page.getByRole('button', { name: '保存', exact: true }).click()]);
    assert.equal(submitted.get('cookie_notice').replaceAll('\r\n', '\n'), 'Cookieの使用について\n次の行');
    assert.equal(submitted.get('terms_text').replaceAll('\r\n', '\n'), '利用規約の本文\n<script>文字として送信</script>');
    for (const key of ['csrf', 'revision', 'request_id']) assert.ok(submitted.has(key), key);
    assert.deepEqual(errors, []);
    await context.close();
  }
  console.log('PASS: terms icon, 320/1024 layout, multiline form submission, JavaScript on/off');
} finally {
  await browser?.close();
  server.close();
}
