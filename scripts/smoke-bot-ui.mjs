/** Goで描画したBot管理画面の幅・選択・通常フォーム送信を隔離Chromiumで検査する。 */
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFile, mkdir } from 'node:fs/promises';
import { createServer } from 'node:http';
import path from 'node:path';

const require = createRequire(import.meta.url);
const { chromium } = require(process.env.OIMO_PLAYWRIGHT_MODULE || 'playwright');
assert.ok(process.env.OIMO_BOT_PAGE_OUTPUT, 'OIMO_BOT_PAGE_OUTPUT is required');
const output = process.env.OIMO_UI_OUTPUT || 'var/bot-ui';
await mkdir(output, { recursive: true, mode: 0o700 });
const html = (await readFile(process.env.OIMO_BOT_PAGE_OUTPUT, 'utf8'))
  .replaceAll(/\/web\/assets\/[a-f0-9]+\/([^" ]+)/g, '/assets/$1');
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
    await page.goto(`http://127.0.0.1:${server.address().port}/`);
    assert.equal(await page.locator('[name=bot_mode]').inputValue(), 'reject');
    for (const width of [320, 1024]) {
      await page.setViewportSize({ width, height: 1000 });
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
      await page.screenshot({ path: path.join(output, `bot-${width}-js-${javaScriptEnabled}.png`), fullPage: true });
    }
    for (const mode of ['off', 'reject', 'observe']) {
      await page.locator('[name=bot_mode]').selectOption(mode);
      assert.equal(await page.locator('[name=bot_mode]').inputValue(), mode);
    }
    await Promise.all([page.waitForURL('**/abuse-guard'), page.getByRole('button', { name: '全板共通の設定を保存' }).click()]);
    assert.equal(submitted.get('bot_mode'), 'observe');
    for (const key of ['csrf', 'revision', 'request_id', 'similar_mode', 'flood_mode', 'rate_enabled']) assert.ok(submitted.has(key), key);
    assert.deepEqual(errors, []);
    await context.close();
  }
  console.log('PASS: Bot modes, form submission, 320/1024 layout, JavaScript on/off');
} finally {
  await browser?.close();
  server.close();
}
