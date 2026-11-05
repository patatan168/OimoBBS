/** 実際の管理画面から回線分類を更新し、HTTP・画面・JavaScriptのエラーと手動上書きの保持を確認する。 */
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {mkdir, writeFile} from 'node:fs/promises';
import {join} from 'node:path';

const {chromium} = createRequire(import.meta.url)(process.env.OIMO_PLAYWRIGHT);
const browser = await chromium.launch({headless: true, executablePath: process.env.OIMO_CHROMIUM, args: ['--no-sandbox']});
const base = process.env.OIMO_NETWORK_BROWSER_URL;
const directory = process.env.OIMO_NETWORK_BROWSER_OUTPUT;
const errors = [], failures = [], updates = [];
try {
  const page = await browser.newPage();
  page.setDefaultTimeout(60000);
  page.on('pageerror', error => errors.push(error.message));
  page.on('response', response => {
    if (response.status() >= 400 && !response.url().endsWith('/favicon.ico')) failures.push({url: response.url(), status: response.status()});
  });
  page.on('requestfailed', request => failures.push({url: request.url(), failure: request.failure()?.errorText}));
  await page.goto(base + '/login');
  await page.locator('[name="login"]').fill('owner');
  await page.locator('[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
  await Promise.all([page.waitForNavigation(), page.locator('button[type="submit"]').click()]);
  if (directory) await mkdir(directory, {recursive: true});

  /** 実フォームの保存と自動再描画を待ち、表示と保存値の両方を確認する。 */
  async function updateFromScreen(label, name) {
    assert.equal((await page.goto(base + '/networks')).status(), 200);
    assert.equal(await page.locator('[role="alert"]').count(), 0);
    assert.equal(await page.locator('[name="action"][value="standard_reclassify"]').count(), 0);
    const before = (await (await page.request.get(base + '/api/v1/networks')).json()).data;
    const submitted = page.waitForResponse(response => response.request().method() === 'POST' && response.url() === base + '/networks');
    await page.getByRole('button', {name: label, exact: true}).click();
    const response = await submitted;
    assert.equal(response.status(), 200, await response.text());
    await page.waitForLoadState('load');
    await page.waitForFunction(() => !document.querySelector('[data-network-poll]'));
    assert.equal(await page.locator('[role="alert"]').count(), 0);
    assert.ok((await page.locator('.site-footer').innerText()).includes('バージョン1.1.1'));
    const after = (await (await page.request.get(base + '/api/v1/networks')).json()).data;
    assert.equal(after.error_code, '');
    assert.ok(BigInt(after.attempt_ns) > BigInt(before.attempt_ns));
    assert.equal(after.applied_version, after.version);
    assert.ok(after.count > 0);
    assert.deepEqual(after.config.overrides, before.config.overrides);
    const counts = {};
    for (const source of after.config.sources.filter(source => source.type === 'asn')) counts[source.kind] = (counts[source.kind] || 0) + 1;
    assert.equal(counts.unknown, 87); assert.equal(counts.fixed, 115);
    assert.equal(counts.mixed, 6); assert.equal(counts.academic, 9);
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
    if (directory) {
      await page.locator('#network-status').scrollIntoViewIfNeeded();
      await page.screenshot({path: join(directory, name + '.png')});
    }
    updates.push({name, status: response.status(), alerts: 0, prefixes: after.count, counts});
  }

  for (const width of [390, 1280]) {
    await page.setViewportSize({width, height: 1000});
    await updateFromScreen('今すぐ更新', 'refresh-' + width);
  }
  await updateFromScreen('全業者の標準取得元を追加して更新', 'all-sources');
  assert.deepEqual(errors, []);
  assert.deepEqual(failures, []);
  const result = {status: 'PASS', liveFeeds: process.env.OIMO_NETWORK_LIVE === '1', updates, javascriptErrors: errors, httpFailures: failures};
  if (directory) await writeFile(join(directory, 'result.json'), JSON.stringify(result, null, 2));
  console.log(JSON.stringify(result));
} finally {
  await browser.close();
}
