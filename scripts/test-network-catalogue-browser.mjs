/** 実際の管理画面から回線分類を更新し、HTTP・画面・JavaScriptのエラーと手動上書きの保持を確認する。 */
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {mkdir, writeFile} from 'node:fs/promises';
import {join} from 'node:path';

const {chromium} = createRequire(import.meta.url)(process.env.OIMO_PLAYWRIGHT);
const browser = await chromium.launch({headless: true, executablePath: process.env.OIMO_CHROMIUM, args: ['--no-sandbox']});
const base = process.env.OIMO_NETWORK_BROWSER_URL;
const directory = process.env.OIMO_NETWORK_BROWSER_OUTPUT;
const errors = [], failures = [], updates = [], schedules = [];
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

  /** 暦設定を実フォームから保存し、即時取得せず次の予定を待つことを確認する。 */
  async function saveSchedule(mode, day, width, colorScheme) {
    await page.setViewportSize({width, height: 1000});
    await page.emulateMedia({colorScheme});
    assert.equal((await page.goto(base + '/networks')).status(), 200);
    const before = (await (await page.request.get(base + '/api/v1/networks')).json()).data;
    const form = page.locator('[data-network-schedule-form]');
    await form.locator('[name="enabled"]').selectOption('true');
    if (mode === 'daily') await form.locator('[name="interval_hours"]').fill('0');
    await form.locator('[name="schedule_mode"]').selectOption(mode);
    await form.locator('[name="schedule_time"]').fill('04:00');
    if (mode === 'weekly') await form.locator('[name="schedule_weekday"]').selectOption('1');
    if (mode === 'monthly') await form.locator('[name="schedule_day"]').selectOption(day);
    assert.equal(await form.locator('[data-network-schedule-field="interval"]').isVisible(), false);
    assert.equal(await form.locator('[data-network-schedule-field="weekly"]').isVisible(), mode === 'weekly');
    assert.equal(await form.locator('[data-network-schedule-field="monthly"]').isVisible(), mode === 'monthly');
    const submitted = page.waitForResponse(response => response.request().method() === 'POST' && response.url() === base + '/networks');
    await form.getByRole('button', {name: '設定を保存', exact: true}).click();
    const response = await submitted;
    assert.equal(response.status(), 200, await response.text());
    await page.waitForLoadState('load');
    assert.equal(await page.locator('[role="alert"],[data-network-poll]').count(), 0);
    const after = (await (await page.request.get(base + '/api/v1/networks')).json()).data;
    assert.equal(after.config.schedule.frequency, mode);
    assert.equal(after.config.schedule.time, '04:00');
    if (mode === 'weekly') assert.equal(after.config.schedule.weekday, 1);
    if (mode === 'monthly') assert.equal(after.config.schedule.day, Number(day));
    assert.ok(Date.parse(after.next_update) > Date.now());
    assert.equal(after.attempt_ns, before.attempt_ns);
    assert.deepEqual(after.config.overrides, before.config.overrides);
    await Promise.all([page.waitForNavigation(), page.getByRole('link', {name: '最新の状態を表示', exact: true}).click()]);
    assert.equal(await form.locator('[name="schedule_mode"]').inputValue(), mode);
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
    if (directory) {
      await page.locator('#network-settings').scrollIntoViewIfNeeded();
      await page.screenshot({path: join(directory, `schedule-${mode}-${day}-${width}-${colorScheme}.png`)});
      await page.locator('[aria-labelledby="network-settings"]').screenshot({path: join(directory, `settings-${mode}-${day}-${width}-${colorScheme}.png`)});
    }
    schedules.push({mode, day, width, colorScheme, nextUpdate: after.next_update, status: response.status()});
  }

  await saveSchedule('daily', '1', 390, 'light');
  await saveSchedule('weekly', '1', 1280, 'light');
  await saveSchedule('monthly', '31', 390, 'dark');
  await saveSchedule('monthly', '0', 1280, 'dark');

  /** 実フォームの保存と自動再描画を待ち、表示と保存値の両方を確認する。 */
  async function updateFromScreen(label, name) {
    assert.equal((await page.goto(base + '/networks')).status(), 200);
    assert.equal(await page.locator('[role="alert"]').count(), 0);
    assert.equal(await page.locator('[name="action"][value="standard_reclassify"]').count(), 0);
    const before = (await (await page.request.get(base + '/api/v1/networks')).json()).data;
    if (label === '全業者の標準取得元を追加して更新') await page.getByText('標準取得元を追加する', {exact: true}).click();
    const submitted = page.waitForResponse(response => response.request().method() === 'POST' && response.url() === base + '/networks');
    await page.getByRole('button', {name: label, exact: true}).click();
    const response = await submitted;
    assert.equal(response.status(), 200, await response.text());
    await page.waitForLoadState('load');
    await page.waitForFunction(() => !document.querySelector('[data-network-poll]'));
    assert.equal(await page.locator('[role="alert"]').count(), 0);
    assert.ok((await page.locator('.site-footer').innerText()).includes('バージョン1.1.2'));
    const after = (await (await page.request.get(base + '/api/v1/networks')).json()).data;
    assert.equal(after.error_code, '');
    assert.ok(BigInt(after.attempt_ns) > BigInt(before.attempt_ns));
    assert.equal(after.applied_version, after.version);
    assert.ok(after.count > 0);
    assert.deepEqual(after.config.overrides, before.config.overrides);
    assert.deepEqual(after.config.schedule, before.config.schedule);
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
  // JavaScriptなしでも同じ保存経路を使い、間隔方式へ戻せる。
  const plain = await browser.newContext({javaScriptEnabled: false, storageState: await page.context().storageState()});
  const plainPage = await plain.newPage();
  assert.equal((await plainPage.goto(base + '/networks')).status(), 200);
  const plainForm = plainPage.locator('[data-network-schedule-form]');
  await plainForm.locator('[name="enabled"]').selectOption('false');
  await plainForm.locator('[name="schedule_mode"]').selectOption('interval');
  await Promise.all([plainPage.waitForNavigation(), plainForm.getByRole('button', {name: '設定を保存', exact: true}).click()]);
  assert.equal(await plainPage.locator('[role="alert"]').count(), 0);
  const plainSaved = (await (await plainPage.request.get(base + '/api/v1/networks')).json()).data;
  assert.equal(plainSaved.config.schedule, undefined);
  assert.equal(plainSaved.config.enabled, false);
  await plain.close();
  await updateFromScreen('全業者の標準取得元を追加して更新', 'all-sources');
  assert.deepEqual(errors, []);
  assert.deepEqual(failures, []);
  const result = {status: 'PASS', liveFeeds: process.env.OIMO_NETWORK_LIVE === '1', schedules, noJavaScriptSave: 'PASS', updates, javascriptErrors: errors, httpFailures: failures};
  if (directory) await writeFile(join(directory, 'result.json'), JSON.stringify(result, null, 2));
  console.log(JSON.stringify(result));
} finally {
  await browser.close();
}
