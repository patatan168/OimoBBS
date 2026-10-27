/** WAF検出画面の本文比較・フィルター・全板規制の保存と解除をブラウザで検証する。 */
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { mkdir } from "node:fs/promises";
const require = createRequire(import.meta.url);
const { chromium } = require(process.env.OIMO_PLAYWRIGHT);
const browser = await chromium.launch({ headless: true, executablePath: process.env.OIMO_CHROMIUM, args: ["--no-sandbox"] });
try {
 const page = await browser.newPage();
 const errors = [];
 page.on("pageerror", error => errors.push(error.message));
 const base = process.env.OIMO_SECURITY_URL;
 await page.goto(`${base}/login`);
 await page.locator('input[name="login"]').fill("owner");
 await page.locator('input[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
 await Promise.all([page.waitForURL(`${base}/`), page.locator('button[type="submit"]').click()]);
 await page.goto(`${base}/waf-events`);
 assert.equal(await page.locator('.security-event').count(), 3);
 assert.equal(await page.locator('select[name="dummy"]').count(), 0);
 assert.ok(!(await page.locator('main').textContent()).includes('表示しない過去の確認用ログ'));
 assert.ok(!(await page.locator('main').textContent()).includes('確認用ダミー'));
 assert.equal(await page.locator('.security-details[open]').count(), 0);
 assert.equal(await page.evaluate(() => window.bad), undefined);
 assert.ok((await page.locator('main').textContent()).includes("類似した投稿の本文例"));
 assert.equal(await page.locator('.security-event a[href*="event="]').count(), 2);
 if (process.env.OIMO_SECURITY_SCREENSHOTS) await mkdir(process.env.OIMO_SECURITY_SCREENSHOTS, {recursive:true});
 for (const colorScheme of ['light','dark']) {
  await page.emulateMedia({colorScheme});
  for (const width of [320,390,700,768,1280]) {
   await page.setViewportSize({width,height:1000});
   assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),true,`logs overflow ${width}`);
   if (width > 700) {
    const row = await page.locator('.security-event').first().evaluate(element => {
     const cells = [...element.cells].map(cell => cell.getBoundingClientRect());
     return {aligned:cells.every(cell => cell.top === cells[0].top),height:element.getBoundingClientRect().height};
    });
    assert.ok(row.aligned && row.height < 130, `compact table rows ${width}: ${JSON.stringify(row)}`);
   }
   if(process.env.OIMO_SECURITY_SCREENSHOTS) await page.screenshot({path:`${process.env.OIMO_SECURITY_SCREENSHOTS}/logs-${colorScheme}-${width}.png`,fullPage:true});
   for (const summary of await page.locator('.security-details > summary').all()) await summary.click();
   assert.equal(await page.locator('.security-details[open]').count(),3);
   const detailWidth = await page.locator('.security-details').first().evaluate(element => ({details:element.getBoundingClientRect().width,table:element.closest('table').getBoundingClientRect().width,cellColumn:getComputedStyle(element.parentElement).gridColumn}));
   assert.ok(detailWidth.details >= detailWidth.table - 25, `full-width details ${width}: ${JSON.stringify(detailWidth)}`);
   assert.ok(await page.getByText('類似した投稿の本文例',{exact:true}).isVisible());
   assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),true,`expanded logs overflow ${width}`);
   if(process.env.OIMO_SECURITY_SCREENSHOTS) await page.screenshot({path:`${process.env.OIMO_SECURITY_SCREENSHOTS}/logs-expanded-${colorScheme}-${width}.png`,fullPage:true});
   for (const summary of await page.locator('.security-details > summary').all()) await summary.click();
  }
 }
 await page.locator('select[name="result"]').selectOption("rejected");
 await Promise.all([page.waitForNavigation(),page.getByRole('button',{name:'絞り込む',exact:true}).click()]);
 assert.equal(await page.locator('.security-event').count(),2);
 await page.goto(`${base}/waf-events?source=similar&result=detected`);
 assert.equal(await page.locator('.security-event').count(),1);
 await page.locator('.security-details > summary').click();
 await page.getByRole('link',{name:'この本文から掲示板全体のNGワードを設定'}).click();
 assert.ok((await page.locator('textarea[name="value"]').inputValue()).includes("確認用の宣伝文"));
 assert.ok(!page.url().includes('script'));
 // 語句を編集して、実フォームで再認証・保存・解除する。
 await page.goto(`${base}/reauth?return_to=%2Fglobal-rules`);
 await page.locator('input[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
 await Promise.all([page.waitForNavigation(),page.locator('form[action*="/reauth"] button[type="submit"]').click()]);
 await page.locator('#add-rule > summary').click();
 await page.locator('textarea[name="value"]').fill("確認用の宣伝文");
 await Promise.all([page.waitForNavigation(),page.getByRole('button',{name:'掲示板全体に規制を追加',exact:true}).click()]);
 assert.ok((await page.locator('main').textContent()).includes("適用中"),await page.locator('main').textContent());
 for(const width of [320,390,1280]) {
  await page.setViewportSize({width,height:1000});
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),true,`rules overflow ${width}`);
  if(process.env.OIMO_SECURITY_SCREENSHOTS) await page.screenshot({path:`${process.env.OIMO_SECURITY_SCREENSHOTS}/rules-${width}.png`,fullPage:true});
 }
 await Promise.all([page.waitForNavigation(),page.locator('.rule-revoke button').first().click()]);
 assert.ok((await page.locator('main').textContent()).includes("解除済み"));
 await page.goto(`${base}/global-rules?state=revoked`);
 assert.equal(await page.locator('tr[data-rule-state="revoked"]').count(),1);
 await page.goto(`${base}${process.env.OIMO_RULE_LIST_PATH}`);
 assert.equal(await page.locator('.rule-table tbody tr').count(),3);
 for(const width of [320,390,1280]) {
  await page.setViewportSize({width,height:1000});
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),true,`board list overflow ${width}`);
  if(process.env.OIMO_SECURITY_SCREENSHOTS) await page.screenshot({path:`${process.env.OIMO_SECURITY_SCREENSHOTS}/board-rules-${width}.png`,fullPage:true});
 }
 await page.locator('.rule-status-tabs a[href*="state=expired"]').click();
 assert.equal(await page.locator('.rule-table tbody tr').count(),1);
 await page.locator('.rule-details summary').click();
 assert.ok(await page.getByText('規制ID',{exact:true}).isVisible());
 await page.locator('input[name="q"]').fill("存在しない規制の検索");
 await Promise.all([page.waitForNavigation(),page.getByRole('button',{name:'検索',exact:true}).click()]);
 assert.equal(await page.locator('.rule-table tbody tr').count(),0);
 assert.ok((await page.locator('main').textContent()).includes("条件に一致する規制はありません"));
 const noJS = await browser.newContext({javaScriptEnabled:false,storageState:await page.context().storageState(),viewport:{width:390,height:1000}});
 const noJSPage = await noJS.newPage();
 await noJSPage.goto(`${base}/waf-events?source=similar&result=detected`);
 await noJSPage.locator('.security-details > summary').click();
 assert.ok(await noJSPage.getByText('類似した投稿の本文例',{exact:true}).isVisible());
 assert.ok(await noJSPage.getByRole('link',{name:'この本文から掲示板全体のNGワードを設定'}).isVisible());
 await noJS.close();
 assert.deepEqual(errors,[]);
 console.log("PASS: hidden historical dummy logs, compact table, collapsed/expanded details in light/dark, escaped bodies, WAF-enabled log-to-rule link, filters, reauthentication, global rule save/revoke, 320/390/700/768/1280px, no-JS details");
} finally {await browser.close();}
