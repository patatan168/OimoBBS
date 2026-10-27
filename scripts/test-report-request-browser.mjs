/** レスからの削除依頼、入力保持、照会、管理設定をデスクトップと携帯幅で検証する。 */
import assert from "node:assert/strict";
import {createRequire} from "node:module";
import {mkdir} from "node:fs/promises";
const {chromium}=createRequire(import.meta.url)(process.env.OIMO_PLAYWRIGHT);
const browser=await chromium.launch({headless:true,executablePath:process.env.OIMO_CHROMIUM,args:["--no-sandbox"]});
try {
 const base=process.env.OIMO_ASSETS_PUBLIC_URL;
 const thread=process.env.OIMO_ASSETS_THREAD;
 const context=await browser.newContext();
 const page=await context.newPage();
 const errors=[];page.on("pageerror",e=>errors.push(e.message));
 await page.goto(base+"/admin/login");
 await page.locator('[name="login"]').fill("owner");
 await page.locator('[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
 await Promise.all([page.waitForNavigation(),page.locator('button[type="submit"]').click()]);
 await page.goto(base+"/admin/operations");
 const interval=page.locator('[name="report_interval_minutes"]');
 assert.equal(await interval.inputValue(),"10");
 await interval.fill("25");
 await page.waitForFunction(()=>document.querySelector('[data-settings-review]').dataset.edited==="true");
 await Promise.all([page.waitForNavigation(),page.locator('form[data-settings-form] button[type="submit"]').click()]);
 assert.equal(await interval.inputValue(),"25");
 for(const width of [1280,390]) {
  await page.setViewportSize({width,height:900});
  await page.goto(`${base}/test/read.cgi/reports/${thread}/`);
  const link=page.getByRole("link",{name:"レス1の削除依頼・問い合わせ",exact:true});
  assert.ok(await link.isVisible());
  const box=await link.boundingBox();assert.ok(box.height>=44,"touch target");
  await Promise.all([page.waitForNavigation(),link.click()]);
  for(const [name,value] of Object.entries({board:"reports",thread,ranges:"1"})) assert.equal(await page.locator(`[name="${name}"]`).inputValue(),value);
  assert.ok((await page.locator("#report-form").textContent()).includes("25分に1件"));
  assert.ok(await page.getByRole("link",{name:"対象のレスを確認する（別タブ）"}).isVisible());
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),"horizontal overflow");
  if(process.env.OIMO_LAYOUT_SCREENSHOTS) {
   await mkdir(process.env.OIMO_LAYOUT_SCREENSHOTS,{recursive:true});
   await page.screenshot({path:`${process.env.OIMO_LAYOUT_SCREENSHOTS}/reports-${width}.png`,fullPage:true});
  }
 }
 await page.locator('[name="reason"]').fill("対象レスの削除を依頼します。");
 const submit=page.getByRole("button",{name:"依頼を送る",exact:true});
 const response=page.waitForNavigation();await submit.click();const accepted=await response;assert.equal(accepted.status(),201,await accepted.text());
 const codes=await page.locator("main code").allTextContents();assert.equal(codes.length,2);
 await page.goto(`${base}/reports?board=reports&thread=${thread}&ranges=1`);
 await page.locator('[name="reason"]').fill("連続送信時の入力を保持");
 await page.locator('[name="contact"]').fill("report@example.test");
 const limited=page.waitForNavigation();await submit.click();const limitedResponse=await limited;
 assert.equal(limitedResponse.status(),429);
 assert.ok(Number(limitedResponse.headers()["retry-after"])>1400);
 assert.equal(await page.locator('[name="reason"]').inputValue(),"連続送信時の入力を保持");
 assert.equal(await page.locator('[name="contact"]').inputValue(),"report@example.test");
 await page.locator('[name="id"]').fill(codes[0]);await page.locator('[name="secret"]').fill(codes[1]);
 const lookup=page.waitForNavigation();await page.getByRole("button",{name:"照会する",exact:true}).click();assert.equal((await lookup).status(),200);
 assert.ok((await page.locator("main").textContent()).includes(codes[0]));
 assert.deepEqual(errors,[]);
 // JavaScriptなしでもレス指定とフォーム入力を利用できる。
 const plain=await browser.newContext({javaScriptEnabled:false});const noJS=await plain.newPage();
 await noJS.goto(`${base}/test/read.cgi/reports/${thread}/`);
 await Promise.all([noJS.waitForNavigation(),noJS.getByRole("link",{name:"レス1の削除依頼・問い合わせ",exact:true}).click()]);
 assert.equal(await noJS.locator('[name="ranges"]').inputValue(),"1");
 await plain.close();await context.close();
 console.log("PASS: interval setting, response links, desktop/mobile layout, acceptance, cooldown, preserved input, lookup, no-JS route");
} finally {await browser.close();}
