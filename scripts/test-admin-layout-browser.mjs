/** 管理画面の共通表示を実ルートで検証し、折りたたみ・権限・フォーム保存を確認する。 */
import assert from "node:assert/strict";
import {createRequire} from "node:module";
import {mkdir} from "node:fs/promises";
const {chromium}=createRequire(import.meta.url)(process.env.OIMO_PLAYWRIGHT);
const browser=await chromium.launch({headless:true,executablePath:process.env.OIMO_CHROMIUM,args:["--no-sandbox"]});
try {
 const page=await browser.newPage();const errors=[];page.on("pageerror",e=>errors.push(e.message));
 const base=process.env.OIMO_LAYOUT_URL;
 await page.goto(base+"/login");
 await page.locator('input[name="login"]').fill("owner");
 await page.locator('input[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
 await Promise.all([page.waitForNavigation(),page.locator('button[type="submit"]').click()]);
 await page.goto(base+"/reauth?return_to=%2Fcaps");
 await page.locator('input[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
 await Promise.all([page.waitForNavigation(),page.locator('form[action*="/reauth"] button[type="submit"]').click()]);
 await page.getByText("新しいキャップを発行",{exact:true}).click();
 await page.locator('input[name="display_name"]').fill("表示確認用キャップ");
 await page.locator('input[name="board_ids"]').first().check();
 await Promise.all([page.waitForNavigation(),page.locator('form[action$="/caps"] button[type="submit"]').click()]);
 await page.goto(base+"/caps");
 assert.equal(await page.locator("article .admin-badge").textContent(),"有効");
 assert.equal(await page.locator('article form[action$="/reset"]').isVisible(),false);
 await page.getByText("鍵をリセット・再発行",{exact:true}).click();
 assert.equal(await page.locator('article form[action$="/reset"]').isVisible(),true);
 // 値やCSRF・revisionを保った実フォームの保存を検査する。
 for(const [route,button] of [["/operations","運用設定を保存する"],["/waf","WAFの設定を保存する"]]) {
  await page.goto(base+route);
  await Promise.all([page.waitForNavigation(),page.getByRole("button",{name:button,exact:true}).click()]);
  assert.equal(new URL(page.url()).pathname,"/admin"+route);
 }
 const routes=["/","/maintenance","/waf","/operations","/anonymous","/boards","/caps","/abuse-guard","/auto-reports","/reports","/reports/"+process.env.OIMO_LAYOUT_REPORT,"/evidence"];
 if(process.env.OIMO_LAYOUT_SCREENSHOTS)await mkdir(process.env.OIMO_LAYOUT_SCREENSHOTS,{recursive:true});
 for(const route of routes) {
  const response=await page.goto(base+route);assert.equal(response.status(),200,route);
  assert.equal(await page.locator("main").count(),1,route);
  if(route==="/maintenance") {assert.ok(await page.locator(".admin-status-grid").count()>=5);assert.ok((await page.locator("main").textContent()).includes("メモリ予算"));}
  if(route==="/waf") {assert.ok((await page.locator("#waf-current-heading").textContent()).includes("現在の稼働状況"));assert.equal(await page.locator("#waf-status h2").textContent(),"起動後の累計");}
  if(route==="/auto-reports") {assert.equal(await page.locator(".admin-record-link").count(),3);assert.ok((await page.locator("main").textContent()).includes("解除済み"));}
  if(route==="/reports") {assert.ok((await page.locator("main").textContent()).includes("未対応"));assert.ok((await page.locator("main").textContent()).includes("通常削除"));}
  if(route==="/evidence")assert.ok((await page.locator(".evidence-case-title").textContent()).includes("CASE-LAYOUT-001"));
  for(const width of [320,390,1024]) {
   await page.setViewportSize({width,height:1000});
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,`overflow ${route}/${width}`);
   // カードと説明リストがHTMLの補正で壊れていないことも、実際の寸法で検査する。
   const broken=await page.locator(".admin-status-grid > div").evaluateAll(cards=>cards.some(card=>card.getBoundingClientRect().width<100));
   assert.equal(broken,false,`narrow status card ${route}/${width}`);
   await page.evaluate(()=>window.scrollTo(0,0));
   if(process.env.OIMO_LAYOUT_SCREENSHOTS)await page.screenshot({path:`${process.env.OIMO_LAYOUT_SCREENSHOTS}/${route.replaceAll("/","_")||"home"}-${width}.png`,fullPage:true});
  }
  for(const summary of await page.locator("main details > summary").all()) {
   // 表示中の最上位項目だけを開く。これにより内側の入力・操作も確認できる。
   if(await summary.isVisible())await summary.click();
  }
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,`details overflow ${route}`);
 }
 await page.emulateMedia({colorScheme:"dark"});
 for(const route of ["/maintenance","/waf","/caps"]) {
  assert.equal((await page.goto(base+route)).status(),200);
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,`dark overflow ${route}`);
  if(process.env.OIMO_LAYOUT_SCREENSHOTS)await page.screenshot({path:`${process.env.OIMO_LAYOUT_SCREENSHOTS}/${route.replaceAll("/","_")}-dark.png`,fullPage:true});
 }
 assert.deepEqual(errors,[]);
 // JSがなくても設定と詳細へ到達できる。
 const plain=await browser.newContext({javaScriptEnabled:false,storageState:await page.context().storageState()});
 const noJS=await plain.newPage();
 for(const route of ["/maintenance","/operations","/caps","/waf"]) {assert.equal((await noJS.goto(base+route)).status(),200);assert.ok(await noJS.locator("main").isVisible());}
 await plain.close();
 console.log("PASS: 12 admin routes, 320/390/1024px, dark mode, details, no-JS, cap issue, operations/WAF save, Japanese report states");
}finally{await browser.close();}
