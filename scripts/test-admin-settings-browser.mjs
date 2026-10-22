/** 隔離サーバーの実設定フォームで、変更確認・入力エラー・保存・JSなしの操作を検証する。 */
import assert from "node:assert/strict";
import {createRequire} from "node:module";
import {mkdir} from "node:fs/promises";
const {chromium}=createRequire(import.meta.url)(process.env.OIMO_PLAYWRIGHT);
const browser=await chromium.launch({headless:true,executablePath:process.env.OIMO_CHROMIUM,args:["--no-sandbox"]});
try {
 const page=await browser.newPage();const errors=[];page.on("pageerror",e=>errors.push(e.message));
 const base=process.env.OIMO_LAYOUT_URL;
 const board=process.env.OIMO_LAYOUT_BOARD;
 const boardPath=`/boards/${board}/settings`;
 const form=page.locator("form[data-settings-form]");
 const review=page.locator("[data-settings-review]");
 const field=name=>form.locator(`[name="${name}"]:not([type="hidden"])`);
 const visit=async route=>{assert.equal((await page.goto(base+route)).status(),200,route);await review.waitFor({state:"visible"});};
 const save=async()=>{await Promise.all([page.waitForNavigation(),form.locator('button[type="submit"]').last().click()]);};
 const edited=async text=>{await page.waitForFunction(()=>document.querySelector('[data-settings-review]').dataset.edited==='true');assert.ok((await review.textContent()).includes(text));};
 await page.goto(base+"/login");
 await page.locator('input[name="login"]').fill("owner");
 await page.locator('input[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
 await Promise.all([page.waitForNavigation(),page.locator('button[type="submit"]').click()]);
 await page.goto(base+"/reauth?return_to=%2Fboards");
 await page.locator('input[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
 await Promise.all([page.waitForNavigation(),page.locator('form[action*="/reauth"] button[type="submit"]').click()]);
 await visit(boardPath);
 assert.equal(await review.getAttribute("data-edited"),"false");
 const originalLines=await field("body_lines").inputValue();
 await field("noname").fill('<img src=x onerror="bad()">');
 await edited("名無し名");assert.equal(await review.locator("img").count(),0,"preview rendered input HTML");
 await field("noname").fill("設定を確認した名無し");
 if(process.env.OIMO_LAYOUT_SCREENSHOTS) {
  await mkdir(process.env.OIMO_LAYOUT_SCREENSHOTS,{recursive:true});
  await review.locator("summary").click();
  await review.screenshot({path:`${process.env.OIMO_LAYOUT_SCREENSHOTS}/draft-review.png`});
 }
 await page.getByRole("link",{name:"文字数・行数",exact:true}).click();
 assert.equal(await page.locator("#board-limits").getAttribute("open"),"");
 await field("body_lines").fill("3");
 await page.locator("#board-limits > summary").click();
 let posts=0;page.on("request",r=>{if(r.method()==="POST"&&r.url()===base+boardPath)posts++;});
 await form.locator('button[type="submit"]').click();
 assert.equal(await page.locator("#board-limits").getAttribute("open"),"","invalid field stayed hidden");
 assert.equal(posts,0,"invalid numeric form submitted");
 await field("body_lines").fill(originalLines);
 await save();assert.equal(await field("noname").inputValue(),"設定を確認した名無し");
 assert.equal(await review.getAttribute("data-edited"),"false");
 // 複数行の回線設定を追加・削除しても、通常のFormDataを変更しない。
 await page.getByText("この板だけの回線名・ID末尾の上書き",{exact:true}).click();
 await page.locator("[data-network-add]").click();
 await field("network_cidr").last().fill("192.0.2.0/24");
 await edited("IPアドレスまたは範囲");
 await page.locator("[data-network-remove]").last().click();
 await page.waitForFunction(()=>document.querySelector('[data-settings-review]').dataset.edited==='false');
 // 国名・英語名・全角コードで検索しても、非表示の国の許可状態を保存から落とさない。
 await page.locator("#board-network > summary").click();
 await page.getByText("国ごとの許可を設定する",{exact:true}).click();
 const countryOptions=page.locator(".country-permissions");
 const countrySearch=countryOptions.locator("..").locator('input[type="search"]');
 const visibleCountries=()=>countryOptions.locator("[data-country-row]:not([hidden]) .country-code").allTextContents();
 await countrySearch.fill("日本");assert.deepEqual(await visibleCountries(),["JP"]);
 await countrySearch.fill("united states");assert.deepEqual(await visibleCountries(),["US"]);
 const originalUS=await form.locator('[name="allow_country"][value="US"]').isChecked();
 await form.locator('[name="allow_country"][value="US"]').uncheck();
 await countrySearch.fill("ｊｐ");assert.deepEqual(await visibleCountries(),["JP"]);
 await save();
 assert.equal(await form.locator('[name="allow_country"][value="US"]').isChecked(),false);
 assert.equal(await form.locator('[name="allow_country"][value="JP"]').isChecked(),true);
 await page.locator("#board-network > summary").click();
 await page.getByText("国ごとの許可を設定する",{exact:true}).click();
 await form.locator('[name="allow_country"][value="US"]').setChecked(originalUS);
 if(process.env.OIMO_LAYOUT_SCREENSHOTS) {
  await page.setViewportSize({width:390,height:1000});
  await countryOptions.locator("..").screenshot({path:`${process.env.OIMO_LAYOUT_SCREENSHOTS}/country-picker-390.png`});
 }
 await save();
 await visit("/operations");
 await field("egress_mbps").fill("81");await edited("81");await save();
 assert.equal(await field("egress_mbps").inputValue(),"81");
 await visit("/waf");
 const wafState=async expected=>assert.deepEqual(await page.locator("[data-waf-result]").allTextContents(),expected);
 const originalRate=await field("client_rate").inputValue();
 await field("enabled").selectOption("false");
 await wafState(["OFF","OFF","OFF"]);
 assert.equal(await field("traffic_enabled").isDisabled(),true);
 await save();
 assert.equal(await field("client_rate").inputValue(),originalRate);
 await field("enabled").selectOption("true");
 await field("traffic_enabled").selectOption("false");
 await wafState(["ON","OFF","OFF"]);
 assert.equal(await field("global_rate").isDisabled(),true);
 await field("traffic_enabled").selectOption("true");
 await field("client_enabled").selectOption("false");
 await wafState(["ON","ON","OFF"]);
 assert.equal(await field("client_rate").isDisabled(),true);
 assert.equal(await field("global_rate").isEnabled(),true);
 await field("client_enabled").selectOption("true");
 await wafState(["ON","ON","ON"]);
 await edited("要求の検査");await save();
 assert.equal(await field("enabled").inputValue(),"true");
 await visit("/reading");
 await page.getByText("IPアドレス・クローラー・UAの条件",{exact:true}).click();
 await field("deny_crawlers").selectOption("true");await edited("既知クローラー");await save();
 assert.equal(await field("deny_crawlers").inputValue(),"true");
 await page.getByText("国名とコードを確認",{exact:true}).click();
 const countryGuide=page.locator(".country-guide");
 const guideSearch=countryGuide.locator('input[type="search"]');
 const guideCodes=()=>countryGuide.locator("[data-country-row]:not([hidden]) .country-code").allTextContents();
 await guideSearch.fill("日本");assert.deepEqual(await guideCodes(),["JP"]);
 await guideSearch.fill("US");assert.deepEqual(await guideCodes(),["US"]);
 await guideSearch.fill("United States");assert.deepEqual(await guideCodes(),["US"]);
 await guideSearch.fill("一致しない国名");assert.deepEqual(await guideCodes(),[]);
 assert.ok((await countryGuide.textContent()).includes("一致する国がありません"));
 await guideSearch.fill("");
 assert.equal(await review.getAttribute("data-edited"),"false","country search changed settings");
 for(const width of [320,390,1024]) {
  await page.setViewportSize({width,height:1000});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,`country guide/${width}`);
  if(process.env.OIMO_LAYOUT_SCREENSHOTS)await countryGuide.screenshot({path:`${process.env.OIMO_LAYOUT_SCREENSHOTS}/country-guide-${width}.png`});
 }
 await visit("/admin-access");
 assert.equal(await field("deny_crawlers").count(),0);
 const crawlerField=form.locator('input[type="hidden"][name="deny_crawlers"]');
 assert.equal(await crawlerField.count(),1);
 const savedCrawler=await crawlerField.inputValue();
 assert.equal(await page.locator("[data-fixed-protection]").count(),3);
 assert.equal(await page.locator('.settings-tabs [aria-current="page"]').filter({hasText:"管理画面"}).count(),1);
 assert.equal(await page.locator(".access-protection").isVisible(),true);
 assert.equal(await field("allow_local_ip").isVisible(),false);
 assert.equal(await field("enabled").inputValue(),"false");
 await save();assert.equal(await crawlerField.inputValue(),savedCrawler);
 await visit("/abuse-guard");
 await page.getByText("類似文を検出する条件（詳細設定）",{exact:true}).click();
 await field("similar_matches").fill("128");
 await field("similar_mode").selectOption("off");await edited("類似文の連投");
 const rejected=page.waitForResponse(r=>r.url()===base+"/abuse-guard"&&r.request().method()==="POST");
 await save();assert.equal((await rejected).status(),422);
 assert.equal(await field("similar_matches").inputValue(),"128");
 assert.equal(await field("similar_matches").isVisible(),true,"server-invalid value stayed hidden");
 assert.equal(await field("similar_mode").inputValue(),"off");
 await field("similar_matches").fill("3");await save();
 assert.equal(await field("similar_mode").inputValue(),"off");
 await visit(`/boards/${board}/thread-settings`);
 await field("user_post_limit").fill("1024");await edited("レス数の上限");await save();
 assert.equal(await field("user_post_limit").inputValue(),"1024");
 const routes=[boardPath,"/operations","/waf","/reading",`/boards/${board}/reading`,"/admin-access","/abuse-guard",`/boards/${board}/thread-settings`];
 if(process.env.OIMO_LAYOUT_SCREENSHOTS)await mkdir(process.env.OIMO_LAYOUT_SCREENSHOTS,{recursive:true});
 for(const route of routes) {
  await visit(route);
  assert.equal(await review.getAttribute("data-edited"),"false",route);
  for(const width of [320,390,1024]) {
   await page.setViewportSize({width,height:1000});
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,`${route}/${width}`);
   if(process.env.OIMO_LAYOUT_SCREENSHOTS)await page.screenshot({path:`${process.env.OIMO_LAYOUT_SCREENSHOTS}/settings-${route.replaceAll("/","_")}-${width}.png`,fullPage:true});
  }
  if(route==="/admin-access") {
   for(const summary of await page.locator("main details > summary").all())if(await summary.isVisible())await summary.click();
   assert.equal(await field("allow_local_ip").isVisible(),true);
   for(const width of [320,390,1024]) {
    await page.setViewportSize({width,height:1000});
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,`expanded access/${width}`);
    if(process.env.OIMO_LAYOUT_SCREENSHOTS)await page.screenshot({path:`${process.env.OIMO_LAYOUT_SCREENSHOTS}/access-expanded-${width}.png`,fullPage:true});
   }
  }
 }
 await page.emulateMedia({colorScheme:"dark"});await visit("/admin-access");
 if(process.env.OIMO_LAYOUT_SCREENSHOTS)await page.screenshot({path:`${process.env.OIMO_LAYOUT_SCREENSHOTS}/access-dark.png`,fullPage:true});
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
 // 同じ実フォームがJSなしでも全入力を送り、保存結果を読み直せる。
 const plain=await browser.newContext({javaScriptEnabled:false,storageState:await page.context().storageState()});
 const noJS=await plain.newPage();
 for(const route of [boardPath,"/operations","/reading","/admin-access","/abuse-guard",`/boards/${board}/thread-settings`,"/waf"]) {
  assert.equal((await noJS.goto(base+route)).status(),200);
  const noForm=noJS.locator("form[data-settings-form]");
  assert.equal(await noJS.locator("[data-settings-review]").isVisible(),false);
  await Promise.all([noJS.waitForNavigation(),noForm.locator('button[type="submit"]').last().click()]);
  assert.ok(!(await noJS.locator("main").textContent()).includes("設定を保存できません"),route);
  assert.equal(new URL(noJS.url()).pathname,"/admin"+route);
 }
 await plain.close();assert.deepEqual(errors,[]);
 console.log("PASS: 8 settings views, draft diff, dynamic rows, hidden invalid fields, server validation retention, real saves, 320/390/1024px and no-JS saves");
}finally{await browser.close();}
