/** 隔離サイトで閉鎖確認・再認証・公開停止と、明暗両テーマの画面を検証する。 */
import assert from "node:assert/strict";
import {createRequire} from "node:module";
import {mkdir} from "node:fs/promises";

const {chromium}=createRequire(import.meta.url)(process.env.OIMO_PLAYWRIGHT);
const base=process.env.OIMO_LAYOUT_URL;
const publicBase=base.replace(/\/admin\/?$/,"");
const directory=process.env.OIMO_LAYOUT_SCREENSHOTS;
const browser=await chromium.launch({headless:true,executablePath:process.env.OIMO_CHROMIUM,args:["--no-sandbox"]});
try {
 const context=await browser.newContext();
 const page=await context.newPage();const errors=[];
 page.on("pageerror",e=>errors.push(e.message));
 await page.goto(base+"/login");
 await page.locator('input[name="login"]').fill("owner");
 await page.locator('input[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
 await Promise.all([page.waitForNavigation(),page.locator('button[type="submit"]').click()]);
 await page.goto(base+"/boards/"+process.env.OIMO_CLOSURE_BOARD+"/settings");
 const settings=page.url();
 if(directory)await mkdir(directory,{recursive:true});
 for(const colorScheme of ["light","dark"]) {
  await page.emulateMedia({colorScheme});
  for(const width of [320,390,1280]) {
   await page.setViewportSize({width,height:1000});
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
   for(const link of await page.locator(".board-settings-tabs a").all()) {
    const box=await link.boundingBox();assert.ok(box.height>=44);
   }
   if(directory){await page.screenshot({path:`${directory}/board-settings-open-${colorScheme}-${width}.png`,fullPage:true});if(width===1280)await page.locator(".board-context").screenshot({path:`${directory}/board-settings-menu-${colorScheme}.png`});}
  }
 }
 assert.equal((await page.request.get(publicBase+"/browser_closure/")).status(),200);
 await page.getByRole("link",{name:"板を閉鎖",exact:true}).click();
 const closure=page.url();
 assert.match(new URL(closure).pathname,/\/boards\/[0-9a-f]{32}\/close$/);
 assert.equal(await page.getByRole("button",{name:"この板を閉鎖する",exact:true}).isDisabled(),true);
 await page.getByRole("link",{name:"再認証して板を閉鎖する",exact:true}).click();
 await page.locator('input[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
 await Promise.all([page.waitForNavigation(),page.locator('form[action*="/reauth"] button[type="submit"]').click()]);
 assert.equal(page.url(),closure);
 assert.ok((await page.locator("main").innerText()).includes("最優先"));
 if(directory)await mkdir(directory,{recursive:true});
 for(const colorScheme of ["light","dark"]) {
  await page.emulateMedia({colorScheme});
  for(const width of [390,1280]) {
   await page.setViewportSize({width,height:1000});
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
   assert.ok(await page.getByRole("button",{name:"この板を閉鎖する",exact:true}).isVisible());
   if(directory)await page.screenshot({path:`${directory}/board-close-${colorScheme}-${width}.png`,fullPage:true});
  }
 }
 const plain=await browser.newContext({javaScriptEnabled:false,storageState:await context.storageState()});
 const noJS=await plain.newPage();
 assert.equal((await noJS.goto(closure)).status(),200);
 assert.equal(await noJS.getByLabel("確認用の板キー",{exact:true}).count(),1);
 await noJS.close();await plain.close();
 await page.getByLabel("確認用の板キー",{exact:true}).fill("wrong");
 await Promise.all([page.waitForNavigation(),page.getByRole("button",{name:"この板を閉鎖する",exact:true}).click()]);
 assert.ok(await page.getByRole("alert").isVisible());
 assert.equal(await page.getByLabel("確認用の板キー",{exact:true}).inputValue(),"wrong");
 assert.equal((await page.request.get(publicBase+"/browser_closure/")).status(),200);
 await page.getByLabel("確認用の板キー",{exact:true}).fill("browser_closure");
 await Promise.all([page.waitForNavigation(),page.getByRole("button",{name:"この板を閉鎖する",exact:true}).click()]);
 assert.ok((await page.getByRole("status").filter({hasText:"閉鎖済み"}).innerText()).includes("閉鎖済み"));
 assert.equal(await page.getByRole("button",{name:"この板を閉鎖する",exact:true}).count(),0);
 for(const route of ["/browser_closure/","/browser_closure/subject.txt","/browser_closure/SETTING.TXT","/web/post?bbs=browser_closure"]) {
  assert.equal((await page.request.get(publicBase+route)).status(),410,route);
 }
 const menu=await page.request.get(publicBase+"/bbsmenu.html");
 assert.ok(!(await menu.text()).includes("browser_closure"));
 await page.goto(settings);
 assert.ok((await page.getByRole("status").filter({hasText:"閉鎖済み"}).innerText()).includes("閉鎖済み"));
 const disabled=page.locator(".board-settings-fields");
 assert.equal(await disabled.getAttribute("disabled"),"");
 assert.equal(await disabled.locator("input:not(:disabled),select:not(:disabled),textarea:not(:disabled),button:not(:disabled)").count(),0);
 assert.equal(await page.locator(".board-settings-tabs a[href*='/metadata'],.board-settings-tabs a[href*='/reading'],a[href*='oimo_cap_only']").count(),0);
 assert.equal(await page.locator('.board-settings-tabs [aria-disabled="true"]').count(),5);
 assert.equal(await page.getByRole("button",{name:"閉鎖済みのため保存できません",exact:true}).isDisabled(),true);
 for(const colorScheme of ["light","dark"]) {
  await page.emulateMedia({colorScheme});
  for(const width of [320,390,1280]) {
   await page.setViewportSize({width,height:1000});
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
   if(directory)await page.screenshot({path:`${directory}/board-settings-closed-${colorScheme}-${width}.png`,fullPage:true});
  }
 }
 const readonly=await browser.newContext({javaScriptEnabled:false,storageState:await context.storageState()});
 const readonlyPage=await readonly.newPage();
 await readonlyPage.goto(settings);
 assert.equal(await readonlyPage.locator('.board-settings-fields input:not(:disabled),.board-settings-fields select:not(:disabled),.board-settings-fields button:not(:disabled)').count(),0);
 await readonly.close();
 for(const route of ["metadata","reading","local-rules","thread-settings","rules"]) {
  await page.goto(settings.replace(/settings$/,route));assert.equal(page.url(),settings);
 }
 await page.goto(base+"/boards");
 const row=page.locator("li").filter({hasText:"閉鎖の動作確認板"});
 assert.ok((await row.innerText()).includes("閉鎖済み"));
 await row.locator("summary").click();
 assert.equal(await row.locator('[aria-disabled="true"]').count(),5);
 assert.equal(await row.locator('a[href$="/rules"],a[href$="/reading"],a[href$="/thread-settings"],a[href$="/local-rules"],a[href*="oimo_cap_only"]').count(),0);
 if(directory)await page.screenshot({path:`${directory}/board-list-closed.png`,fullPage:true});
 assert.deepEqual(errors,[]);
 console.log("PASS: compact setting tabs, closed inputs/links, no-JS read-only, direct URL redirects, closure/public routes, light/dark 320/390/1280px");
} finally {await browser.close();}
