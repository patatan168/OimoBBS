/** 隔離した管理画面で、最新版の確認から再起動への同意・受付までを検証する。 */
import assert from "node:assert/strict";
import {createRequire} from "node:module";
import {mkdir} from "node:fs/promises";

const {chromium}=createRequire(import.meta.url)(process.env.OIMO_PLAYWRIGHT);
const browser=await chromium.launch({headless:true,executablePath:process.env.OIMO_CHROMIUM,args:["--no-sandbox"]});
try {
 const page=await browser.newPage();
 const errors=[];page.on("pageerror",error=>errors.push(error.message));
 const base=process.env.OIMO_LAYOUT_URL;
 let applyRequests=0;
 page.on("request",request=>{if(request.method()==="POST"&&new URL(request.url()).pathname.endsWith("/updates/apply"))applyRequests++;});
 await page.goto(base+"/login");
 await page.locator('input[name="login"]').fill("owner");
 await page.locator('input[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
 await Promise.all([page.waitForNavigation(),page.locator('button[type="submit"]').click()]);
 await page.goto(base+"/updates");
 await Promise.all([page.waitForNavigation(),page.getByRole("button",{name:"最新版を確認する",exact:true}).click()]);
 await page.getByRole("link",{name:"更新内容と再起動を確認する",exact:true}).click();
 assert.equal(await page.locator("h1").textContent(),"更新・再起動の確認");
 assert.equal(await page.getByRole("button",{name:"更新して再起動する",exact:true}).count(),0);
 await page.getByRole("link",{name:"再認証する",exact:true}).click();
 await page.locator('input[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
 await Promise.all([page.waitForNavigation(),page.locator('form[action*="/reauth"] button[type="submit"]').click()]);
 assert.ok(page.url().endsWith("/updates"));
 await page.getByRole("link",{name:"更新内容と再起動を確認する",exact:true}).click();
 await page.getByRole("link",{name:"キャンセル",exact:true}).click();
 assert.equal(applyRequests,0);
 await page.getByRole("link",{name:"更新内容と再起動を確認する",exact:true}).click();
 const screenshotDirectory=process.env.OIMO_UPDATE_SCREENSHOTS;
 if(screenshotDirectory)await mkdir(screenshotDirectory,{recursive:true});
 for(const colorScheme of ["light","dark"]) {
  await page.emulateMedia({colorScheme});
  for(const width of [320,390,1024,2200,2600,3199,3200,3840]) {
   await page.setViewportSize({width,height:1000});
   const dimensions=await page.evaluate(()=>({viewport:innerWidth,scroll:document.documentElement.scrollWidth,nav:document.querySelector('.admin-nav-wide').getBoundingClientRect().width,brand:document.querySelector('.brand').getBoundingClientRect().width}));
   assert.equal(dimensions.scroll<=width,true,`overflow ${colorScheme}/${width}: ${JSON.stringify(dimensions)}`);
   assert.equal(await page.locator('input[name="revision"]').inputValue(),"b".repeat(40));
   if(screenshotDirectory)await page.screenshot({path:`${screenshotDirectory}/confirm-${colorScheme}-${width}.png`,fullPage:true});
  }
 }
 const plain=await browser.newContext({javaScriptEnabled:false,storageState:await page.context().storageState()});
 const plainPage=await plain.newPage();
 assert.equal((await plainPage.goto(base+"/updates/confirm")).status(),200);
 assert.equal(await plainPage.getByRole("button",{name:"更新して再起動する",exact:true}).isVisible(),true);
 await plain.close();
 const form=page.locator('form[action$="/updates/apply"]');
 assert.equal(await form.evaluate(node=>node.checkValidity()),false);
 await page.getByRole("button",{name:"更新して再起動する",exact:true}).click();
 assert.equal(applyRequests,0,"unchecked confirmation submitted");
 await page.locator('input[name="restart_confirmed"]').check();
 assert.equal(await form.evaluate(node=>node.checkValidity()),true);
 await Promise.all([page.waitForNavigation(),page.getByRole("button",{name:"更新して再起動する",exact:true}).click()]);
 assert.equal(applyRequests,1);
 assert.equal(await page.getByRole("heading",{name:"ビルド・検証中",exact:true}).isVisible(),true);
 assert.equal(await page.getByRole("button",{name:"最新版を確認する",exact:true}).count(),0);
 await page.getByRole("link",{name:"状態を更新する",exact:true}).click();
 assert.equal(applyRequests,1,"refresh restarted update");
 assert.deepEqual(errors,[]);
 console.log("PASS: update confirmation, cancellation, reauthentication return, consent required, one apply, no-JS, light/dark 320 through 3840px");
} finally {await browser.close();}
