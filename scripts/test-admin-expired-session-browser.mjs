/** HTML受信後のセッション消失でも、拒否された資産に依存せずログインへ復帰する。 */
import assert from 'node:assert/strict';
import {mkdir} from 'node:fs/promises';
import {join} from 'node:path';
import {createRequire} from 'node:module';
const {chromium,firefox}=createRequire(import.meta.url)(process.env.OIMO_PLAYWRIGHT);
const browser=await (process.env.OIMO_FIREFOX ? firefox.launch({headless:true}) : chromium.launch({headless:true,executablePath:process.env.OIMO_CHROMIUM,args:['--no-sandbox']}));
try {
 const page=await browser.newPage();const base=process.env.OIMO_LAYOUT_URL;
 const violations=[];await page.exposeFunction('recordViolation',directive=>violations.push(directive));
 await page.addInitScript(()=>document.addEventListener('securitypolicyviolation',e=>window.recordViolation(e.violatedDirective)));
 await page.goto(base+'/login');await page.locator('[name="login"]').fill('owner');await page.locator('[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
 await Promise.all([page.waitForNavigation(),page.locator('button[type="submit"]').click()]);
 const denied=[];
 await page.route('**/web/assets/page/**',async route=>{
  const request=route.request(),scope=new URL(request.url()).pathname.split('/page/')[1].split('/')[0];
  if(Buffer.from(scope,'base64url').toString()!=='/operations')return route.continue();
  const headers=await request.allHeaders();headers.cookie="";
  const response=await route.fetch({headers});denied.push({method:request.method(),status:response.status()});
  await route.fulfill({response});
 });
 await page.goto(base+'/operations').catch(error=>{if(!error.message.includes('interrupted by another navigation'))throw error;});
 await page.waitForURL(base+'/login');
 await page.waitForLoadState('networkidle');
 assert.ok(denied.some(r=>r.status===401));assert.ok(denied.some(r=>r.method==='HEAD'&&r.status===401));
 assert.equal(await page.locator('[data-login-form]').isVisible(),true);
 assert.ok(await page.locator('link[rel="stylesheet"]').evaluateAll(nodes=>nodes.every(n=>n.sheet)));
 for(const width of [320,1024]) {await page.setViewportSize({width,height:900});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);}
 assert.deepEqual(violations,[],'fixed inline recovery must satisfy CSP');
 await page.unroute('**/web/assets/page/**');await page.context().clearCookies();
 const response=await page.goto(base+'/operations');assert.equal(response.status(),401);await page.waitForLoadState('networkidle');
 assert.equal(await page.locator('[data-login-form]').isVisible(),true);
 assert.ok(await page.locator('link[rel="stylesheet"]').evaluateAll(nodes=>nodes.every(n=>n.sheet)));
 assert.ok(await page.locator('main').innerText().then(text=>text.includes('ログインの有効期限')));
 if(process.env.OIMO_SESSION_SCREENSHOT_DIR) {
  await mkdir(process.env.OIMO_SESSION_SCREENSHOT_DIR,{recursive:true});
  for(const width of [320,1024]) {await page.setViewportSize({width,height:900});await page.screenshot({path:join(process.env.OIMO_SESSION_SCREENSHOT_DIR,`expired-${process.env.OIMO_FIREFOX?'firefox':'chromium'}-${width}.png`),fullPage:true});}
 }
 await page.route('**/web/assets/page/**',route=>route.fulfill({status:403,body:'blocked'}));
 let navigations=0;page.on('request',request=>{if(request.resourceType()==='document')navigations++;});
 await page.goto(base+'/login');await page.waitForLoadState('networkidle');
 assert.equal(navigations,1,'a denied asset must not cause a reload loop');
 assert.ok(await page.locator('svg').evaluateAll(nodes=>nodes.every(node=>node.getBoundingClientRect().width<=40)),'fallback icons must remain bounded');
 assert.deepEqual(violations,[]);
 console.log('PASS: assets denied after HTML200 redirect to styled login; HTML401 shows styled login; CSP and 320/1024px verified');
}finally{await browser.close();}
