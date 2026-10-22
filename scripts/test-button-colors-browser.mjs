/** 実画面の操作部品を明暗両テーマでホバーし、文字と背景のコントラストを検証する。 */
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {mkdir} from 'node:fs/promises';
const {chromium}=createRequire(import.meta.url)(process.env.OIMO_PLAYWRIGHT);
const browser=await chromium.launch({headless:true,executablePath:process.env.OIMO_CHROMIUM,args:['--no-sandbox']});
const failures=[];
let checked=0;
try {
 const page=await browser.newPage({reducedMotion:'reduce'});
 const base=process.env.OIMO_LAYOUT_URL;
 /** 透明な背景を祖先の背景に重ね、実際に描画される色同士を比較する。 */
 async function inspect(control,label) {
  const result=await control.evaluate(el=>{
   const rgb=value=>value.match(/[\d.]+/g).map(Number);
   const over=(front,back)=>front.slice(0,3).map((v,i)=>v*(front[3]??1)+back[i]*(1-(front[3]??1))).concat(1);
   const chain=[];for(let node=el;node;node=node.parentElement)chain.unshift(node);
   let bg=[255,255,255,1];for(const node of chain)bg=over(rgb(getComputedStyle(node).backgroundColor),bg);
   let fg=over(rgb(getComputedStyle(el).color),bg);
   const filter=getComputedStyle(el).filter;
   const brightness=filter.match(/brightness\(([\d.]+)\)/);
   if(brightness){const factor=Number(brightness[1]);bg=bg.map((v,i)=>i<3?Math.min(255,v*factor):v);fg=fg.map((v,i)=>i<3?Math.min(255,v*factor):v);}
   const lum=c=>c.slice(0,3).map(v=>{v/=255;return v<=.04045?v/12.92:((v+.055)/1.055)**2.4;}).reduce((n,v,i)=>n+v*[.2126,.7152,.0722][i],0);
   const a=lum(fg),b=lum(bg);
   return {ratio:(Math.max(a,b)+.05)/(Math.min(a,b)+.05),text:el.textContent.trim().replace(/\s+/g,' ').slice(0,60),fg,bg};
  });
  checked++;
  if(result.ratio<4.5)failures.push({label,...result});
 }
 /** 操作は実行せず、折りたたみ内も開いて通常・ホバー状態を検査する。 */
 async function audit(route,root=base) {
  assert.equal((await page.goto(root+route)).status(),200,route);
  await page.locator('main details').evaluateAll(nodes=>nodes.forEach(el=>el.open=true));
  const controls=page.locator('button:not(:disabled),a.action-button,nav a,.tonal-link');
  for(const control of await controls.all()) {
   if(!await control.isVisible())continue;
   await page.mouse.move(0,0);
   await inspect(control,`${route}:normal`);
   await control.hover({force:true});
   await inspect(control,`${route}:hover`);
  }
 }
 for(const theme of ['dark','light']) {
  await page.emulateMedia({colorScheme:theme});
  await audit('/login');
 }
 {
   await page.locator('[name="login"]').fill('owner');
   await page.locator('[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
   await Promise.all([page.waitForNavigation(),page.locator('button[type="submit"]').click()]);
   await page.goto(base+'/reauth?return_to=%2Fevidence');
   await page.locator('[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
   await Promise.all([page.waitForNavigation(),page.locator('form[action*="/reauth"] button[type="submit"]').click()]);
 }
 for(const theme of ['light','dark']) {
  await page.emulateMedia({colorScheme:theme});
  for(const route of ['/','/evidence','/evidence?kind=other','/maintenance','/waf','/operations','/anonymous','/boards','/caps','/abuse-guard','/auto-reports','/reports','/passkeys','/board-categories','/networks','/audit','/reading','/administrators',`/boards/${process.env.OIMO_LAYOUT_BOARD}/settings`, `/boards/${process.env.OIMO_LAYOUT_BOARD}/rules`, `/boards/${process.env.OIMO_LAYOUT_BOARD}/thread-settings`])await audit(route);
  for(const route of ['/',`/reports/`,`/test/read.cgi/reports/${process.env.OIMO_ASSETS_THREAD}/`])await audit(route,process.env.OIMO_ASSETS_PUBLIC_URL);
  if(process.env.OIMO_BUTTON_SCREENSHOTS) {
   await mkdir(process.env.OIMO_BUTTON_SCREENSHOTS,{recursive:true});
   await page.goto(base+'/evidence');
   await page.locator('.evidence-kinds a[aria-current]').hover();
   await page.screenshot({path:`${process.env.OIMO_BUTTON_SCREENSHOTS}/evidence-${theme}.png`,fullPage:true});
  }
 }
 console.log(JSON.stringify({checked,failures},null,2));
 assert.deepEqual(failures,[],'操作部品の文字コントラストは通常・ホバーとも4.5以上');
}finally {await browser.close();}
