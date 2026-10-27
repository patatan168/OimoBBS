/** 隔離した実管理ルートで、読み込むCSS/JS・通信エラー・画面操作を検証する。 */
import assert from "node:assert/strict";
import {createRequire} from "node:module";
const {chromium}=createRequire(import.meta.url)(process.env.OIMO_PLAYWRIGHT);
const browser=await chromium.launch({headless:true,executablePath:process.env.OIMO_CHROMIUM,args:["--no-sandbox"]});
try {
 const page=await browser.newPage();const errors=[];page.on("pageerror",e=>errors.push(e.message));
 page.on("response",r=>{if(["script","stylesheet"].includes(r.request().resourceType())&&r.status()>=400)errors.push(`${r.status()} ${r.url()}`);});
 const base=process.env.OIMO_LAYOUT_URL,board=process.env.OIMO_LAYOUT_BOARD;
 const common=["ui.css","admin.css","ui.js","admin.js"];
 async function visit(route,extra,root=base,shared=common) {
  const requests=[];
  const listener=r=>{if(["script","stylesheet"].includes(r.resourceType()))requests.push(new URL(r.url()).pathname.split("/").at(-1));};
  page.on("request",listener);
  try {
   const response=await page.goto(root+route);
   assert.equal(response.status(),200,route);
   if(root===base&&!route.startsWith("/login")&&!route.startsWith("/reauth")) {
    const section="/"+(route.split("?")[0].split("/")[1]||"");
    const href=new URL(base).pathname+section;
    assert.ok((await response.text()).includes(`href="${href}" aria-current="page"`),`current marker must be in HTML on ${route}`);
    assert.deepEqual(await page.locator('.site-header nav a[aria-current="page"]').evaluateAll(nodes=>[...new Set(nodes.map(n=>new URL(n.href).pathname))]),[href]);
   }
   const wanted=[...shared,...extra].sort();
   assert.deepEqual(requests.sort(),wanted,`unexpected asset download on ${route}`);
   const declared=await page.locator('link[rel="stylesheet"],script[src]').evaluateAll(nodes=>nodes.map(n=>new URL(n.href||n.src).pathname.split("/").at(-1)).sort());
   assert.deepEqual(declared,wanted,route);
   // 同じOriginのアイコンがCSPで拒否されず、ブラウザーで画像として描画できることを確認する。
   assert.equal(await page.locator('link[rel="icon"]').count(),1,route);
   assert.equal(await page.locator('link[rel="icon"]').evaluate(link=>new Promise(resolve=>{
    const icon=new Image();icon.onload=()=>resolve(icon.naturalWidth>0&&icon.naturalHeight>0);icon.onerror=()=>resolve(false);icon.src=link.href;
   })),true,`favicon blocked or invalid on ${route}`);
   for(const width of [320,1024]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,route);}
  }finally{page.off("request",listener);}
 }
 await visit("/login",["admin-auth.css","admin-auth.js"]);
 await page.locator('input[name="login"]').fill("owner");await page.locator('input[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
 await Promise.all([page.waitForNavigation(),page.locator('button[type="submit"]').click()]);
 await visit("/reauth?return_to=%2Fboards",["admin-auth.css","admin-auth.js"]);
 await page.locator('input[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
 await Promise.all([page.waitForNavigation(),page.locator('form[action*="/reauth"] button[type="submit"]').click()]);
 const settings=["admin-settings.css","admin-settings.js"];
 const countries=["countries.css","countries.js","list.css","list.js"];
 const routes=[
  ["/",[]],["/maintenance",[]],["/manual",["admin-access.css"]],["/caps",["dates.css","dates.js"]],
  ["/boards",["list.css","list.js"]],
  [`/boards/${board}/settings`,[...settings,...countries,"admin-board.css","admin-board.js"]],
  [`/boards/${board}/rules`,["admin-rules.css","admin-rules.js"]],
  [`/boards/${board}/thread-settings`,[...settings,"admin-thread-settings.css","admin-thread-settings.js"]],
  ["/reading",[...settings,...countries,"protection.css","admin-reading.css"]],
  ["/waf",[...settings,"protection.css","admin-waf.css","admin-waf.js"]],
  ["/abuse-guard",[...settings,"admin-bot.css"]],["/operations",settings],
  ["/networks",["admin-networks.css","list.css","list.js","admin-networks.js"]],
  ["/audit",["admin-audit.css","admin-audit.js","dates.css","dates.js"]],["/passkeys",["admin-auth.css","admin-auth.js"]],
  ["/administrators",["admin-access.css","admin-access.js"]],
  ["/board-categories",["admin-categories.css","list.css","list.js"]],
 ];
 for(const [route,extra] of routes)await visit(route,extra);
 const publicBase=process.env.OIMO_ASSETS_PUBLIC_URL;
 const publicCommon=["ui.css","public.css","ui.js"];
 await visit("/",["list.css","list.js"],publicBase,publicCommon);
 await visit("/web/terms",[],publicBase,publicCommon);
 await visit(`/test/read.cgi/reports/${process.env.OIMO_ASSETS_THREAD}/`,["thread.css","thread.js"],publicBase,publicCommon);
 assert.equal(await page.locator("[data-response-jump]").isVisible(),true);
 assert.equal(await page.locator(".response-body").evaluate(node=>getComputedStyle(node).fontSize),"15px");
 assert.deepEqual(errors,[]);
 console.log(`PASS: ${routes.length+2} actual admin routes and 3 public routes download exactly their CSS/JS; no asset/JS errors; 320/1024px`);
}finally{await browser.close();}
