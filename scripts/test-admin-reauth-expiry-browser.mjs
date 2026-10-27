/** 11分前に再認証した隔離セッションで、表示中の期限切れ・送信拒否・再認証からの復帰を確認する。 */
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {mkdir} from 'node:fs/promises';
const {chromium,firefox}=createRequire(import.meta.url)(process.env.OIMO_PLAYWRIGHT);
const browser=await (process.env.OIMO_FIREFOX?firefox.launch({headless:true}):chromium.launch({headless:true,executablePath:process.env.OIMO_CHROMIUM,args:['--no-sandbox']}));
let page;
try {
 page=await browser.newPage();page.setDefaultTimeout(10000);
 const base=process.env.OIMO_LAYOUT_URL;
 if(process.env.OIMO_REAUTH_SCREENSHOTS)await mkdir(process.env.OIMO_REAUTH_SCREENSHOTS,{recursive:true});
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 async function login(){
  await page.goto(base+'/login');await page.locator('[name="login"]').fill('owner');await page.locator('[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
  await Promise.all([page.waitForURL(base+'/'),page.getByRole('button',{name:'パスワードでログイン',exact:true}).click()]);
  await page.waitForLoadState('networkidle');
 }
 async function reauth(destination){
  await page.locator('[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
  await Promise.all([page.waitForURL(base+destination),page.getByRole('button',{name:/^再認証して/}).click()]);
  await page.waitForLoadState('networkidle');
 }
 /** 実時間の待機や本番用時計の差し替えを避け、生存している期限切れセッションへ切り替える。 */
 async function expire(value=process.env.OIMO_EXPIRED_COOKIE){await page.context().addCookies([{name:'oimo_admin',value,url:base+'/'}]);}
 await login();await page.goto(base+'/reauth?return_to=%2Fboards');await reauth('/boards');
 const form=page.locator('form[action="/admin/boards"]');assert.ok(await form.count());
 await form.locator('..').locator('summary').click();
 await form.locator('[name="key"]').fill('mustnotcreate');await form.locator('[name="name"]').fill('期限切れで作成されない板');
 await expire();
 // 画面の入力を残したまま期限が切れても、送信を実行せず本人確認へ案内する。
 const [response]=await Promise.all([page.waitForResponse(r=>r.url()===base+'/boards'&&r.request().method()==='POST'),form.getByRole('button',{name:'板を追加',exact:true}).click()]);
 assert.equal(response.status(),403);assert.ok((await page.locator('main').innerText()).includes('自動で再実行しません'));
 await page.waitForLoadState('load');
 if(process.env.OIMO_REAUTH_SCREENSHOTS){await page.setViewportSize({width:390,height:900});await page.screenshot({path:`${process.env.OIMO_REAUTH_SCREENSHOTS}/expired-operation-390.png`,fullPage:true});}
 await page.getByRole('link',{name:'再認証して管理画面へ戻る',exact:true}).click();
 assert.equal(new URL(page.url()).searchParams.get('return_to'),'/boards');
 await page.goto(base+'/passkeys');
 assert.equal(await page.locator('[data-passkey-register]').count(),0);
 assert.equal(await page.locator('[data-auth-policy-form]').count(),0);
 assert.ok(await page.getByRole('link',{name:'再認証して登録・削除へ進む'}).isVisible());
 await page.goto(base+'/administrators');assert.equal(new URL(page.url()).pathname,'/admin/reauth');
 assert.equal(new URL(page.url()).searchParams.get('return_to'),'/administrators');
 await page.waitForLoadState('load');
 for(const width of [320,390,1024]){
  await page.setViewportSize({width,height:900});assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
  assert.ok(await page.locator('link[rel="stylesheet"]').evaluateAll(nodes=>nodes.every(n=>n.sheet)));
  if(process.env.OIMO_REAUTH_SCREENSHOTS)await page.screenshot({path:`${process.env.OIMO_REAUTH_SCREENSHOTS}/reauth-${width}.png`,fullPage:true});
 }
 await reauth('/administrators');
 const boardsResponse=await page.request.get(base+'/api/v1/boards');assert.equal(boardsResponse.status(),200);assert.equal((await boardsResponse.text()).includes('mustnotcreate'),false);
 // HTML200の後、CSS/JS取得時に期限が切れた競合も、再認証画面へ復帰させる。
 const armed=await page.request.post(new URL('/__test/expire-reauth-during-assets',base).href);assert.equal(armed.status(),204);
 await page.goto(base+'/administrators').catch(e=>{if(!e.message.includes('interrupted by another navigation'))throw e;});
 await page.waitForURL(url=>url.pathname==='/admin/reauth');await page.waitForLoadState('load');
 assert.ok(await page.locator('link[rel="stylesheet"]').evaluateAll(nodes=>nodes.every(n=>n.sheet)));
 assert.equal(new URL(page.url()).searchParams.get('return_to'),'/administrators');
 assert.deepEqual(errors,[]);
 console.log('PASS: expired reauthentication keeps login, denies changes, hides controls, restores destination after password reauthentication; asset expiry recovery and 320/390/1024px styles');
}finally{await browser.close();}
