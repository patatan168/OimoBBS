/** 隔離管理画面でCAP相当の操作をコマンド入力なしに実行し、公開反映と狭幅表示を確認する。 */
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {mkdir} from 'node:fs/promises';
import {appendFileSync} from 'node:fs';
const {chromium,firefox}=createRequire(import.meta.url)(process.env.OIMO_PLAYWRIGHT);
const browser=await (process.env.OIMO_FIREFOX ? firefox.launch({headless:true}) : chromium.launch({headless:true,executablePath:process.env.OIMO_CHROMIUM,args:['--no-sandbox']}));
const trace=stage=>{if(process.env.OIMO_ACTIONS_TRACE)appendFileSync(process.env.OIMO_ACTIONS_TRACE,stage+'\n');};
try {
 const page=await browser.newPage({javaScriptEnabled:!process.env.OIMO_NOJS});const errors=[],assetFailures=[];page.setDefaultTimeout(10000);page.setDefaultNavigationTimeout(15000);
 page.on('pageerror',e=>errors.push(e.message));
 page.on('response',response=>{if(response.url().includes('/web/assets/')&&response.status()>=400)assetFailures.push([response.status(),new URL(response.url()).pathname]);});
 const base=process.env.OIMO_ACTIONS_URL,board=process.env.OIMO_ACTIONS_BOARD,thread=process.env.OIMO_ACTIONS_THREAD;
 const postPath=`/boards/${board}/threads/${thread}/posts/1`,rulesPath=`/boards/${board}/rules`;
 const navigate=path=>page.goto(base+path);
 await navigate('/login');
 await page.locator('[name="login"]').fill('owner');await page.locator('[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
 await Promise.all([page.waitForURL(base+'/'),page.getByRole('button',{name:'パスワードでログイン',exact:true}).click()]);
 await page.waitForLoadState('networkidle');
 await navigate('/boards');assert.ok(await page.getByRole('link',{name:'レス削除・投稿者規制',exact:true}).count());
 await navigate(postPath);
 assert.equal(await page.getByRole('button',{name:'この投稿者を規制・解除',exact:true}).count(),0);
 await page.waitForLoadState('networkidle');
 await page.getByRole('link',{name:'再認証して、このスレッドへ戻る',exact:true}).click();
 await page.locator('[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
 await Promise.all([page.waitForURL(base+postPath),page.locator('button[type="submit"]').click()]);
 if(process.env.OIMO_ACTIONS_SCREENSHOTS)await mkdir(process.env.OIMO_ACTIONS_SCREENSHOTS,{recursive:true});
/** 各画面幅で横あふれを検査し、指定時は操作前の画面を保存する。 */
 async function layouts(label){
  // Firefoxへ遷移途中のviewport変更を送らず、CSSを含む表示完了後に測定する。
  await page.waitForLoadState('load');
  for(const width of [320,390,1024]){
   trace(`${label} ${width}: resize`);await page.setViewportSize({width,height:1000});trace(`${label} ${width}: resized`);
   assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),`${label}: overflow at ${width}`);trace(`${label} ${width}: measured`);
   if(process.env.OIMO_ACTIONS_SCREENSHOTS)await page.screenshot({path:`${process.env.OIMO_ACTIONS_SCREENSHOTS}/${label}-${width}.png`,fullPage:true});
  }
 }
 await trace('posts layout');await layouts('posts');
 const displayedName=await page.locator('#post-1 h2').innerText();assert.ok(displayedName.includes('('));assert.equal(displayedName.includes('</b>'),false);assert.equal(displayedName.includes('<b>'),false);
 const controls=page.locator('#post-1 .post-moderation-actions');
 const boxes=await controls.locator(':scope > form > button, :scope > details > summary').evaluateAll(nodes=>nodes.map(node=>{const b=node.getBoundingClientRect();return {y:b.y,height:b.height};}));
 assert.ok(boxes.every(box=>box.height>=44));assert.ok(boxes.every(box=>Math.abs(box.y-boxes[0].y)<1),'desktop controls must align');
 await page.getByRole('button',{name:'この投稿者を規制・解除',exact:true}).click();
 await trace('subject shortcut opened');
 const quick=page.locator('[data-quick-subject-rule]');await quick.waitFor();
 const subject=await quick.locator('[name="target"]').inputValue();assert.match(subject,/^[a-f0-9]{64}$/);
 await trace('subject layout');await layouts('subject');
 await quick.locator('[name="duration_minutes"]').selectOption('10');
 await quick.locator('[name="reason_code"]').selectOption('spam');await quick.locator('[type="checkbox"]').check();
 await Promise.all([page.waitForURL(base+rulesPath),quick.getByRole('button',{name:'この投稿者を規制する',exact:true}).click()]);
 async function rules(){const response=await page.request.get(base+'/api/v1'+rulesPath);assert.equal(response.status(),200);return (await response.json()).data.rules;}
 await trace('restriction registered');let saved=await rules();const active=saved.find(rule=>rule.target===subject&&rule.enabled);assert.ok(active);
 assert.equal(active.match.field,'token');assert.equal(active.match.effect,'deny');
 assert.equal(Date.parse(active.expires_at)-Date.parse(active.starts_at),600000);
 await navigate(postPath);await page.getByRole('button',{name:'この投稿者を規制・解除',exact:true}).click();
 await trace('restriction selected');const subjectPanel=page.locator('section[aria-labelledby="quick-subject-heading"]');
 assert.ok((await subjectPanel.innerText()).includes('適用中の規制（1件）'));
 await Promise.all([page.waitForURL(base+rulesPath),subjectPanel.getByRole('button',{name:'この規制を解除する',exact:true}).click()]);
 await trace('restriction revoked');saved=await rules();assert.equal(saved.find(rule=>rule.id===active.id).enabled,false);
 await navigate(postPath);
 await Promise.all([page.waitForURL(`${base}/boards/${board}/threads/${thread}/actions`),page.getByRole('link',{name:'スレッドを停止',exact:true}).click()]);
 await trace('stop layout');await layouts('stop');await page.locator('[data-quick-thread-stop] button').click();
 assert.ok((await page.locator('main').innerText()).includes('変更内容の確認'));
 await page.getByRole('button',{name:'この対象へ適用',exact:true}).click();
 await trace('stop applied');const state=await page.request.get(`${base}/api/v1/boards/${board}/threads/${thread}/actions`);
 assert.equal((await state.json()).data.state,'stopped');
 await page.getByRole('link',{name:'レスの管理へ戻る',exact:true}).click();
 await trace('deletion opened');const target=page.locator('#post-1');await target.getByText('このレスを削除',{exact:true}).click();
 await target.locator('input[name="confirm"]').check();
 await target.getByRole('button',{name:'このレスを削除する',exact:true}).click();
 await page.waitForURL(url=>url.pathname===new URL(base+postPath).pathname);
 assert.equal((await page.locator('main').innerText()).includes('MANAGEMENT-TARGET-BODY'),false);
 await trace('deletion applied');const publicResponse=await page.request.get(new URL(`/test/read.cgi/news/${thread}/`,base).href);
 assert.equal(publicResponse.status(),200);assert.equal((await publicResponse.text()).includes('MANAGEMENT-TARGET-BODY'),false);
 assert.deepEqual(errors,[]);assert.deepEqual(assetFailures,[]);
 console.log('PASS: scoped shortcuts, reauthentication, 10-minute subject restriction, revocation, stop confirmation, response deletion, public reflection, assets and 320/390/1024px layouts');
} catch(error) {trace('ERROR: '+error.message);throw error;} finally {await trace('closing browser');await browser.close();}
