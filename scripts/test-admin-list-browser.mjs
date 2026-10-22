/** 実際の分類一覧で、ページ送りが画面を動かさず、絞込みと編集値を保つことを確認する。 */
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {mkdir} from 'node:fs/promises';
import {join} from 'node:path';
const {chromium,firefox}=createRequire(import.meta.url)(process.env.OIMO_PLAYWRIGHT);
const browser=await (process.env.OIMO_FIREFOX ? firefox.launch({headless:true}) : chromium.launch({headless:true,executablePath:process.env.OIMO_CHROMIUM,args:['--no-sandbox']}));
try {
 const page=await browser.newPage();const base=process.env.OIMO_LAYOUT_URL,errors=[];
 page.on('pageerror',error=>errors.push(error.message));
 await page.goto(base+'/login');await page.locator('[name="login"]').fill('owner');await page.locator('[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
 await Promise.all([page.waitForNavigation(),page.locator('button[type="submit"]').click()]);
 for(const width of [320,1024]) {
  await page.setViewportSize({width,height:900});await page.goto(base+'/networks');
  const section=page.locator('section[aria-labelledby="network-sources"]'),pager=section.locator('.filter-pager'),viewport=section.locator('.filter-viewport'),rows=section.locator('.network-row'),visible=section.locator('.network-row:not([hidden])');
  const count=await rows.count();assert.ok(count>50);assert.equal(await visible.count(),10);
  assert.ok(await viewport.evaluate(n=>n.clientHeight<=560&&n.scrollHeight>n.clientHeight));
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
  const jump=pager.getByLabel('ページ',{exact:true}),size=pager.getByLabel('表示件数',{exact:true});
  async function stable(action) {
   await pager.scrollIntoViewIfNeeded();const before=await page.evaluate(()=>scrollY);
   await action();await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
   assert.ok(Math.abs((await page.evaluate(()=>scrollY))-before)<2,'pagination moved the document');
   assert.equal(await viewport.evaluate(n=>n.scrollTop),0);
  }
  await viewport.evaluate(n=>n.scrollTop=200);
  await stable(()=>pager.getByRole('button',{name:'次へ',exact:true}).click());assert.equal(await jump.inputValue(),'1');
  await stable(()=>jump.selectOption(String(Math.ceil(count/10)-1)));assert.equal(await pager.getByRole('button',{name:'次へ',exact:true}).isDisabled(),true);
  await stable(()=>jump.selectOption('2'));assert.equal(await visible.count(),10);
  await stable(()=>size.selectOption('20'));assert.equal(await jump.inputValue(),'1');assert.equal(await visible.count(),20);
  await stable(()=>jump.selectOption('0'));
  const first=visible.first();await first.locator(':scope > summary').click();await first.locator('details > summary').click();
  const name=first.locator('input[name="name"]');await name.fill('保存前の入力を保持');
  await stable(()=>jump.selectOption('1'));await stable(()=>jump.selectOption('0'));assert.equal(await name.inputValue(),'保存前の入力を保持');
  await first.locator(':scope > summary').click();
  const search=section.locator('.filter-tools input[type="search"]');await search.fill('存在しない分類12345');assert.equal(await visible.count(),0);assert.equal(await pager.getByRole('button',{name:'次へ',exact:true}).isDisabled(),true);
  await search.fill('');const kind=section.locator('.filter-tools select');const selected=await kind.locator('option').nth(1).getAttribute('value');await kind.selectOption(selected);
  assert.ok(await visible.evaluateAll((nodes,value)=>nodes.length>0&&nodes.every(n=>n.dataset.filterKind===value),selected));
  await kind.selectOption('');await size.selectOption('10');await jump.selectOption('0');
  if(process.env.OIMO_LIST_SCREENSHOT_DIR) {await mkdir(process.env.OIMO_LIST_SCREENSHOT_DIR,{recursive:true});await section.screenshot({path:join(process.env.OIMO_LIST_SCREENSHOT_DIR,`list-${width}.png`)});}
 }
 assert.deepEqual(errors,[]);
 console.log('PASS: real 240-source list, 320/1024px, stable document position, bounded viewport, page jump, page sizes, filtering and unsaved input preservation');
} finally {await browser.close();}
