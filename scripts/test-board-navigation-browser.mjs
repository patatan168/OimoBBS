/** 同じ板の設定間の移動、現在地・対象板の表示と、省スペースな明暗/モバイル表示を実画面で検証する。 */
import assert from "node:assert/strict";
import {createRequire} from "node:module";
import {mkdir} from "node:fs/promises";
const {chromium}=createRequire(import.meta.url)(process.env.OIMO_PLAYWRIGHT);
const browser=await chromium.launch({headless:true,executablePath:process.env.OIMO_CHROMIUM,args:["--no-sandbox"]});
const base=process.env.OIMO_LAYOUT_URL,board=process.env.OIMO_LAYOUT_BOARD;
const root=`${base}/boards/${board}/`,directory=process.env.OIMO_LAYOUT_SCREENSHOTS;
try {
 const context=await browser.newContext();const page=await context.newPage();const errors=[];
 page.on("pageerror",e=>errors.push(e.message));
 await page.goto(base+"/login");
 await page.getByLabel("ログイン名",{exact:true}).fill("owner");
 await page.locator('input[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
 await Promise.all([page.waitForNavigation(),page.locator('button[type="submit"]').click()]);
 await page.goto(root+"settings");
 const boardName=await page.locator(".board-target-name").innerText();
 const nav=page.getByRole("navigation",{name:"この板の設定",exact:true});
 const targets=[["reading","板の閲覧権限を設定"],["thread-settings","レス数上限・終了レス"],["local-rules","ローカルルール"],["rules","投稿規制"],["metadata","板名・キーを変更"],["threads","レス削除・投稿者規制"],["close","板を閉鎖"],["settings","投稿設定"]];
 if(directory)await mkdir(directory,{recursive:true});
 for(const [route,title] of targets) {
  await nav.getByRole("link",{name:title,exact:true}).click();
  assert.equal(page.url(),root+route);
  assert.equal(await page.locator(".board-target-name").innerText(),boardName);
  assert.equal(await nav.locator('[aria-current="page"]').count(),1);
  assert.equal(await nav.locator('[aria-current="page"]').getAttribute("href"),new URL(root+route).pathname);
  assert.ok((await page.locator(".board-current").innerText()).includes(title));
  assert.ok((await page.title()).includes(boardName));
  for(const colorScheme of ["light","dark"]) {
   await page.emulateMedia({colorScheme});
   for(const width of [320,390,1280]) {
    await page.setViewportSize({width,height:900});
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,route);
    await page.waitForFunction(()=>{const tabs=document.querySelector('.board-settings-tabs');const tab=tabs.querySelector('[aria-current="page"]').getBoundingClientRect();const nav=tabs.getBoundingClientRect();return tab.left>=nav.left-1 && tab.right<=nav.right+1 && tabs.scrollWidth<=tabs.clientWidth;});
    const box=await page.locator(".board-context").boundingBox();assert.ok(box.height<340,`${route}: nav height ${box.height}`);
    assert.ok((await nav.locator('[aria-current="page"]').boundingBox()).height>=44);
    if(directory && ["settings","reading","thread-settings"].includes(route)) {
     await page.mouse.move(0,0);
     await page.screenshot({path:`${directory}/board-nav-${route}-${colorScheme}-${width}.png`});
    }
   }
  }
 }
 // 長い設定を下へスクロールしても、板名と現在地が画面内に残る。
 await page.evaluate(()=>scrollTo(0,1200));
 assert.ok((await page.locator(".board-context").boundingBox()).y>=0);
 assert.ok((await page.locator(".board-context").boundingBox()).y<10);
 await page.getByRole("link",{name:"文字数・行数",exact:true}).click();
 assert.equal(await page.locator("#board-limits").getAttribute("open"),"");
 assert.ok((await page.locator("#board-limits").boundingBox()).y>=(await page.locator(".board-context").boundingBox()).height);
 // JavaScriptなしでも、板一覧を挟まず同じ板の設定へ移動できる。
 const plain=await browser.newContext({javaScriptEnabled:false,storageState:await context.storageState()});
 const noJS=await plain.newPage();await noJS.setViewportSize({width:320,height:900});await noJS.goto(root+"local-rules");
 await noJS.getByRole("navigation",{name:"この板の設定",exact:true}).getByRole("link",{name:"板の閲覧権限を設定",exact:true}).click();
 assert.equal(noJS.url(),root+"reading");assert.equal(await noJS.locator(".board-target-name").innerText(),boardName);
 await plain.close();
 // スレッドの操作画面でも現在地と他の板設定への直接リンクを保持する。
 await page.goto(root+`threads/${process.env.OIMO_ASSETS_THREAD}/posts/1`);
 assert.equal(await page.locator(".board-target-name").innerText(),boardName);
 assert.ok((await page.locator(".board-current").innerText()).includes("レスの管理"));
 await page.setViewportSize({width:700,height:400});
 await page.goto(root+"settings");
 assert.equal(await page.locator(".board-context").evaluate(el=>getComputedStyle(el).position),"static");
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
 await page.goto(base+"/reading");assert.equal(await page.locator(".board-context").count(),0);
 assert.deepEqual(errors,[]);
 console.log("PASS: 8 direct board settings, current section/board/title, sticky wrapping tabs <340px without horizontal scrolling, light/dark 320/390/1280px, nested posts, no-JS and global-scope separation");
} finally {await browser.close();}
