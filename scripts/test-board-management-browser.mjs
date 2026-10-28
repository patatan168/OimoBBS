/** 隔離サイトで板追加・再認証・板名とキー変更・旧URL・公開投稿を実ブラウザから検証する。 */
import assert from "node:assert/strict";
import {createRequire} from "node:module";
import {mkdir} from "node:fs/promises";

const {chromium}=createRequire(import.meta.url)(process.env.OIMO_PLAYWRIGHT);
const base=process.env.OIMO_BOARD_ADMIN_URL;
const publicBase=base.replace(/\/admin\/?$/,"");
const directory=process.env.OIMO_BOARD_SCREENSHOTS;
const browser=await chromium.launch({headless:true,executablePath:process.env.OIMO_CHROMIUM,args:["--no-sandbox"]});
try {
 const context=await browser.newContext();const page=await context.newPage();const errors=[];
 page.on("pageerror",e=>errors.push(e.message));
 await page.goto(base+"/login");
 await page.locator('input[name="login"]').fill("owner");
 await page.locator('input[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
 await Promise.all([page.waitForNavigation(),page.locator('button[type="submit"]').click()]);
 assert.equal((await page.goto(base+"/boards")).status(),200);
 await page.getByRole("link",{name:"新しい板を追加",exact:true}).click();
 assert.equal(new URL(page.url()).pathname,"/admin/boards/new");
 await page.getByRole("link",{name:"再認証して板を追加する",exact:true}).click();
 await page.locator('input[name="password"]').fill(process.env.OIMO_TEST_PASSWORD);
 await Promise.all([page.waitForNavigation(),page.locator('form[action*="/reauth"] button[type="submit"]').click()]);
 assert.equal(new URL(page.url()).pathname,"/admin/boards/new");
 await page.getByLabel("板の名前",{exact:true}).fill("追加と変更の確認板");
 await page.getByLabel("URLに使う板キー",{exact:true}).fill("browser_board");
 if(directory)await mkdir(directory,{recursive:true});
 for(const width of [390,1280]) {
  await page.setViewportSize({width,height:1000});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
  if(directory)await page.screenshot({path:`${directory}/board-create-${width}.png`,fullPage:true});
 }
 await page.getByLabel("URLに使う板キー",{exact:true}).fill("admin");
 await Promise.all([page.waitForNavigation(),page.getByRole("button",{name:"この内容で板を追加",exact:true}).click()]);
 assert.ok(await page.locator('[role="alert"]').isVisible());
 assert.equal(await page.getByLabel("板の名前",{exact:true}).inputValue(),"追加と変更の確認板");
 await page.getByLabel("URLに使う板キー",{exact:true}).fill("browser_board");
 await Promise.all([page.waitForNavigation(),page.getByRole("button",{name:"この内容で板を追加",exact:true}).click()]);
 const settings=page.url();assert.match(new URL(settings).pathname,/\/boards\/[0-9a-f]{32}\/settings$/);
 const publicPage=await context.newPage();publicPage.on("pageerror",e=>errors.push(e.message));
 await publicPage.goto(publicBase+"/web/post?bbs=browser_board");
 await publicPage.locator('input[name="subject"]').fill("変更前の投稿");
 await publicPage.locator('textarea[name="MESSAGE"]').fill("板名とキーを変えても残る本文です。");
 await Promise.all([publicPage.waitForNavigation(),publicPage.getByRole("button",{name:"書き込む",exact:true}).click()]);
 const consent=publicPage.getByRole("button",{name:"Cookieと利用規約に同意して書き込む",exact:true});
 if(await consent.count())await Promise.all([publicPage.waitForNavigation(),consent.click()]);
 assert.match(new URL(publicPage.url()).pathname,/\/test\/read.cgi\/browser_board\/\d+\//);
 const thread=new URL(publicPage.url()).pathname;
 const threadKey=thread.split("/")[4];
 const before=await page.request.get(publicBase+`/browser_board/dat/${threadKey}.dat`);
 assert.equal(before.status(),200);const dat=await before.body();
 await page.goto(settings);await page.getByRole("link",{name:"板名・キーを変更",exact:true}).click();
 await page.getByLabel("表示名",{exact:true}).fill("変更後の板名");
 await page.getByLabel("板キー",{exact:true}).fill("renamed_board");
 await Promise.all([page.waitForNavigation(),page.getByRole("button",{name:"板名・キーを保存",exact:true}).click()]);
 assert.equal(page.url(),settings);
 assert.ok((await page.locator("h1").innerText()).includes("変更後の板名"));
 for(const key of ["browser_board","renamed_board"]) {
  assert.equal((await publicPage.goto(publicBase+thread.replace("browser_board",key))).status(),200);
  assert.ok((await publicPage.locator("main").innerText()).includes("板名とキーを変えても残る本文です。"));
  const result=await page.request.get(publicBase+`/${key}/dat/${threadKey}.dat`);
  assert.equal(result.status(),200);assert.deepEqual(await result.body(),dat);
 }
 await page.getByRole("link",{name:"板名・キーを変更",exact:true}).click();
 assert.ok((await page.locator("main").innerText()).includes("browser_board"));
 if(directory)await page.screenshot({path:`${directory}/board-metadata.png`,fullPage:true});
 assert.ok((await page.locator(".site-footer").innerText()).includes("バージョン1.0.2"));
 // JavaScriptを使わない場合も同じ追加・変更フォームへ到達する。
 const plain=await browser.newContext({javaScriptEnabled:false,storageState:await page.context().storageState()});
 const noJS=await plain.newPage();
 assert.equal((await noJS.goto(base+"/boards/new")).status(),200);
 assert.equal(await noJS.getByLabel("板の名前",{exact:true}).count(),1);
 assert.deepEqual(errors,[]);
 console.log("PASS: board creation, reauthentication return, validation, rename, old/new URLs, unchanged DAT, mobile/desktop and no-JS forms; version 1.0.2");
} finally {await browser.close();}
