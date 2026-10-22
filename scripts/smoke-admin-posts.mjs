/** 管理人用閲覧と規制入力をChromiumで検証する。削除検証は明示指定した隔離fixtureだけに許す。 */
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {readFile, mkdtemp, mkdir, writeFile, rm, stat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';

const credentialsPath = process.env.OIMO_POSTS_CREDENTIALS || 'var/credentials/admin-login.txt';
const info = await stat(credentialsPath);
assert.equal(info.mode & 0o777, 0o600);
assert.equal(info.uid, process.getuid());
const credentials = Object.fromEntries((await readFile(credentialsPath, 'utf8')).trim().split('\n').map(line => {
  const i = line.indexOf(': '); return [line.slice(0, i), line.slice(i + 2)];
}));
const admin = process.env.OIMO_POSTS_ADMIN || 'http://127.0.0.1:9081';
assert.ok(['http://127.0.0.1:9081', 'http://127.0.0.1:9181'].includes(admin));
assert.equal(credentials.URL.replace(/\/$/, ''), admin);
const deleteFixture = process.env.OIMO_POSTS_DELETE_FIXTURE === '1';
if (deleteFixture) assert.equal(admin,'http://127.0.0.1:9181');
const profile = await mkdtemp(path.join(tmpdir(), 'oimo-ui-'));
const output = process.env.OIMO_UI_OUTPUT || 'var/admin-posts/ui';
await mkdir(output, {recursive: true, mode: 0o700});
const browser = spawn(process.env.OIMO_CHROME || 'chromium', ['--headless=new', '--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage', '--no-proxy-server', '--remote-debugging-port=0', '--remote-debugging-address=127.0.0.1', '--user-data-dir=' + profile, 'about:blank'], {stdio: ['ignore', 'ignore', 'pipe']});
browser.stderr.on("data", data => { if (process.env.OIMO_UI_DEBUG) process.stderr.write(data); });
let ws;
const errors = [];
try {
  let port;
  for (let n = 0; n < 100; n++) {
    try { port = (await readFile(path.join(profile, 'DevToolsActivePort'), 'utf8')).split('\n')[0]; break; } catch { await delay(100); }
  }
  assert.ok(port, 'Chromium did not start');
  const target = await (await fetch(`http://127.0.0.1:${port}/json/new?about:blank`, {method: 'PUT'})).json();
  ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject; });
  let id = 0;
  const pending = new Map();
  const waiters = new Map();
  ws.onmessage = (event) => {
    const message = JSON.parse(event.data);
    if (process.env.OIMO_UI_DEBUG && message.method) console.log("CDP event:", message.method, message.params?.errorText || message.params?.response?.status || "");
    if (message.id && pending.has(message.id)) {
      const item = pending.get(message.id); pending.delete(message.id);
      clearTimeout(item.timer);
      if (message.error) item.reject(new Error(message.error.message)); else item.resolve(message.result);
    }
    if (message.method === 'Runtime.exceptionThrown') errors.push('JavaScript exception');
    if (message.method === 'Log.entryAdded' && message.params.entry.level === 'error') errors.push(message.params.entry.text);
    if (waiters.has(message.method) && waiters.get(message.method)(message.params) !== false) waiters.delete(message.method);
  };
  function send(method, params = {}) {
    return new Promise((resolve, reject) => {
      const requestID = ++id;
      const timer = setTimeout(() => {pending.delete(requestID); reject(new Error('CDP timeout: ' + method));}, 15000);
      pending.set(requestID, {resolve, reject, timer});
      ws.send(JSON.stringify({id: requestID, method, params}));
    });
  }
  function loaded() {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {waiters.delete('Page.loadEventFired'); reject(new Error('Page load timeout'));}, 15000);
      waiters.set('Page.loadEventFired', () => {clearTimeout(timer); resolve();});
    });
  }
  /** フォーム送信後は遷移先のloaderに対応するloadだけを待ち、直前のイベントを採用しない。 */
  function loadedAtPath(expected) {
    return new Promise((resolve, reject) => {
      let loader;
      const cleanup = () => {waiters.delete('Page.frameNavigated'); waiters.delete('Page.lifecycleEvent'); clearTimeout(timer);};
      const timer = setTimeout(() => {cleanup(); reject(new Error('Page destination timeout: ' + expected));}, 15000);
      waiters.set('Page.frameNavigated', ({frame}) => {
        if (!frame.parentId && new URL(frame.url).pathname === expected) {loader = frame.loaderId; return true;}
        return false;
      });
      waiters.set('Page.lifecycleEvent', event => {
        if (loader && event.loaderId === loader && event.name === 'load') {cleanup(); resolve(); return true;}
        return false;
      });
    });
  }
  async function evaluate(expression) {
    const result = await send('Runtime.evaluate', {expression, returnByValue: true, awaitPromise: true});
    assert.ok(!result.exceptionDetails, 'Browser evaluation failed');
    return result.result.value;
  }
  async function navigate(url) {
    if (process.env.OIMO_UI_DEBUG) console.log('Check page:', url);
    const ready = loaded(); ready.catch(() => {});
    const navigation = await send('Page.navigate', {url});
    assert.ok(!navigation.errorText, navigation.errorText || 'Navigation failed');
    await ready;
    assert.ok(await evaluate('Boolean(document.querySelector("main"))'), 'Page missing main: ' + url);
  }
  async function screenshot(name) {
    await evaluate('Promise.all(document.getAnimations().map(animation => animation.finished.catch(() => {})))');
    const {data} = await send('Page.captureScreenshot', {format: 'png'});
    await writeFile(path.join(output, name + '.png'), Buffer.from(data, 'base64'), {mode: 0o600});
  }
  await send('Page.enable'); await send('Page.setLifecycleEventsEnabled', {enabled: true}); await send('Runtime.enable'); await send('Log.enable'); await send('Network.enable');
  await navigate(admin + '/login');
  if (process.env.OIMO_UI_DEBUG) console.log("Check login submission");
  const loggedIn = loadedAtPath('/'); loggedIn.catch(() => {});
  await evaluate(`(() => {const f=document.querySelector('form[action="/login"]'); f.elements.login.value=${JSON.stringify(credentials.Login)}; f.elements.password.value=${JSON.stringify(credentials.Password)}; f.requestSubmit();})()`);
  await loggedIn;
  assert.equal(await evaluate('location.pathname'), '/', 'Login failed');

  await navigate(admin + '/reauth?return_to=%2Fboards');
  const reauthenticated = loadedAtPath('/boards'); reauthenticated.catch(() => {});
  await evaluate(`(() => {const f=document.querySelector('form[action^="/reauth"]');f.elements.password.value=${JSON.stringify(credentials.Password)};f.requestSubmit();})()`);
  await reauthenticated;
  const cookieResult = await send('Network.getCookies', {urls:[admin+'/']});
  const cookieHeader = cookieResult.cookies.map(cookie => cookie.name+'='+cookie.value).join('; ');
  const getJSON = async route => {
    const response = await fetch(admin+route,{redirect:'error',headers:{Cookie:cookieHeader}});
    assert.equal(response.status,200);return response.json();
  };
  const boards = (await getJSON('/api/v1/boards')).data;
  let board,thread;
  for (const candidate of boards) {
    const threads=(await getJSON('/api/v1/boards/'+candidate.id+'/threads')).data;
    thread=threads.find(row=>row.public_status===200);
    if (thread) {board=candidate;break;}
  }
  assert.ok(board && thread,'No public thread for admin reading check');
  const list='/boards/'+board.id+'/threads';
  const rules='/boards/'+board.id+'/rules';
  const posts=list+'/'+thread.key+'/posts/1';
  const measurements=[];
  for (const width of [320,390,1280]) {
    await send('Emulation.setDeviceMetricsOverride',{width,height:900,deviceScaleFactor:1,mobile:width<700});
    for (const route of [list,rules,posts]) {
      await navigate(admin+route);
      const metrics=await evaluate('({width:innerWidth,scroll:document.documentElement.scrollWidth,rows:document.querySelectorAll("[id^=post-]").length})');
      assert.ok(metrics.scroll<=metrics.width,'Horizontal overflow');
      if (route===posts) assert.ok(metrics.rows>0 && metrics.rows<=50,'Post page bound');
      if (route===rules) {
        const states=await evaluate(`(() => {
          const form=document.querySelector('form[action="${rules}"]');
          const data=[];
          for(const value of ['auto','host','ua','token']) {
            form.elements.field.value=value;form.dispatchEvent(new Event('change'));
            data.push({field:value,label:form.querySelector('[data-rule-target-label]').textContent,operators:[...form.elements.operator.options].filter(o=>!o.disabled).map(o=>o.value),required:form.elements.target.required});
          }
          return {states:data,advancedOpen:!!form.querySelector('details')?.open,targetBeforeOperator:!!(form.elements.target.compareDocumentPosition(form.elements.operator)&Node.DOCUMENT_POSITION_FOLLOWING)};
        })()`);
        assert.equal(states.advancedOpen,false);
        assert.equal(states.targetBeforeOperator,true);
        assert.deepEqual(states.states.map(s=>s.operators),[['exact'],['exact','suffix'],['exact','contains','regexp'],['exact']]);
        assert.ok(states.states.every(s=>s.required));
      }
      if (width!==320) await screenshot((route===rules?'rules':route===posts?'posts':'thread-list')+'-'+width);
      measurements.push({width,page:route===rules?'rules':route===posts?'posts':'thread-list',overflow:metrics.scroll-metrics.width});
    }
  }
  await navigate(admin+posts);
  const inspect = await evaluate(`document.querySelector('form[action$="/inspect"]')?.getAttribute('action') || null`);
  let privateRecord=false;
  let regulationPrefilled=false;
  if (inspect) {
    const inspected=loadedAtPath(inspect);inspected.catch(()=>{});
    await evaluate(`document.querySelector('form[action="${inspect}"]').requestSubmit()`);
    await inspected;
    assert.ok(await evaluate('document.body.textContent.includes("投稿操作ID")'),'Live accepted record not resolved');
    const metrics=await evaluate('({width:innerWidth,scroll:document.documentElement.scrollWidth})');
    assert.ok(metrics.scroll<=metrics.width,'Private details overflow');
    // メタデータや接続情報を標準出力・結果JSONへ書かない。
    privateRecord=true;
    if (admin.endsWith(':9181')) await screenshot('private-record-1280');
    const rule = await evaluate(`document.querySelector('form[action$="/rule"]')?.getAttribute('action') || null`);
    if (rule) {
      const prefilled=loadedAtPath(rule);prefilled.catch(()=>{});
      await evaluate(`document.querySelector('form[action="${rule}"]').requestSubmit()`);
      await prefilled;
      // 原本のIP/UA等を出力せず、自動入力と確認フォームの存在だけを検査する。
      const values=await evaluate(`(() => {
        const form=document.querySelector('form[action="${rules}"]');
        return {field:form.elements.field.value,hasTarget:!!form.elements.target.value,advancedOpen:!!form.querySelector('details')?.open};
      })()`);
      assert.equal(values.field,'auto');assert.ok(values.hasTarget);assert.equal(values.advancedOpen,false);
      regulationPrefilled=true;
      if (admin.endsWith(':9181')) await screenshot('prefilled-rule-1280');
    }
  }
  let fixtureDeleted=false;
  if (deleteFixture) {
    await navigate(admin+posts);
    assert.ok(await evaluate(`[1,2,3].every(n=>document.body.textContent.includes('ADMIN-POSTS-FIXTURE-RESPONSE-'+n))`),'Requires untouched isolated fixture');
    const deleted=loadedAtPath(posts);deleted.catch(()=>{});
    await evaluate(`(() => {
      const form=document.querySelector('#post-3 form[action$="/delete"]');
      form.querySelector('[name="confirm"]').checked=true;
      form.requestSubmit();
    })()`);
    await deleted;
    assert.ok(await evaluate(`document.querySelector('#post-3').textContent.includes('あぼーん') && !document.body.textContent.includes('ADMIN-POSTS-FIXTURE-RESPONSE-3') && document.body.textContent.includes('ADMIN-POSTS-FIXTURE-RESPONSE-1')`));
    fixtureDeleted=true;
    await screenshot('deleted-fixture-1280');
  }
  const meaningfulErrors=errors.filter(message=>!message.includes('404'));
  assert.deepEqual(meaningfulErrors,[],'Browser errors');
  await writeFile(path.join(output,'result.json'),JSON.stringify({status:'PASS',measurements,privateRecord,regulationPrefilled,fixtureDeleted,regulationApplied:false,exportApplied:false},null,2),{mode:0o600});
  console.log(JSON.stringify({status:'PASS',viewportChecks:measurements.length,privateRecord,regulationPrefilled,fixtureDeleted,regulationApplied:false,exportApplied:false}));
} finally {
  ws?.close();browser.kill('SIGTERM');
  await new Promise(resolve=>{if(browser.exitCode!==null)resolve();else browser.once('exit',resolve);});
  await rm(profile,{recursive:true,force:true,maxRetries:10,retryDelay:100});
}
