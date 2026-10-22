/** 独立したChromiumでレスポンシブUIを検査する。Node標準APIのみ、管理設定は保存しない。 */
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {readFile, mkdtemp, mkdir, writeFile, rm, stat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';

const credentialsPath = 'var/credentials/admin-login.txt';
const info = await stat(credentialsPath);
assert.equal(info.mode & 0o777, 0o600);
assert.equal(info.uid, process.getuid());
const credentials = Object.fromEntries((await readFile(credentialsPath, 'utf8')).trim().split('\n').map(line => {
  const i = line.indexOf(': '); return [line.slice(0, i), line.slice(i + 2)];
}));
const admin = 'http://127.0.0.1:9081';
assert.equal(credentials.URL.replace(/\/$/, ''), admin);
const profile = await mkdtemp(path.join(tmpdir(), 'oimo-ui-'));
const output = process.env.OIMO_UI_OUTPUT || 'var/ui-verification';
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
  await navigate(admin + '/caps');
  assert.equal(await evaluate('location.pathname'), '/reauth', 'Cap reauthentication entry');
  const reauthenticated = loadedAtPath('/caps'); reauthenticated.catch(() => {});
  await evaluate(`(() => {const f=document.querySelector('form[action^="/reauth"]');f.elements.password.value=${JSON.stringify(credentials.Password)};f.requestSubmit();})()`);
  await reauthenticated;
  assert.equal(await evaluate('location.pathname'), '/caps', 'Reauthentication must return to caps');
  assert.ok(await evaluate(`Boolean(document.querySelector('input[type="checkbox"][name="board_ids"]'))`), 'Cap board picker missing');
  // アプリのCSPは通信を許可しない。試験のAPI照会はNodeから固定localhostだけへ送る。
  const cookies = await send('Network.getCookies', {urls: [admin + '/']});
  const boardResponse = await fetch(admin + '/api/v1/boards', {redirect: 'error', headers: {Cookie: cookies.cookies.map(cookie => cookie.name + '=' + cookie.value).join('; ')}});
  assert.equal(boardResponse.status, 200);
  const boards = (await boardResponse.json()).data;
  assert.ok(boards.length);
  const board = boards[0];
  const settings = admin + '/boards/' + board.id + '/thread-settings';
  const localRules = admin + '/boards/' + board.id + '/local-rules';
  const capThreadForm = 'https://patatanmc.f5.si/web/post?bbs=' + board.key + '&oimo_cap_only=1';
  const routes = [admin + '/', admin + '/boards', admin + '/board-categories', admin + '/boards/' + board.id + '/settings', settings, localRules, admin + '/boards/' + board.id + '/rules', admin + '/audit', admin + '/networks', admin + '/anonymous', admin + '/caps', admin + '/administrators', admin + '/maintenance', 'https://patatanmc.f5.si/', 'https://patatanmc.f5.si/' + board.key + '/', 'https://patatanmc.f5.si/web/post?bbs=' + board.key, capThreadForm];
  const smoke = JSON.parse(await readFile('var/docker-smoke.json', 'utf8'));
  const threadURL = process.env.OIMO_UI_THREAD || smoke.thread || smoke.location;
  if (threadURL) routes.push(new URL(threadURL, 'https://patatanmc.f5.si').href);
  routes.push('https://patatanmc.f5.si/search', 'https://patatanmc.f5.si/' + board.key + '/subback.html');
  // 上限件数のGoテンプレートをブラウザのDOMだけに展開し、実際の表示補助を検査する。
  if (process.env.OIMO_CATEGORY_UI_FIXTURE) {
    const fixture = await readFile(process.env.OIMO_CATEGORY_UI_FIXTURE, 'utf8');
    for (const width of [320, 390, 1280]) {
      await send('Emulation.setDeviceMetricsOverride', {width, height:900, deviceScaleFactor:1, mobile:width<700});
      await navigate(admin + '/board-categories');
      await evaluate(`(() => {const fixture=new DOMParser().parseFromString(${JSON.stringify(fixture)},'text/html');document.querySelector('main').replaceWith(fixture.querySelector('main'));for(const list of document.querySelectorAll('[data-filter-list]')) enhanceList(list);})()`);
      assert.equal(await evaluate(`document.querySelectorAll('.category-editor-list details').length`), 384);
      assert.equal(await evaluate(`document.querySelectorAll('.category-editor-list details[open]').length`), 0);
      const result = await evaluate(`(() => {
        const [categories,boards]=document.querySelectorAll('.category-editor-list');
        const search=(list,value)=>{const input=list.previousElementSibling.querySelector('input');input.value=value;input.dispatchEvent(new Event('input'));return [...list.children].filter(row=>!row.hidden);};
        const category=search(categories,'カテゴリー127');const board=search(boards,'カテゴリー127');
        const valid=category.length===1 && board.length===1 && board[0].dataset.filterText.includes('board127');
        category[0].querySelector('summary').click();
        const name=category[0].querySelector('input[name=name]');name.value='保存前の名前';
        const none=search(categories,'存在しない名前').length===0;
        search(categories,'');
        const preserved=name.value==='保存前の名前' && category[0].querySelector('details').open;
        const key=search(boards,'board042').length===1;
        return {valid,none,preserved,key,overflow:document.documentElement.scrollWidth>innerWidth};
      })()`);
      assert.deepEqual(result, {valid:true,none:true,preserved:true,key:true,overflow:false}, 'Large category editing/filtering failed');
      if (width===390 || width===1280) await screenshot('board-categories-many-' + width);
    }
  }
  const measurements = [];
  for (const width of [320, 390, 600, 700, 701, 768, 1024, 1280]) {
    await send('Emulation.setDeviceMetricsOverride', {width, height: 900, deviceScaleFactor: 1, mobile: width < 700});
    for (const url of routes) {
      await navigate(url);
      const metrics = await evaluate(`(() => ({width:innerWidth, scroll:document.documentElement.scrollWidth, css:document.styleSheets.length, preview:!!document.querySelector('.ending-preview'), smallControls:[...document.querySelectorAll('button,input:not([type=hidden]):not([type=checkbox]),select')].filter(e=>e.getBoundingClientRect().height>0 && e.getBoundingClientRect().height<44).length}))()`);
      assert.ok(metrics.css > 0, 'CSS missing: ' + url);
      assert.ok(metrics.scroll <= metrics.width, 'Horizontal overflow: ' + width + ' ' + url);
      assert.equal(metrics.smallControls, 0, 'Small controls: ' + url);
      if (url === admin + '/boards' || url === admin + '/boards/' + board.id + '/settings') {
        assert.ok(await evaluate(`[...document.querySelectorAll('a')].some(a=>a.href===${JSON.stringify(capThreadForm)})`), 'Admin CAP thread creation link missing');
      }
      if (url === capThreadForm) {
        assert.ok(await evaluate(`(() => {const input=document.querySelector('input[name="oimo_cap_only"]');return input.type==='hidden' && input.value==='1' && !document.body.textContent.includes('CAP専用（返信をCAPに限定）');})()`), 'CAP hidden preset missing or selector exposed');
        assert.equal(await evaluate(`document.querySelector('h1').textContent`), 'CAP専用スレッドを立てる');
        if (width === 390 || width === 1280) await screenshot('cap-thread-form-' + width);
      }
      if (url === 'https://patatanmc.f5.si/web/post?bbs=' + board.key) {
        assert.ok(await evaluate(`!document.querySelector('[name="oimo_cap_only"]') && !document.body.textContent.includes('CAP専用（返信をCAPに限定）')`), 'Ordinary public form exposes CAP selector');
      }
      if (url === admin + '/boards') {
        assert.deepEqual(await evaluate(`[...document.querySelector('select[name="posting_mode"]').options].map(o=>o.value)`), ['anyone', 'cap_only'], 'Board creation modes missing');
        if (width === 390 || width === 1280) {
          await evaluate(`document.querySelector('form[action="/boards"]').scrollIntoView({block:'start'})`);
          await screenshot('board-create-' + width);
        }
      }
      if ([admin + '/caps', admin + '/administrators', admin + '/audit'].includes(url)) {
        assert.ok(await evaluate(`Boolean(document.querySelector('input[type="checkbox"][name="${url.endsWith('/audit') ? 'board' : 'board_ids'}"]'))`), 'Board checkbox missing: ' + url);
        assert.ok(await evaluate("[...document.querySelectorAll('.check-option')].every(e=>e.getBoundingClientRect().height>=44)"), 'Board checkbox target too small');
        if (width === 390 || width === 1280) {
          await evaluate("document.querySelector('fieldset').scrollIntoView({block:'center'})");
          await screenshot('board-selection-' + new URL(url).pathname.slice(1) + '-' + width);
        }
      }
      if (url === admin + '/board-categories') {
        assert.equal(await evaluate(`document.querySelector('h1').textContent`), '板カテゴリー');
        assert.ok(await evaluate(`Boolean(document.querySelector('input[name="name"]')) && document.querySelectorAll('select[name="category"]').length === ${boards.length}`), 'Board category add/assignment controls missing');
        assert.ok(await evaluate(`[...document.querySelectorAll('form[action="/board-categories"]')].every(form=>form.method==='post' && form.querySelector('input[name=csrf]') && form.querySelector('input[name=revision]') && form.querySelector('input[name=request_id]'))`), 'Board category save protection missing');
        if (width === 390 || width === 1280) await screenshot('board-categories-' + width);
      }
      if (url === localRules) {
        assert.ok(await evaluate(`Boolean(document.querySelector('textarea[name="text"]'))`), 'Local rule editor missing');
        if (width === 390 || width === 1280) await screenshot('local-rules-' + width);
      }
      if (url === 'https://patatanmc.f5.si/' + board.key + '/') {
        assert.ok(await evaluate(`Boolean(document.querySelector('#local-rules'))`), 'Public local rules missing');
      }
      if (url === settings) {
        assert.ok(metrics.preview, 'Ending preview missing');
        if (width === 390 || width === 1280) await screenshot('settings-' + width);
      }
      if (url === admin + '/networks') {
        await evaluate("document.querySelector('.category-grid details').open = true");
        assert.ok(await evaluate('document.documentElement.scrollWidth <= innerWidth'), 'Category editor overflows');
        const editor = await evaluate(`(() => {const e=document.querySelector('.category-grid details form');const r=e.getBoundingClientRect();return {left:r.left,right:r.right,inputs:[...e.querySelectorAll('input:not([type=hidden]),select,textarea')].every(x=>x.getBoundingClientRect().width>=150)};})()`);
        assert.ok(editor.left >= 0 && editor.right <= width && editor.inputs, 'Category editor too narrow');
        if (width === 390 || width === 1280) {
          await screenshot('networks-' + width);
          await evaluate("document.querySelector('.category-grid details').scrollIntoView({block:'start'})");
          await screenshot('category-editor-' + width);
        }
      }
      if (url.startsWith('https:') && width <= 700) {
        const navigation = await evaluate(`(() => {const nav=document.querySelector('.site-header nav');const r=nav.getBoundingClientRect();return {height:r.height,visible:[...nav.querySelectorAll('a')].every(a=>{const x=a.getBoundingClientRect();return x.left>=0 && x.right<=innerWidth && x.height>=44})};})()`);
        assert.ok(navigation.height <= 90 && navigation.visible, 'Public navigation wraps or overflows');
      }
      if (url === 'https://patatanmc.f5.si/' && (width === 390 || width === 1280)) await screenshot('boards-' + width);
      if (url === new URL(threadURL, 'https://patatanmc.f5.si').href && (width === 390 || width === 1280)) await screenshot('responses-' + width);
      if (url === admin + '/boards/' + board.id + '/settings') {
        assert.ok(await evaluate(`(() => {const select=document.querySelector('select[name="no_reprint"]');return select && [...select.options].map(x=>x.value).join(',')==='false,true' && select.closest('p').textContent.includes('無断転載禁止') && select.closest('p').textContent.includes('投稿確認画面');})()`), 'Board reprint setting and explanation missing');
        const commandOptions = await evaluate(`[...document.querySelector('select[name="slip_mode"]').options].map(o=>({value:o.value,text:o.textContent}))`);
        assert.ok(commandOptions.every(o=>o.text.includes('!slip:' + o.value) && o.text.length > o.value.length + 10), 'Display meaning/command pair missing');
        const commandChecks = await evaluate(`[...document.querySelectorAll('[data-display-commands] input[type=checkbox]')].map(x => x.value)`);
        assert.equal(commandChecks.length, 36);
        assert.equal(new Set(commandChecks).size, 36);
        assert.ok(await evaluate(`(() => {const checks=[...document.querySelectorAll('[data-display-commands] input[type=checkbox]')];const before=checks.map(x=>x.checked);const target=checks.findIndex(x=>x.value==='!slip:vvvvv');checks[target].click();const independent=checks.every((x,i)=>x.checked===(i===target?!before[i]:before[i]));checks[target].click();return independent;})()`), 'Display command checkboxes are not independent');
        assert.ok(await evaluate(`(() => {
          const root=document.querySelector('[data-display-commands]');
          const form=root.closest('form');
          const id=form.querySelector('select[name=id_mode]');
          const slip=form.querySelector('select[name=slip_mode]');
          const checks=[...root.querySelectorAll('input[type=checkbox]')];
          const before=checks.map(x=>x.checked), originalID=id.value, originalSlip=slip.value;
          const visible=x=>!x.closest('[data-command-option]').hidden;
          let valid=true;
          for(const [idMode,slipMode,count] of [['required','none',27],['optional','none',36],['required','vvvvv',9],['optional','vvvvv',12],['required','vvvvvv',6]]) {
            id.value=idMode;slip.value=slipMode;id.dispatchEvent(new Event('change'));slip.dispatchEvent(new Event('change'));
            valid=valid && checks.filter(visible).length===count;
          }
          id.value=originalID;slip.value=originalSlip;id.dispatchEvent(new Event('change'));slip.dispatchEvent(new Event('change'));
          for(const group of [root,...root.querySelectorAll('[data-command-group]')]) {
            if(group.hidden) continue;
            for(const state of ['off','on']) {
              checks.forEach((x,i)=>{x.checked=before[i]});
              const button=[...group.children].flatMap(x=>[...x.querySelectorAll('[data-command-bulk]')]).find(x=>x.closest('[data-command-group]')===group && x.dataset.commandBulk===state);
              button.click();
              valid=valid && checks.every((x,i)=>x.checked===(group.contains(x)&&visible(x)?state==='on':before[i]));
            }
          }
          checks.forEach((x,i)=>{x.checked=before[i]});
          const submitted=new FormData(form).getAll('display_commands');
          return valid && submitted.length===before.filter(Boolean).length;
        })()`), 'Display command filtering, bulk isolation, or hidden permissions failed');
        assert.ok(await evaluate(`document.documentElement.scrollWidth <= innerWidth`), 'Display command guide overflows');
        assert.ok(await evaluate(`document.querySelector('[data-display-commands]').textContent.includes('!extend:default:vvvvv::')`), 'Extend command guide missing');
        if (width === 390 || width === 1280) {
          await evaluate(`document.querySelector('[data-display-commands]').scrollIntoView({block:'start'})`);
          await screenshot('board-display-commands-' + width);
        }
        await evaluate("document.querySelector('#network-permissions details').open = true");
        const countrySearch = await evaluate(`(() => {
          const box=document.querySelector('.country-options');const input=box.previousElementSibling.querySelector('input');
          input.value='日本';input.dispatchEvent(new Event('input'));
          const visible=[...box.children].filter(e=>!e.hidden).map(e=>e.querySelector('input').value);
          input.value='';input.dispatchEvent(new Event('input'));
          return visible;
        })()`);
        assert.deepEqual(countrySearch, ['JP'], 'Country-name filter failed');
        assert.ok(await evaluate('document.documentElement.scrollWidth <= innerWidth'), 'Country selector overflows');
        assert.ok(await evaluate("!!document.querySelector('#network-permissions input[type=checkbox]') && [...document.querySelectorAll('.check-option')].every(e=>e.getBoundingClientRect().height===0 || e.getBoundingClientRect().height>=44)"), 'Permission checkbox targets missing');
        if (width === 390 || width === 1280) {
          await evaluate("document.querySelector('#network-permissions').scrollIntoView({block:'start'})");
          await screenshot('network-permissions-' + width);
        }
      }
      measurements.push({width, url, overflow: metrics.scroll - metrics.width});
    }
  }
  await navigate(settings);
  const preview = await evaluate(`(() => {const form=document.querySelector('[data-ending-settings]');form.elements.user_post_limit.value='2';form.elements.ending_1_enabled.value='false';form.elements.ending_2_enabled.value='true';form.elements.ending_2_name.value='<img src=x onerror=alert(1)>';form.elements.ending_2_body.value='終了';form.dispatchEvent(new Event('input'));return {text:document.querySelector('.ending-preview').textContent, images:document.querySelector('.ending-preview img')!==null};})()`);
  assert.ok(preview.text.includes('3：<img src=x onerror=alert(1)>'));
  assert.equal(preview.images, false, 'Preview HTML injection');
  await navigate('https://patatanmc.f5.si/' + board.key + '/');
  const search = await evaluate(`(() => {const input=document.querySelector('input[type=search]');if(!input)return null;input.value='no-match-ui-check-987654321';input.dispatchEvent(new Event('input'));return [...document.querySelectorAll('[data-filter-list] > li')].every(e=>e.hidden);})()`);
  assert.notEqual(search, false, 'Local filter failed');
  await send('Emulation.setDeviceMetricsOverride', {width: 390, height: 900, deviceScaleFactor: 1, mobile: true});
  await navigate('https://patatanmc.f5.si/' + board.key + '/');
  await screenshot('threads-390');
  await send('Emulation.setEmulatedMedia', {features: [{name: 'prefers-color-scheme', value: 'dark'}]});
  await screenshot('threads-dark-390');
  await navigate(settings);
  await send('Page.bringToFront');
  await send('Emulation.setFocusEmulationEnabled', {enabled: true});
  await evaluate('document.querySelector("input[name=user_post_limit]").focus()');
  if (process.env.OIMO_UI_DEBUG) console.log(await evaluate('({width:innerWidth,focus:document.hasFocus(),active:document.activeElement.name,matches:document.body.matches("body:has(input:focus)")})')); 
  assert.notEqual(await evaluate('getComputedStyle(document.querySelector(".site-header nav")).position'), 'fixed', 'Admin navigation covers editing area');
  await navigate('https://patatanmc.f5.si/web/post?bbs=' + board.key);
  await evaluate('document.querySelector("textarea").focus()');
  assert.equal(await evaluate('getComputedStyle(document.querySelector(".site-header nav")).display'), 'none', 'Reader navigation covers composer');
  await navigate(new URL(threadURL, 'https://patatanmc.f5.si').href);
  const responseTools = await evaluate(`(() => {
    const main=document.querySelector('[data-thread-base]');
    const body=main.querySelector('[data-response-body]');
    body.textContent='<img src=x onerror=alert(1)> >>1';
    enhanceResponseLinks(main);
    const link=body.querySelector('a');
    const f=main.querySelector('[data-response-jump]');f.elements.response.value='1';f.requestSubmit();
    return {link:link?.getAttribute('href'),safe:!body.querySelector('img'),hash:location.hash,visible:!f.hidden};
  })()`);
  assert.deepEqual(responseTools, {link:'#1',safe:true,hash:'#1',visible:true});
  await send('Emulation.setScriptExecutionDisabled', {value: true});
  await navigate(settings);
  assert.equal(await evaluate('document.querySelectorAll("fieldset").length'), 2, 'No-JS form missing');
  await navigate(admin + '/board-categories');
  assert.ok(await evaluate(`(() => {const select=document.querySelector('.category-editor-list select[name=category]');select.closest('details').open=true;return select.getBoundingClientRect().height>=44 && !document.querySelector('.filter-field');})()`), 'No-JS category editor missing');
  await navigate(new URL(threadURL, 'https://patatanmc.f5.si').href);
  assert.ok(await evaluate("!!document.querySelector('.response-list article') && !!document.querySelector('a[href$=l50]')"), 'No-JS reading controls missing');
  await send('Emulation.setScriptExecutionDisabled', {value: false});
  const meaningfulErrors = errors.filter(message => !message.includes('404'));
  assert.deepEqual(meaningfulErrors, [], 'Browser errors');
  await writeFile(path.join(output, 'result.json'), JSON.stringify({status: 'PASS', measurements, preview: true, search, noJS: true}, null, 2), {mode: 0o600});
  console.log(JSON.stringify({status: 'PASS', viewportChecks: measurements.length, preview: true, search, noJS: true, screenshots: output}));
} finally {
  ws?.close();
  browser.kill('SIGTERM');
  await new Promise(resolve => {if (browser.exitCode !== null) resolve(); else browser.once('exit', resolve);});
  await rm(profile, {recursive: true, force: true, maxRetries: 10, retryDelay: 100});
}
