/** Goが描画した閲覧制限fixtureを独立したChromiumで検証する。実サイトの設定は変更しない。 */
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {readFile, mkdtemp, mkdir, writeFile, rm} from 'node:fs/promises';
import {createServer} from 'node:http';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';

const fixture = process.env.OIMO_READING_PAGE_OUTPUT;
assert.ok(fixture, 'OIMO_READING_PAGE_OUTPUT must name the Go-rendered fixture');
const html = (await readFile(fixture, 'utf8')).replaceAll(/\/web\/assets\/[a-f0-9]+\/([^" ]+)/g, '/assets/$1');
const server = createServer(async (request, response) => {
 if (process.env.OIMO_UI_DEBUG) console.log("fixture request",request.url);
  const asset = request.url?.match(/^\/assets\/(ui\.css|ui\.js|admin\.js)$/)?.[1];
  if (asset) {
    response.setHeader('Content-Type', asset.endsWith('css') ? 'text/css' : 'text/javascript');
    response.end(await readFile('internal/webui/assets/' + asset));
  } else if (request.url === '/') {
    response.setHeader('Content-Type', 'text/html; charset=utf-8'); response.end(html);
  } else { response.writeHead(404); response.end(); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const admin = 'http://127.0.0.1:' + server.address().port;
const profile = await mkdtemp(path.join(tmpdir(), 'oimo-reading-ui-'));
const output = process.env.OIMO_UI_OUTPUT || path.join(tmpdir(), 'oimo-reading-ui');
await mkdir(output, {recursive:true,mode:0o700});
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
  const measurements = [];
  for (const width of [160, 320, 390, 1280, 1800, 1920, 2200]) {
    await send('Emulation.setDeviceMetricsOverride', {width, height:900, deviceScaleFactor:1, mobile:width<700});
    await navigate(admin + '/');
    const result = await evaluate(`(() => {
      const form=document.querySelector('form');
      const permissionNames=Array.from(form.querySelectorAll('input[type="checkbox"]')).map(input=>input.name);
      const toggle=form.querySelector('select[name="enabled"]');
      toggle.value='true';form.querySelector('textarea[name="allowed_cidrs"]').value='192.0.2.1\\n2001:db8::/48';
      const agent=form.querySelector('textarea[name="denied_agents"]');agent.value='keep-agent';
      const advanced=agent.closest('details');advanced.open=true;
      const data=new FormData(form);
      const preserve=data.get('denied_agents')==='keep-agent' && data.get('enabled')==='true';
      const privacy=Boolean(document.querySelector('a[href="/reading"]')) && Boolean(document.querySelector('a[href="/admin-access"]'));
      const recovery=document.querySelector('main').textContent.includes('admin reset-reading-access');
      const overflow=document.documentElement.scrollWidth>innerWidth;
      return {width:innerWidth,overflow,preserve,privacy,recovery,checked:permissionNames.length,valid:form.checkValidity()};
    })()`);
    assert.equal(result.width,width,'Viewport expanded at '+width);
    assert.equal(result.overflow,false,'Horizontal overflow at '+width);
    assert.ok(result.preserve && result.privacy && result.recovery && result.checked===6 && result.valid,'Form behavior');
    measurements.push(result);
    await screenshot('reading-'+width);
  }
  await send('Emulation.setScriptExecutionDisabled', {value:true});
  await navigate(admin + '/');
  assert.ok(await evaluate(`Boolean(document.querySelector('form[action="/admin-access"]') && document.querySelector('textarea[name="allowed_cidrs"]') && document.querySelector('select[name="enabled"]'))`),'No-JS form lost');
  assert.deepEqual(errors.filter(message=>!message.includes('404')),[], 'Browser errors');
  await writeFile(path.join(output,'result.json'),JSON.stringify({status:'PASS',measurements,noJS:true},null,2),{mode:0o600});
  console.log(JSON.stringify({status:'PASS',viewports:measurements.length,noJS:true,screenshots:output}));
} finally {
  ws?.close(); browser.kill('SIGTERM');
  await new Promise(resolve=>{if(browser.exitCode!==null)resolve();else browser.once('exit',resolve);});
  await rm(profile,{recursive:true,force:true,maxRetries:10,retryDelay:100});
  server.closeAllConnections(); server.close();
}
