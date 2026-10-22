/** Goが描画したWAFのfixtureを独立したChromiumで検証する。実サイトの設定は変更しない。 */
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {readFile, mkdtemp, mkdir, writeFile, rm} from 'node:fs/promises';
import {createServer} from 'node:http';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';

const fixture = process.env.OIMO_WAF_PAGE_OUTPUT;
assert.ok(fixture, 'OIMO_WAF_PAGE_OUTPUT must name the Go-rendered fixture');
const html = (await readFile(fixture, 'utf8')).replaceAll(/\/web\/assets\/[a-f0-9]+\/([^" ]+)/g, '/assets/$1');
let submitted;
const server = createServer(async (request, response) => {
 if (process.env.OIMO_UI_DEBUG) console.log("fixture request",request.url);
  if (request.method === 'POST' && request.url === '/submit-check') {
    const chunks=[];
    for await (const chunk of request) chunks.push(chunk);
    submitted=new URLSearchParams(Buffer.concat(chunks).toString());
    response.setHeader('Content-Type','text/html; charset=utf-8');
    response.end('<main>保存内容の確認</main>');return;
  }
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
const profile = await mkdtemp(path.join(tmpdir(), 'oimo-waf-ui-'));
await mkdir(path.join(profile,'Default'),{recursive:true});
await writeFile(path.join(profile,'Default','Preferences'),JSON.stringify({dns_over_https:{mode:'off'},credentials_enable_service:false,profile:{password_manager_enabled:false}}),{mode:0o600});
const output = process.env.OIMO_UI_OUTPUT || path.join(tmpdir(), 'oimo-waf-ui');
await mkdir(output, {recursive:true,mode:0o700});
const browser = spawn(process.env.OIMO_CHROME || 'chromium', ['--headless=new', '--disable-quic', '--disable-background-networking', '--password-store=basic', '--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage', '--no-proxy-server', '--remote-debugging-port=0', '--remote-debugging-address=127.0.0.1', '--user-data-dir=' + profile, 'about:blank'], {stdio: ['ignore', 'ignore', 'pipe']});
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
    if (process.env.OIMO_UI_DEBUG && message.method) console.log("CDP event:", message.method, message.params?.errorText || message.params?.request?.url || message.params?.response?.status || "");
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
    const {cssContentSize} = await send('Page.getLayoutMetrics');
    const {data} = await send('Page.captureScreenshot', {format:'png',captureBeyondViewport:true,clip:{x:0,y:0,width:cssContentSize.width,height:cssContentSize.height,scale:1}});
    await writeFile(path.join(output, name + '.png'), Buffer.from(data, 'base64'), {mode: 0o600});
  }
  await send('Page.enable'); await send('Page.setLifecycleEventsEnabled', {enabled: true}); await send('Runtime.enable'); await send('Log.enable'); await send('Network.enable');
  const measurements = [];
  const expectedFields = ['csrf','revision','request_id','enabled','traffic_enabled','client_enabled','client_rate','client_burst','global_rate','global_burst','client_concurrent','global_concurrent','search_rate','search_burst','search_global_rate','search_global_burst','search_concurrent','posting_client_rate','posting_client_burst','posting_global_rate','posting_global_burst','posting_client_concurrent','posting_global_concurrent'].sort();
  for (const width of [320,390,700,1280,1920]) {
    await send('Emulation.setDeviceMetricsOverride', {width,height:1000,deviceScaleFactor:1,mobile:width<700});
    await navigate(admin + '/');
    const initial = await evaluate(`(() => {const form=document.querySelector('#waf-settings');return {fields:[...new FormData(form).keys()].sort(),searchOpen:document.querySelector('#waf-search-limits').open,postingOpen:document.querySelector('#waf-posting-limits').open,overflow:document.documentElement.scrollWidth>innerWidth,valid:form.checkValidity()}})()`);
    assert.deepEqual(initial.fields,expectedFields,'Closed details lost submitted fields');
    assert.equal(initial.searchOpen,false); assert.equal(initial.postingOpen,false);
    assert.equal(initial.overflow,false); assert.equal(initial.valid,true);
    await screenshot('waf-'+width+'-overview');
    const edited = await evaluate(`(() => {
      const form=document.querySelector('#waf-settings');
      const details=document.querySelector('#waf-posting-limits');
      details.querySelector('summary').click();
      const opened=details.open && document.querySelector('#posting_global_rate').getBoundingClientRect().height>0;
      form.elements.posting_global_rate.value='200';form.elements.posting_global_burst.value='400';form.elements.posting_global_concurrent.value='64';
      details.querySelector('summary').click();
      const data=new FormData(form);
      return {opened,closed:!details.open,rate:data.get('posting_global_rate'),burst:data.get('posting_global_burst'),concurrent:data.get('posting_global_concurrent'),fields:[...data.keys()].sort(),valid:form.checkValidity(),overflow:document.documentElement.scrollWidth>innerWidth};
    })()`);
    assert.ok(edited.opened && edited.closed && edited.valid && !edited.overflow);
    assert.deepEqual([edited.rate,edited.burst,edited.concurrent],['200','400','64']);
    assert.deepEqual(edited.fields,expectedFields);
    if (width===390 || width===1280) {
      await evaluate(`document.querySelectorAll('main details').forEach(details=>details.open=true)`);
      assert.equal(await evaluate('document.documentElement.scrollWidth>innerWidth'),false);
      await screenshot('waf-'+width+'-expanded');
    }
    measurements.push({width,...initial,edited});
  }
  // すべての切り替え組合せで、編集可否と送信値の保持を確認する。
  const limitStates=[];
  for (const waf of [true,false]) for (const traffic of [true,false]) for (const client of [true,false]) {
    const state=await evaluate(`(() => {
      const f=document.querySelector('#waf-settings');
      const original=Object.fromEntries(new FormData(f));
      for (const [name,value] of Object.entries({enabled:${waf},traffic_enabled:${traffic},client_enabled:${client}})) f.elements[name].value=String(value);
      f.dispatchEvent(new Event('change',{bubbles:true}));
      const enabled=${waf} && ${traffic};
      const groups=[...f.querySelectorAll('[data-waf-limit]')];
      const correct=groups.every(g=>{const off=!enabled || g.dataset.wafLimit==='client' && !${client};return g.getAttribute('aria-disabled')===String(off) && [...g.querySelectorAll('input')].every(e=>e.disabled===off)});
      const data=new FormData(f);
      return {correct,trafficDisabled:f.elements.traffic_enabled.disabled,clientDisabled:f.elements.client_enabled.disabled,fields:[...data.keys()].sort(),valuesPreserved:[...f.querySelectorAll('input[type="number"]')].every(e=>data.get(e.name)===original[e.name]),flags:[data.get('enabled'),data.get('traffic_enabled'),data.get('client_enabled')]};
    })()`);
    assert.ok(state.correct && state.valuesPreserved);
    assert.equal(state.trafficDisabled,!waf);assert.equal(state.clientDisabled,!(waf && traffic));
    assert.deepEqual(state.fields,expectedFields);assert.deepEqual(state.flags,[waf,traffic,client].map(String));
    limitStates.push({waf,traffic,client,...state});
  }
  await screenshot('waf-disabled');
  const expectedSubmission=await evaluate(`Object.fromEntries(new FormData(document.querySelector('#waf-settings')))`);
  const submittedPage=loaded();submittedPage.catch(()=>{});
  await evaluate(`(() => {const f=document.querySelector('#waf-settings');f.action='/submit-check';f.requestSubmit();})()`);
  await submittedPage;
  assert.ok(submitted,'Native form submission missing');
  assert.deepEqual([...submitted.keys()].sort(),expectedFields);
  assert.deepEqual(Object.fromEntries(submitted),expectedSubmission,'Disabled settings lost on native submit');

  await send('Emulation.setDeviceMetricsOverride',{width:390,height:1000,deviceScaleFactor:1,mobile:true});
  await send('Emulation.setScriptExecutionDisabled',{value:true});
  await navigate(admin+'/');
  const noJS=await evaluate(`(() => {const details=document.querySelector('#waf-search-limits');details.querySelector('summary').click();return {open:details.open,fields:[...new FormData(document.querySelector('#waf-settings')).keys()].sort(),overflow:document.documentElement.scrollWidth>innerWidth};})()`);
  assert.ok(noJS.open && !noJS.overflow);assert.deepEqual(noJS.fields,expectedFields);
  assert.deepEqual(errors.filter(message=>!message.includes('404')),[],'Browser errors');
  await writeFile(path.join(output,'result.json'),JSON.stringify({status:'PASS',measurements,limitStates,nativeSubmit:true,noJS:true},null,2),{mode:0o600});
  console.log(JSON.stringify({status:'PASS',viewports:measurements.length,toggleStates:limitStates.length,nativeSubmit:true,noJS:true,formFields:expectedFields.length,screenshots:output}));
} finally {
  ws?.close(); browser.kill('SIGTERM');
  await new Promise(resolve=>{if(browser.exitCode!==null)resolve();else browser.once('exit',resolve);});
  await rm(profile,{recursive:true,force:true,maxRetries:10,retryDelay:100});
  server.closeAllConnections(); server.close();
}
