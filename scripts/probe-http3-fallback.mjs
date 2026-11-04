/** 実Chromiumの通常Alt-Svc選択でHTTP/3へ移行し、UDP断後のHTTP/2応答を検証する。 */
import { spawn } from 'node:child_process';
import { readFile, mkdir } from 'node:fs/promises';
import { connect as connectTLS } from 'node:tls';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import path from 'node:path';

const options = Object.fromEntries(process.argv.slice(2).reduce((pairs, value, i, all) =>
  i % 2 === 0 ? [...pairs, [value.slice(2), all[i + 1]]] : pairs, []));
const origin = options.origin;
const control = options.control;
const address = new URL(origin);
const controlAddress = new URL(control);
if (address.protocol !== 'https:' || address.hostname !== 'localhost' || !address.port ||
    origin !== address.origin || controlAddress.protocol !== 'http:' ||
    controlAddress.hostname !== '127.0.0.1' || !controlAddress.port || control !== controlAddress.origin) {
  throw new Error('isolated loopback endpoints required');
}
const profile = path.resolve(options.profile + '-' + process.pid);
await mkdir(profile, { recursive: true, mode: 0o700 });
const spki = await new Promise((resolve, reject) => {
  const socket = connectTLS({ host: '127.0.0.1', port: Number(address.port), rejectUnauthorized: false }, () => {
    const key = socket.getPeerX509Certificate().publicKey.export({ type: 'spki', format: 'der' });
    resolve(createHash('sha256').update(key).digest('base64'));
    socket.end();
  });
  socket.on('error', reject);
});
// port 1指定はlocalhostの未知root許可用。実際の試験portのHTTP/3選択を強制しない。
const flags = [
  '--headless', '--no-sandbox', '--disable-gpu', '--remote-debugging-port=0',
  `--user-data-dir=${profile}`, `--ignore-certificate-errors-spki-list=${spki}`,
  '--no-proxy-server', '--no-first-run', '--disable-background-networking',
  '--disable-component-update', '--enable-quic', '--origin-to-force-quic-on=localhost:1',
  '--host-resolver-rules=MAP localhost 127.0.0.1', `--log-net-log=${profile}/netlog.json`,
];
const child = spawn(options.chrome, [...flags, 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'] });
let stderr = '', ws, next = 0;
const pending = new Map();
child.stderr.on('data', data => { stderr += data.toString(); });

/** CDPを要求IDで照合し、失敗やタイムアウトを成功として扱わない。 */
function send(method, params = {}) {
  const id = ++next;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error('CDP timeout ' + method));
    }, 90000);
    pending.set(id, {
      resolve: result => { clearTimeout(timer); resolve(result); },
      reject: error => { clearTimeout(timer); reject(error); },
    });
    ws.send(JSON.stringify({ id, method, params }));
  });
}

/** 全本文hashとresource timingを返し、キャッシュや圧縮による代替を検出する。 */
async function readDAT() {
  const result = await send('Runtime.evaluate', {
    expression: `(async () => {
      const url = '/dat?fallback=' + crypto.randomUUID();
      const start = performance.now();
      const response = await fetch(url, { cache: 'no-store' });
      const body = await response.arrayBuffer();
      const digest = await crypto.subtle.digest('SHA-256', body);
      const hash = Array.from(new Uint8Array(digest), x => x.toString(16).padStart(2, '0')).join('');
      const entry = performance.getEntriesByName(location.origin + url).at(-1);
      return { protocol: entry?.nextHopProtocol, status: response.status, bytes: body.byteLength,
        sha256: hash, encoding: response.headers.get('content-encoding'),
        alt_svc: response.headers.get('alt-svc'), elapsed_ms: performance.now() - start };
    })()`,
    awaitPromise: true,
    returnByValue: true,
  });
  if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
  const value = result.result.value;
  if (value.status !== 200 || value.bytes !== 65536 || value.encoding ||
      value.sha256 !== '079dfa4bbb15bbcc92e08465e77507b100ec01a702f1fa6a76e0ba93fcd44b5f') {
    throw new Error('invalid response ' + JSON.stringify(value));
  }
  return value;
}

try {
  let port;
  for (let attempt = 0; attempt < 100; attempt++) {
    if (child.exitCode !== null) throw new Error(stderr);
    try {
      port = Number((await readFile(path.join(profile, 'DevToolsActivePort'), 'utf8')).split('\n')[0]);
      break;
    } catch {
      await new Promise(resolve => setTimeout(resolve, 50));
    }
  }
  if (!port) throw new Error('browser readiness timeout ' + stderr);
  const version = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json();
  const pages = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
  ws = new WebSocket(pages.find(page => page.type === 'page').webSocketDebuggerUrl);
  ws.addEventListener('message', event => {
    const message = JSON.parse(event.data);
    const request = pending.get(message.id);
    if (!request) return;
    pending.delete(message.id);
    if (message.error) request.reject(new Error(JSON.stringify(message.error)));
    else request.resolve(message.result);
  });
  await once(ws, 'open');
  await send('Page.enable');
  await send('Runtime.enable');
  await send('Page.navigate', { url: origin + '/metrics' });
  for (let attempt = 0; attempt < 100; attempt++) {
    const result = await send('Runtime.evaluate', {
      expression: 'location.href + " " + document.readyState', returnByValue: true,
    });
    if (result.result?.value === origin + '/metrics complete') break;
    if (attempt === 99) throw new Error('navigation timeout ' + JSON.stringify(result));
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  const warm = [];
  for (let i = 0; i < 100; i++) {
    const response = await readDAT();
    warm.push(response);
    if (response.protocol === 'h3') break;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  if (warm.at(-1)?.protocol !== 'h3') {
    throw new Error('automatic HTTP/3 not established ' + JSON.stringify(warm));
  }
  const before = await (await fetch(control + '/drop', { method: 'POST' })).json();
  const fallback = await readDAT();
  if (fallback.protocol !== 'h2') throw new Error('did not fall back to h2 ' + JSON.stringify(fallback));
  const continued = [];
  for (let i = 0; i < 10; i++) continued.push(await readDAT());
  if (continued.some(response => response.protocol !== 'h2')) throw new Error('TCP continuity failed');
  const relay = await (await fetch(control + '/stats')).json();
  if (!relay.dropped_udp) throw new Error('no UDP packet was dropped');
  console.log(JSON.stringify({
    browser: version.Browser,
    scope: 'isolated loopback relay; ordinary Alt-Svc; test port not forced; localhost:1 permits ephemeral root; GET only',
    browser_flags: flags.filter(flag => !flag.startsWith('--user-data-dir') && !flag.startsWith('--log-net-log')),
    warm, fallback, continued, relay_before_drop: before, relay,
  }, null, 2));
} finally {
  if (ws) ws.close();
  const exited = child.exitCode === null && child.signalCode === null ? once(child, 'exit') : Promise.resolve();
  child.kill('SIGTERM');
  const timer = setTimeout(() => child.kill('SIGKILL'), 3000);
  timer.unref();
  await exited.catch(() => {});
  clearTimeout(timer);
  if (stderr) process.stderr.write(stderr);
}
