/** 実専ブラの確認/DATパーサーで隔離サーバーのキャップ投稿・停止を検査する。 */
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { stripTypeScriptTypes } from 'node:module';
import { resolve } from 'node:path';
const [base, credentialFile, phase = 'post', checkout = '/home/patatan/Ole Board Browser'] = process.argv.slice(2);
assert.ok(['127.0.0.1', 'localhost', '[::1]'].includes(new URL(base).hostname), 'loopback validation only');
assert.ok(['post', 'revoked', 'restored'].includes(phase), 'known phase required');
const state = JSON.parse(await readFile(credentialFile, 'utf8'));
assert.match(state.board, /^[a-z][a-z0-9_]{0,31}$/);
assert.ok(/^#cap:[0-9a-f-]+:[A-Za-z0-9_-]{43}$/.test(state.credential), 'canonical credential required');
const sources = {};
async function load(relative) {
  const source = await readFile(resolve(checkout, relative), 'utf8');
  sources[relative] = createHash('sha256').update(source).digest('hex');
  return import(`data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(source)).toString('base64')}`);
}
const confirmation = await load('src/functions/post/bbsPostConfirmation.ts');
const datFields = await load('src/functions/dat/datLineFields.ts');
const version = JSON.parse(await readFile(resolve(checkout, 'package.json'), 'utf8')).version;
const decoder = new TextDecoder('shift_jis', { fatal: true });
const cookies = new Map();
async function post(fields) {
  const escaped = Object.fromEntries(Object.entries(fields).map(([k, v]) => [k, [...v].map(c => c.codePointAt(0) > 127 ? `&#${c.codePointAt(0)};` : c).join('')]));
  const cookie = [...cookies].map(([k, v]) => `${k}=${v}`).join('; ');
  const response = await fetch(`${base}/test/bbs.cgi`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=Shift_JIS', ...(cookie ? { Cookie: cookie } : {}) }, body: new URLSearchParams(escaped) });
  assert.equal(response.status, 200);
  for (const header of response.headers.getSetCookie()) {
    const [pair, ...attributes] = header.split(';');
    const i = pair.indexOf('=');
    assert.ok(i > 0, 'cookie structure');
    if (attributes.some(a => /^\s*max-age\s*=\s*0\s*$/i.test(a))) cookies.delete(pair.slice(0, i));
    else cookies.set(pair.slice(0, i), pair.slice(i + 1));
  }
  return decoder.decode(await response.arrayBuffer());
}
const fields = { bbs: state.board, FROM: '通信試験#A', mail: `sage ${state.credential}`, MESSAGE: 'キャップ通信確認', time: '1', submit: '書き込む' };
if (phase === 'post') {
  fields.subject = `キャップ専ブラ確認 ${Date.now()}`;
  fields.oimo_request_id = 'cap-client-create-00001';
  const confirmed = confirmation.createBbsCookieConfirmationFields(await post(fields), fields);
  assert.ok(confirmed, 'actual client confirmation parser');
  assert.ok(cookies.has('oimo_anon'), 'required anonymous Cookie issued');
  assert.ok((await post(confirmed)).includes('書きこみが終わりました。'), 'cap accepted');
  assert.ok((await post(confirmed)).includes('受理済み'), 'cap deduplication');
  const subjects = decoder.decode(await (await fetch(`${base}/${state.board}/subject.txt`)).arrayBuffer());
  const key = subjects.split('\n').find(line => line.endsWith(`.dat<>${fields.subject} (1)`))?.split('.dat<>')[0];
  assert.ok(key, 'created thread found');
  state.key = key;
  await writeFile(credentialFile, JSON.stringify(state), { mode: 0o600 });
  fields.key = key;
  delete fields.subject;
  fields.oimo_request_id = 'cap-client-reply-000001';
  const reply = confirmation.createBbsCookieConfirmationFields(await post(fields), fields);
  assert.ok(reply, 'reply confirmation');
  assert.ok((await post(reply)).includes('書きこみが終わりました。'), 'cap reply accepted');
  assert.ok(cookies.has('oimo_anon'), 'Cookie retained by harness');
} else {
  fields.key = state.key;
  fields.oimo_request_id = 'cap-client-after-stop';
  const result = await post(fields);
  assert.ok(result.includes('キャップ') && result.includes('ERROR') && !result.includes('書きこみが終わりました。'), 'revoked credential refused');
}
const dat = await fetch(`${base}/${state.board}/dat/${state.key}.dat`);
assert.equal(dat.status, 200);
const bytes = new Uint8Array(await dat.arrayBuffer());
const text = decoder.decode(bytes);
assert.ok(!text.includes(state.credential) && !text.includes(state.credential.split(':')[2]), 'no credential in DAT');
const lines = text.trimEnd().split('\n');
assert.equal(lines.length, 2);
for (const line of lines) {
  const parsed = datFields.splitStandardDatLine(line, line.indexOf('<>'));
  assert.ok(parsed.name.includes('◆hRJ9Ya./t.') && parsed.name.includes(`${state.name} ★`), 'trip and cap components');
  assert.equal(parsed.mail, 'sage');
  assert.ok(parsed.date.includes('ID:CAP_USER'), 'cap public ID');
  assert.equal(parsed.body, fields.MESSAGE);
}
const sha256 = createHash('sha256').update(bytes).digest('hex');
if (phase === 'post') {
  state.sha256 = sha256;
  state.etag = dat.headers.get('etag');
  await writeFile(credentialFile, JSON.stringify(state), { mode: 0o600 });
} else {
  assert.equal(sha256, state.sha256, 'historical DAT preserved');
  assert.equal(dat.headers.get('etag'), state.etag, 'historical ETag preserved');
}
console.log(JSON.stringify({ status: 'PASS', client: 'OleBoardBrowser', version, phase, sources, checks: ['confirmation', 'required Cookie', 'trip and cap DAT', 'secret removal', 'deduplication', 'revoke and restart history'], scope: 'real HTTP and client source parsers; no Android UI execution' }, null, 2));
