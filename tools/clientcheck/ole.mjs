/** OleBoardBrowserの既存パーサを変更せず、検証サーバーの通信結果と照合する。 */
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { stripTypeScriptTypes } from 'node:module';
import { resolve } from 'node:path';
const [base = 'http://127.0.0.1:9080', checkout = '/home/patatan/Ole Board Browser', board = 'oimo', replyKey] = process.argv.slice(2);
assert.match(board, /^[a-z][a-z0-9_]{0,31}$/);
const origins = new URL(base);
assert.ok(['localhost','127.0.0.1','[::1]'].includes(origins.hostname) || origins.origin === 'https://patatanmc.f5.si', 'authorized validation server only');
const sources = {};
async function load(relative) {
  const source = await readFile(resolve(checkout, relative), 'utf8');
  sources[relative] = createHash('sha256').update(source).digest('hex');
  return import(`data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(source)).toString('base64')}`);
}
const confirmation = await load('src/functions/post/bbsPostConfirmation.ts');
const datFields = await load('src/functions/dat/datLineFields.ts');
const ranges = await load('src/functions/dat/datByteRange.ts');
const version = JSON.parse(await readFile(resolve(checkout,'package.json'),'utf8')).version;
const decoder = new TextDecoder('shift_jis', { fatal: true });
const cookies = new Map();
async function post(fields) {
  // 非ASCIIはクライアントが使用する十進参照へ。フォーム自体はASCII/SJIS共通。
  const escaped = Object.fromEntries(Object.entries(fields).map(([k,v]) => [k, [...v].map(c => c.codePointAt(0) > 127 ? `&#${c.codePointAt(0)};` : c).join('')]));
  const cookie = [...cookies].map(([name,value]) => `${name}=${value}`).join('; ');
  const response = await fetch(`${base}/test/bbs.cgi`, { method:'POST', headers: { 'Content-Type':'application/x-www-form-urlencoded; charset=Shift_JIS', ...(cookie ? {Cookie:cookie}: {}) }, body:new URLSearchParams(escaped) });
  assert.equal(response.status,200);
  const set = response.headers.getSetCookie();
  // 確認Cookieだけの更新で、既存の匿名Cookieを落とさない。実機の保存挙動とは別の試験jar。
  for (const header of set) {
    const [pair, ...attributes] = header.split(';');
    const index = pair.indexOf('=');
    assert.ok(index > 0, 'Set-Cookie name/value');
    const name = pair.slice(0,index);
    if (attributes.some(attribute => /^\s*max-age\s*=\s*0\s*$/i.test(attribute))) cookies.delete(name);
    else cookies.set(name,pair.slice(index+1));
  }
  return decoder.decode(await response.arrayBuffer());
}
if (replyKey) {
  assert.match(replyKey, /^[1-9][0-9]*$/);
  const datURL = `${base}/${board}/dat/${replyKey}.dat`;
  const before = new Uint8Array(await (await fetch(datURL)).arrayBuffer());
  const fields = {bbs:board,key:replyKey,FROM:'専ブラ通信確認',mail:'sage',MESSAGE:'OleBoardBrowserの投稿経路修正を確認しました。',time:'1',submit:'書き込む'};
  const confirmed = confirmation.createBbsCookieConfirmationFields(await post(fields), fields);
  assert.ok(confirmed, 'confirmation parser');
  assert.ok((await post(confirmed)).includes('書きこみが終わりました。'));
  assert.ok((await post(confirmed)).includes('受理済み'));
  const delta = await fetch(datURL, {headers:{Range:`bytes=${before.length}-`, 'Accept-Encoding':'identity'}});
  assert.equal(delta.status,206);
  const tail = new Uint8Array(await delta.arrayBuffer());
  assert.equal(decoder.decode(tail).trimEnd().split('\n').length,1);
  const parsed = datFields.splitStandardDatLine(decoder.decode(tail).trimEnd(), decoder.decode(tail).indexOf('<>'));
  assert.equal(parsed.body,fields.MESSAGE);
  console.log(JSON.stringify({status:'PASS',client:'OleBoardBrowser',version,replyKey,scope:`${origins.protocol === 'https:' ? 'HTTPS' : 'HTTP'} plus real client parsers; no Android UI execution`,sources},null,2));
  process.exit(0);
}
const menu = await (await fetch(`${base}/bbsmenu.json`)).json();
assert.ok(menu.menu_list.some(category => category.category_content.some(item => item.url === `${base}/${board}/`)));
const title = `Ole互換試験 ${Date.now()}`;
const fields = {bbs:board,FROM:'tester#A',mail:'',subject:title,MESSAGE:'本文😀\n<script>&',time:'1',submit:'新規スレッド作成'};
const first = await post(fields);
const anonymousIssued = cookies.has('oimo_anon');
const confirmed = confirmation.createBbsCookieConfirmationFields(first, fields);
assert.ok(confirmed, 'Ole must recognize confirmation');
assert.equal(confirmed.MESSAGE,fields.MESSAGE);
const success = await post(confirmed);
assert.ok(success.includes('書きこみが終わりました。'));
const subject = decoder.decode(await (await fetch(`${base}/${board}/subject.txt`)).arrayBuffer());
const key = subject.split('\n').find(line => line.endsWith(`.dat<>${title} (1)`))?.split('.dat<>')[0];
assert.ok(key, subject);
const datURL = `${base}/${board}/dat/${key}.dat`;
const initial = await fetch(datURL);
const bytes = new Uint8Array(await initial.arrayBuffer());
const line = decoder.decode(bytes).trimEnd();
const parsed = datFields.splitStandardDatLine(line, line.indexOf('<>'));
assert.ok(parsed.name.includes('◆hRJ9Ya./t.'));
assert.equal(parsed.body,'本文&#128512;<br>&lt;script&gt;&amp;');
assert.ok(parsed.date.includes(' ID:'));
assert.equal(confirmation.createBbsCookieConfirmationFields(success, fields),null);
const repeat = await post(confirmed);
assert.ok(repeat.includes('受理済み'));
const reply = {bbs:board,FROM:'tester',mail:'sage',key,MESSAGE:'返信',time:'2',submit:'書き込む'};
const replyConfirm = confirmation.createBbsCookieConfirmationFields(await post(reply),reply);
assert.ok(replyConfirm);
if (anonymousIssued) assert.ok(cookies.has('oimo_anon'), 'confirmation update must retain anonymous Cookie in harness');
assert.ok((await post(replyConfirm)).includes('書きこみが終わりました。'));
const delta = await fetch(datURL,{headers:{Range:`bytes=${bytes.length}-`, 'Accept-Encoding':'identity'}});
assert.equal(delta.status,206);
const tail = new Uint8Array(await delta.arrayBuffer());
const total = ranges.resolvePartialDatByteLength(delta.headers.get('Content-Range'),bytes.length,tail.length);
assert.equal(total,bytes.length+tail.length);
assert.equal(decoder.decode(tail).split('<>')[3],'返信');
const head = await fetch(datURL,{method:'HEAD',headers:{Range:'bytes=1-'}});
assert.equal(head.status,200);
assert.equal((await head.arrayBuffer()).byteLength,0);
console.log(JSON.stringify({ status:'PASS', client:'OleBoardBrowser', version, board, scope:'real HTTP plus client source parsers; no Android UI execution', sources, checks:['menu','confirmation parser','Japanese DAT','trip','HTML escaping','deduplication','reply','Range parser','HEAD'] },null,2));
