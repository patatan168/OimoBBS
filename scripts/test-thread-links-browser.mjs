/** 公開レス本文のURL・返信リンクと、投稿文字列の安全な表示を独立ブラウザで検証する。 */
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {readFile} from 'node:fs/promises';

const {chromium, firefox} = createRequire(import.meta.url)(process.env.OIMO_PLAYWRIGHT);
const browser = await (process.env.OIMO_FIREFOX
  ? firefox.launch({headless: true, executablePath: process.env.OIMO_FIREFOX_EXECUTABLE})
  : chromium.launch({headless: true, executablePath: process.env.OIMO_CHROMIUM, args: ['--no-sandbox']}));
const base = 'https://thread.test';
const thread = '/test/read.cgi/test/123/';
const cases = [
  {body: '普通の本文\n改行も保持する', links: []},
  {body: '参照 https://example.test/path?a=1&b=2#part と http://example.test/', links: ['https://example.test/path?a=1&b=2#part', 'http://example.test/']},
  {body: 'HTTPS://example.test/日本語', links: ['HTTPS://example.test/日本語']},
  {body: '「https://example.test/a」。次は（https://example.test/b）、終わり', links: ['https://example.test/a', 'https://example.test/b']},
  {body: '(https://example.test/wiki/Foo_(bar)). [https://example.test/a] https://example.test/b!?', links: ['https://example.test/wiki/Foo_(bar)', 'https://example.test/a', 'https://example.test/b']},
  {body: '>>1 と >>999 https://example.test/#>>2', links: ['>>1', '>>999', 'https://example.test/#', '>>2']},
  {body: 'javascript:alert(1) data:text/html,test ftp://example.test/ https://', links: []},
  {body: '<img src=x onerror="window.linkXSS=1"> https://example.test/"onclick="alert(1) <script>window.linkXSS=2</script>', links: ['https://example.test/']},
  {body: 'https://example.test/%22%3E%3Cscript%3E?q=%26 https://[::1]:8080/a', links: ['https://example.test/%22%3E%3Cscript%3E?q=%26', 'https://[::1]:8080/a']},
  {body: 'http://[invalid]/ https://example.test:bad/ >>0 >>123456', links: []},
];
const escapeHTML = text => text.replace(/[&<>"']/g, char => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[char]));
const assets = new Map(await Promise.all(['ui.css', 'public.css', 'thread.css', 'thread.js'].map(async name => [name, await readFile(new URL('../internal/webui/assets/' + name, import.meta.url))])));
const html = `<!doctype html><html lang="ja"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  ${['ui.css', 'public.css', 'thread.css'].map(name => `<link rel="stylesheet" href="/${name}">`).join('')}
  <script src="/thread.js" defer></script><body class="public"><main data-thread-base="${thread}">
  <form data-response-jump hidden><input name="response" type="number" min="1" max="999" required><button>移動</button></form>
  <div class="response-list">${cases.map((test, index) => `<article id="${index + 1}"><pre class="response-body" data-response-body>${escapeHTML(test.body)}</pre></article>`).join('')}</div>
  </main></body></html>`;

try {
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  // 全通信を試験内で完結させ、投稿中の外部URLには接続しない。
  await page.context().route('**/*', route => {
    const url = new URL(route.request().url());
    const asset = assets.get(url.pathname.slice(1));
    if (url.origin === base && asset) return route.fulfill({body: asset, contentType: url.pathname.endsWith('.js') ? 'text/javascript' : 'text/css'});
    return route.fulfill({body: url.origin === base ? html : '<!doctype html><title>リンク先</title>', contentType: 'text/html'});
  });
  await page.goto(base + thread);
  const bodies = page.locator('[data-response-body]');
  assert.deepEqual(await bodies.allTextContents(), cases.map(test => test.body), '本文と改行を保持する');
  for (let index = 0; index < cases.length; index++) {
    const body = bodies.nth(index);
    assert.deepEqual(await body.locator('a').allTextContents(), cases[index].links, `レス${index + 1}のリンク`);
    assert.equal(await body.locator('img, script, [onclick], [onerror], a a').count(), 0);
    for (const link of await body.locator('a').all()) {
      const label = await link.textContent();
      const href = await link.getAttribute('href');
      if (label.startsWith('>>')) {
        assert.equal(href, label === '>>999' ? thread + '999n' : '#' + label.slice(2));
      } else {
        assert.equal(href, label);
        assert.equal(await link.getAttribute('target'), '_blank');
        assert.deepEqual((await link.getAttribute('rel')).split(' ').sort(), ['nofollow', 'noopener', 'noreferrer', 'ugc']);
      }
    }
  }
  assert.equal(await page.evaluate(() => window.linkXSS), undefined);
  // 再実行しても、返信リンクやURLが重複・入れ子にならない。
  await page.addScriptTag({content: assets.get('thread.js').toString()});
  assert.deepEqual(await bodies.allTextContents(), cases.map(test => test.body));
  assert.equal(await bodies.locator('a').count(), cases.reduce((sum, test) => sum + test.links.length, 0));

  const opened = page.waitForEvent('popup');
  await bodies.nth(1).locator('a').first().click();
  const popup = await opened;
  await popup.waitForLoadState();
  assert.equal(popup.url(), 'https://example.test/path?a=1&b=2#part');
  assert.deepEqual(await popup.evaluate(() => ({opener: window.opener, referrer: document.referrer})), {opener: null, referrer: ''});
  await popup.close();
  await bodies.nth(5).getByText('>>1', {exact: true}).click();
  assert.equal(new URL(page.url()).hash, '#1');
  await page.locator('input[name=response]').fill('2');
  await page.locator('[data-response-jump] button').click();
  assert.equal(new URL(page.url()).hash, '#2');
  for (const width of [320, 1280]) {
    await page.setViewportSize({width, height: 900});
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
    if (process.env.OIMO_THREAD_SCREENSHOT_DIR) await page.screenshot({path: `${process.env.OIMO_THREAD_SCREENSHOT_DIR}/thread-links-${width}.png`, fullPage: true});
  }
  assert.deepEqual(errors, []);
  console.log(`PASS: ${cases.length}本文、URL遷移・返信・番号移動・安全性・再実行・320/1280px表示`);
} finally {
  await browser.close();
}
