"""隔離loopbackサイトでキャップ管理と実専ブラパーサーを検証し、保存先を回収する。"""
from pathlib import Path
import html.parser
import http.cookiejar
import json
import os
import re
import secrets
import signal
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]
CHECKOUT = Path('/home/patatan/Ole Board Browser')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """ログインの303を成功として観測し、遷移先へ要求を送らない。"""
    def redirect_request(self, *args):
        return None


class FormFields(html.parser.HTMLParser):
    """管理HTMLが発行したhidden値を抽出する。"""
    def __init__(self, page):
        super().__init__()
        self.fields = {}
        self.feed(page.decode('utf-8'))

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'input' and attrs.get('type') == 'hidden':
            self.fields[attrs['name']] = attrs.get('value', '')


def unused_port():
    """専用loopback待受用の未使用portを選ぶ。"""
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


class Fixture:
    """一時サイトのprocess・秘密・管理Cookieを同じ所有範囲に閉じ込める。"""
    def __init__(self, root):
        self.root = Path(root)
        self.binary = self.root / 'oimobbs'
        self.config = self.root / 'config.json'
        self.credential = self.root / 'credential.json'
        self.public = f'http://127.0.0.1:{unused_port()}'
        self.admin = f'http://127.0.0.1:{unused_port()}'
        self.process = None
        self.password = secrets.token_urlsafe(24)
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), NoRedirect())
        self.log = (self.root / 'server.log').open('w')

    def prepare(self):
        """現在のコードをbuildし、この一時保存先だけを初期化する。"""
        subprocess.run(['mise', 'exec', '--', 'go', 'build', '-o', str(self.binary), './cmd/oimobbs'],
                       cwd=ROOT, check=True)
        cfg = json.loads((ROOT / 'config.example.json').read_text())
        cfg['data_dir'] = str(self.root / 'data')
        cfg['public']['listen'] = self.public.removeprefix('http://')
        cfg['public']['base_url'] = self.public
        cfg['admin']['listen'] = self.admin.removeprefix('http://')
        cfg['admin']['origin'] = self.admin
        self.config.write_text(json.dumps(cfg))
        self.cli(['init'])
        self.cli(['board', 'create', '--key', 'caps', '--name', 'キャップ試験'])
        self.cli(['admin', 'init', '--login', 'owner', '--password-stdin'], self.password + '\n')
        self.cli(['admission', 'enable'])
        self.cli(['anonymous', 'enable', '--mode', 'required'])

    def cli(self, args, password=None):
        """原秘密は標準入力に限定し、CLI結果を検査する。"""
        result = subprocess.run([str(self.binary), *args, '--config', str(self.config)],
                                input=password, text=True, capture_output=True)
        if result.returncode:
            raise RuntimeError('CLI failed: ' + result.stderr)
        return json.loads(result.stdout)

    def start(self):
        """保存先を開く検証サーバーを起動し、listen完了を待つ。"""
        self.process = subprocess.Popen(
            [str(self.binary), 'validation-serve', '--config', str(self.config), '--admin'],
            stdout=self.log, stderr=self.log)
        for _ in range(100):
            if self.process.poll() is not None:
                raise RuntimeError('server startup failed')
            try:
                with urllib.request.urlopen(self.public + '/bbsmenu.json', timeout=1):
                    return
            except OSError:
                time.sleep(.05)
        raise RuntimeError('readiness timeout')

    def stop(self):
        """正常終了を待ち、同じ保存先で再起動できる状態にする。"""
        if self.process is None:
            return
        self.process.send_signal(signal.SIGTERM)
        try:
            status = self.process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
            raise
        finally:
            self.process = None
        if status:
            raise RuntimeError('server shutdown failed')

    def request(self, method, path, data=None, headers=None):
        """同じ管理Cookie/OriginでHTTP要求し、原秘密を出力しない。"""
        headers = {} if headers is None else dict(headers)
        if method != 'GET':
            headers['Origin'] = self.admin
        req = urllib.request.Request(self.admin + path, data=data, headers=headers, method=method)
        try:
            response = self.opener.open(req, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, response.headers, response.read()

    def authorize(self):
        """実HTTPログインとCookie交換付き再認証を行う。"""
        _, _, page = self.request('GET', '/login')
        fields = FormFields(page).fields
        fields.update(login='owner', password=self.password)
        status, _, _ = self.request('POST', '/login', urllib.parse.urlencode(fields).encode(),
                                    {'Content-Type': 'application/x-www-form-urlencoded'})
        assert status == 303, 'login rejected'
        _, headers, _ = self.request('GET', '/api/v1/reauth')
        status, _, _ = self.request('POST', '/api/v1/reauth',
                                    json.dumps({'password': self.password}).encode(),
                                    {'Content-Type': 'application/json',
                                     'X-CSRF-Token': headers['X-CSRF-Token']})
        assert status == 200, 'reauthentication rejected'

    def configure_board(self):
        """キャップ専用板でもCookie requiredを維持する。"""
        _, _, body = self.request('GET', '/api/v1/boards')
        board = json.loads(body)['data'][0]
        path = '/api/v1/boards/' + board['id'] + '/settings'
        _, headers, _ = self.request('GET', path)
        edit = board['settings']
        edit.update(create_policy='cap_only', reply_policy='cap_only',
                    anonymous={'cookie_mode': 'required', 'token_wait_seconds': 0})
        status, _, _ = self.request('PATCH', path, json.dumps(edit).encode(), {
            'Content-Type': 'application/json', 'X-CSRF-Token': headers['X-CSRF-Token'],
            'If-Match': headers['ETag'], 'Idempotency-Key': str(uuid.uuid4())})
        assert status == 200, 'board settings rejected'
        return board['id']

    def issue(self, board):
        """HTML入力で発行し、一回限りの秘密を0600ファイルへ渡す。"""
        _, _, page = self.request('GET', '/caps')
        fields = FormFields(page).fields
        fields.update(display_name='通信運営', board_ids=board, permissions='create post',
                      expires_at=time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(time.time() + 86400)))
        status, _, body = self.request('POST', '/caps', urllib.parse.urlencode(fields).encode(),
                                      {'Content-Type': 'application/x-www-form-urlencoded'})
        assert status == 200, 'HTML issuance rejected'
        credential = re.search(rb'#cap:([0-9a-f-]+):[A-Za-z0-9_-]{43}', body)
        assert credential is not None, 'first secret unavailable'
        state = {'board': 'caps', 'name': '通信運営', 'credential': credential[0].decode()}
        self.credential.write_text(json.dumps(state))
        return credential[1].decode()

    def revoke(self, cap):
        """API停止をCAS/CSRF付きで確定する。"""
        path = '/api/v1/caps/' + cap
        _, headers, _ = self.request('GET', path)
        status, _, _ = self.request('POST', path + '/revoke', b'{}', {
            'Content-Type': 'application/json', 'X-CSRF-Token': headers['X-CSRF-Token'],
            'If-Match': headers['ETag'], 'Idempotency-Key': str(uuid.uuid4())})
        assert status == 200, 'revoke rejected'

    def node(self, phase):
        """実クライアントパーサーへ渡す秘密をコマンド引数に含めない。"""
        subprocess.run(['mise', '-C', str(CHECKOUT), 'exec', '--', 'node',
                        str(ROOT / 'tools/clientcheck/caps.mjs'), self.public,
                        str(self.credential), phase, str(CHECKOUT)], cwd=ROOT, check=True)


def main():
    """成功・失敗のどちらでも検証サーバーと一時保存先を回収する。"""
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='oimobbs-caps-client-') as root:
        fixture = Fixture(root)
        try:
            fixture.prepare()
            fixture.start()
            fixture.authorize()
            cap = fixture.issue(fixture.configure_board())
            fixture.node('post')
            fixture.revoke(cap)
            fixture.node('revoked')
            fixture.stop()
            fixture.start()
            fixture.node('restored')
        finally:
            try:
                fixture.stop()
            finally:
                fixture.log.close()
    print(json.dumps({'status': 'PASS', 'scope': 'isolated cap-only board; Cookie required; actual parser; revoke and restart',
                      'temporary_data_removed': True}))


if __name__ == '__main__':
    main()
