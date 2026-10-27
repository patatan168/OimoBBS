#!/usr/bin/env python3
"""隔離した保存先とloopbackで、セットアップ・TLS・再実行拒否を検証する。"""
import hashlib
import html.parser
import http.cookiejar
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request

sys.dont_write_bytecode = True
SCRIPT = Path(__file__).with_name('setup.sh')
SECRET = 'setup-test-secret-2026-ONLY'


class Fields(html.parser.HTMLParser):
    """ログイン画面からCSRFを含むhidden入力を読み出す。"""
    def __init__(self, page):
        super().__init__()
        self.values = {}
        self.feed(page)

    def handle_starttag(self, tag, attrs):
        row = dict(attrs)
        if tag == 'input' and row.get('type') == 'hidden':
            self.values[row['name']] = row.get('value', '')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """ログイン成功の303を直接検査するため、自動転送を無効にする。"""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def port():
    """隔離サーバーに使うloopbackの空きポートを返す。"""
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


@unittest.skipUnless(os.environ.get('OIMO_SETUP_TEST_BINARY'), 'OIMO_SETUP_TEST_BINARYが必要です')
class SetupIntegrationTests(unittest.TestCase):
    """実CLI・HTTP・検証済みTLSで初期設定と再起動を検査する。"""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='oimo-setup-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / 'config.json'
        self.binary = Path(os.environ['OIMO_SETUP_TEST_BINARY']).absolute()

    def invoke(self, extra=(), password=SECRET, build=False, env=None):
        """秘密を引数へ含めず、隔離先でスクリプトを実行する。"""
        command = ["bash", str(SCRIPT), '--config', str(self.config), '--password-stdin']
        if not build:
            command += ['--binary', str(self.binary)]
        result = subprocess.run([*command, *extra], input=password + '\n',
                                text=True, capture_output=True, timeout=180, env=env)
        self.assertNotIn(password, result.stdout + result.stderr)
        return result

    def opener(self, certificate=None):
        """Cookieを保持し、HTTPSでは試験証明書を信頼して名前も検査する。"""
        handlers = [urllib.request.ProxyHandler({}),
                    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), NoRedirect()]
        if certificate:
            handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=certificate)))
        return urllib.request.build_opener(*handlers)

    def request(self, opener, url, fields=None, origin=None):
        """隔離HTTPへ接続し、秘密が応答へ出ていないことを確認する。"""
        data = None if fields is None else urllib.parse.urlencode(fields).encode()
        req = urllib.request.Request(url, data=data)
        if fields is not None:
            req.add_header('Origin', origin)
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        try:
            result = opener.open(req, timeout=2)
        except urllib.error.HTTPError as error:
            result = error
        with result:
            body = result.read()
            self.assertNotIn(SECRET.encode(), body)
            return result.status, body

    def serve(self, launch, public_url, admin_url, certificate=None, stop_signal=signal.SIGTERM):
        """サーバー起動後に公開板と管理者認証を確認し、必ず正常停止する。"""
        output = tempfile.TemporaryFile()
        try:
            process = subprocess.Popen(launch, stdin=subprocess.PIPE, stdout=output, stderr=output)
            opener = self.opener(certificate)
            try:
                process.stdin.write((SECRET + '\n').encode())
                process.stdin.close()
                deadline = time.monotonic() + 30
                while True:
                    try:
                        status, menu = self.request(opener, public_url + '/bbsmenu.json')
                        if status == 200:
                            break
                    except (OSError, urllib.error.URLError):
                        pass
                    if time.monotonic() >= deadline or process.poll() is not None:
                        output.seek(0)
                        self.fail(output.read().decode(errors='replace'))
                    time.sleep(0.05)
                self.assertIn(b'operate', menu)
                if certificate:
                    # 同じTLSポートへ平文を送っても公開本文を返さない。
                    plain_url = public_url.replace('https://', 'http://', 1)
                    try:
                        plain_status, _ = self.request(self.opener(), plain_url + '/bbsmenu.json')
                    except (OSError, urllib.error.URLError):
                        pass
                    else:
                        self.assertGreaterEqual(plain_status, 400)
                if admin_url is None:
                    admin_url = json.loads(self.config.read_text())['admin']['origin']
                status, page = self.request(opener, admin_url.rstrip('/') + '/login')
                self.assertEqual(status, 200)
                fields = Fields(page.decode()).values
                fields.update(login='owner', password=SECRET)
                status, _ = self.request(opener, admin_url.rstrip('/') + '/login', fields,
                                         urllib.parse.urlsplit(admin_url).scheme + '://' + urllib.parse.urlsplit(admin_url).netloc)
                self.assertEqual(status, 303)
                status, _ = self.request(opener, admin_url.rstrip('/') + '/api/v1/site')
                self.assertEqual(status, 200)
            finally:
                if process.poll() is None:
                    process.send_signal(stop_signal)
                try:
                    process.wait(timeout=35)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            self.assertEqual(process.returncode, 0)
        finally:
            output.close()

    def test_local_build_login_restart_and_no_overwrite(self):
        # 空白・日本語を含む設定パスでもシェル文字列へ展開せず起動できる。
        self.config = self.root / '設定 with spaces' / 'config.json'
        public_port, admin_port = port(), port()
        url = f'http://127.0.0.1:{public_port}'
        result = self.invoke(['--allow-http', '--url', url, '--listen', f'127.0.0.1:{public_port}',
                              '--admin-port', str(admin_port)], build=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        config = json.loads(self.config.read_text())
        self.assertEqual(stat_mode(self.config), 0o600)
        self.assertEqual(config['public']['tls_key_file'], '')
        self.assertEqual(config['admin']['transport'], 'public_path')
        self.assertEqual(config['admin']['listen'], '')
        self.assertEqual(config['admin']['origin'], url + '/admin/')
        binary = self.config.parent / 'bin/oimobbs'
        launch = [str(binary), 'validation-serve', '--config', str(self.config), '--admin']
        for _ in range(2):
            self.serve(launch, url, config['admin']['origin'])
        paths = [self.config, *Path(config['data_dir']).rglob('*')]
        before = {str(p): hashlib.sha256(p.read_bytes()).digest() for p in paths if p.is_file()}
        refused = self.invoke(['--login', 'another-owner'])
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual(before, {str(p): hashlib.sha256(p.read_bytes()).digest() for p in paths if p.is_file()})
        self.assertTrue(all(SECRET.encode() not in p.read_bytes() for p in paths if p.is_file()))

    @unittest.skipUnless(shutil.which('openssl'), 'TLS試験にはopensslが必要です')
    def test_https_start_and_public_admin(self):
        cert, key = self.certificate()
        public_port = port()
        url = f'https://127.0.0.1:{public_port}'
        options = ['--url', url, '--listen', f'127.0.0.1:{public_port}',
                   '--tls-cert', str(cert), '--tls-key', str(key), '--public-admin']
        result = self.invoke(options)
        self.assertEqual(result.returncode, 0, result.stderr)
        config = json.loads(self.config.read_text())
        self.assertEqual(config['admin']['origin'], url + '/admin/')
        native = [str(self.binary), 'serve', '--config', str(self.config)]
        for _ in range(2):
            self.serve(native, url, config['admin']['origin'], cert)
        self.config = self.root / 'second-config.json'
        launch = ["bash", str(SCRIPT), '--config', str(self.config),
                  '--data-dir', 'second-site', '--binary', str(self.binary),
                  *options, '--password-stdin', '--start']
        self.serve(launch, url, None, cert, stop_signal=signal.SIGINT)

    def certificate(self):
        """loopbackの名前を持つ短命な試験証明書と0600鍵を生成する。"""
        cert, key = self.root / 'cert.pem', self.root / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(key), '-out', str(cert), '-days', '1',
                        '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        key.chmod(0o600)
        return cert, key

    @unittest.skipUnless(shutil.which('openssl'), 'TLS試験にはopensslが必要です')
    def test_default_https_443_and_operations_board(self):
        """実CLIで既定HTTPS設定と運営板の永続登録を検査する。待受は行わない。"""
        cert, key = self.certificate()
        result = self.invoke(['--tls-cert', str(cert), '--tls-key', str(key)])
        self.assertEqual(result.returncode, 0, result.stderr)
        config = json.loads(self.config.read_text())
        self.assertEqual(config['public']['base_url'], 'https://localhost')
        self.assertEqual(config['public']['listen'], '0.0.0.0:443')
        self.assertEqual(config['admin']['origin'], 'https://localhost/admin/')
        listed = subprocess.run([str(self.binary), 'board', 'list', '--validation',
                                 '--config', str(self.config)], check=True, text=True,
                                capture_output=True)
        boards = json.loads(listed.stdout)
        self.assertEqual(len(boards), 1)
        self.assertEqual(boards[0]['key'], 'operate')
        self.assertEqual(boards[0]['name'], '運営')

    @unittest.skipUnless(shutil.which('openssl'), 'TLS試験にはopensslが必要です')
    def test_bad_certificate_does_not_initialize_data(self):
        cert, key = self.certificate()
        result = self.invoke(['--url', 'https://wrong.example', '--tls-cert', str(cert), '--tls-key', str(key)])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('certificate does not match', result.stderr)
        self.assertFalse((self.root / 'var/site').exists())
        self.assertTrue(self.config.is_file())

    def test_default_requires_tls_and_http_requires_opt_in(self):
        """証明書なし・HTTPの暗黙許可を拒否し、保存物を作らない。"""
        for options, message in [((), 'HTTPSには'),
                                 (['--url', 'http://127.0.0.1'], 'HTTPは既定で無効')]:
            with self.subTest(options=options):
                result = self.invoke(options)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertFalse(self.config.exists())
                self.assertFalse((self.root / 'var/site').exists())

    def test_bad_password_does_not_create_config(self):
        result = self.invoke(['--allow-http', '--url', 'http://127.0.0.1'], password='short')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.config.exists())

    @unittest.skipUnless(Path('/run/systemd/system').is_dir() and os.getuid() != 0,
                         '一般ユーザーとsystemdが必要です')
    def test_service_registration_and_existing_site_preservation(self):
        """実CLIで初期化し、sudo/systemctlだけを代替してサービス連携を検査する。"""
        commands = self.root / 'commands'
        commands.mkdir()
        sudo = commands / 'sudo'
        sudo.write_text('''#!/bin/sh
if [ "$1" = -v ]; then exit 0; fi
if [ "$2" = /bin/sh ]; then
  cat > "$SERVICE_TEST_ROOT/unit"
  exit 0
fi
printf '%s\\n' "$3" >> "$SERVICE_TEST_ROOT/actions"
''')
        systemctl = commands / 'systemctl'
        systemctl.write_text('''#!/bin/sh
printf '%s\\n' "${SERVICE_TEST_STATE:-not-found}"
''')
        sudo.chmod(0o700)
        systemctl.chmod(0o700)
        env = {**os.environ, 'PATH': str(commands) + ':' + os.environ['PATH'],
               'SERVICE_TEST_ROOT': str(self.root)}
        result = self.invoke(['--allow-http', '--url', 'http://127.0.0.1', '--install-service', '--start'], env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        unit = (self.root / 'unit').read_text()
        self.assertIn(f'User={os.getuid()}\n', unit)
        self.assertIn('validation-serve', unit)
        self.assertIn('AmbientCapabilities=CAP_NET_BIND_SERVICE\n', unit)
        self.assertIn('CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n', unit)
        self.assertIn(str(self.config), unit)
        actions = self.root / 'actions'
        self.assertEqual(actions.read_text(), 'daemon-reload\nenable\nstart\n')
        refused = subprocess.run(['bash', str(SCRIPT), '--service-only', '--config', str(self.config),
                                  '--binary', str(self.binary)], input='', text=True,
                                 capture_output=True, timeout=180, env=env)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn('--allow-http', refused.stderr)
        self.assertEqual(actions.read_text(), 'daemon-reload\nenable\nstart\n')
        paths = [self.config, *(self.root / 'var/site').rglob('*')]
        before = {str(p): hashlib.sha256(p.read_bytes()).digest() for p in paths if p.is_file()}
        actions.unlink()
        # パスワード入力・再初期化なし。--startを省略すると起動しない。
        result = subprocess.run(['bash', str(SCRIPT), '--service-only', '--allow-http', '--config', str(self.config),
                                 '--binary', str(self.binary)], input='', text=True,
                                capture_output=True, timeout=180, env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(actions.read_text(), 'daemon-reload\nenable\n')
        self.assertEqual(before, {str(p): hashlib.sha256(p.read_bytes()).digest()
                                  for p in paths if p.is_file()})
        # 登録済みなら新しい設定・データを作る前に拒否する。
        self.config = self.root / 'refused.json'
        env['SERVICE_TEST_STATE'] = 'loaded'
        refused = self.invoke(['--allow-http', '--url', 'http://127.0.0.1', '--install-service', '--data-dir', 'refused-site'], env=env)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn('登録済み', refused.stderr)
        self.assertFalse(self.config.exists())
        self.assertFalse((self.root / 'refused-site').exists())


def stat_mode(path):
    """設定ファイルの許可ビットだけを取得する。"""
    return path.stat().st_mode & 0o777


if __name__ == '__main__':
    unittest.main()
