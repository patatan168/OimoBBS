#!/usr/bin/env python3
"""専用の一時volumeとloopbackで運用設定の保存・即時反映・再起動を検証する。"""
import argparse
import datetime
import html.parser
import http.cookiejar
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

class Fields(html.parser.HTMLParser):
    """ログインに必要なhidden値だけを取得する。"""
    def __init__(self, body):
        super().__init__(); self.values = {}; self.feed(body.decode())
    def handle_starttag(self, tag, attrs):
        row = dict(attrs)
        if tag == 'input' and row.get('type') == 'hidden':
            self.values[row['name']] = row.get('value', '')
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def main():
    """試験用の設定・認証情報は出力せず、専用コンテナとvolumeを終了時に除去する。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    output = Path(args.output); assert not output.exists()
    name = 'oimo-operations-' + uuid.uuid4().hex[:10]
    volume = name + '-data'
    def run(*command, data=None):
        return subprocess.run(command, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=120).stdout
    def port():
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0)); return sock.getsockname()[1]
    public_port, admin_port = port(), port()
    base = f'http://127.0.0.1:{admin_port}'
    secret = secrets.token_urlsafe(40)
    with tempfile.TemporaryDirectory(prefix='operations-docker-', dir='var') as temporary:
        folder = Path(temporary); folder.chmod(0o700)
        cert, key = folder / 'cert.pem', folder / 'key.pem'
        run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-keyout', str(key), '-out', str(cert), '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1')
        config = folder / 'config.json'
        settings = {'schema_version': 1, 'data_dir': '/data/site', 'public': {'listen': f'127.0.0.1:{public_port}', 'base_url': f'https://127.0.0.1:{public_port}', 'tls_cert_file': '/probe/cert.pem', 'tls_key_file': '/probe/key.pem'}, 'admin': {'listen': f'127.0.0.1:{admin_port}', 'transport': 'loopback_tunnel', 'origin': base}, 'trusted_proxies': [], 'cache_bytes': 268435456, 'egress_budget_bits_per_second': 80000000}
        settings.update(edge=None, auto_reports=None, maintenance=settings.get('maintenance'))
        config.write_text(json.dumps(settings));config.chmod(0o644)
        mounts = ['-v', volume + ':/data', '-v', str(folder.resolve()) + ':/probe:ro']
        run('docker', 'run', '--rm', '--network', 'none', '--user', '0:0', '-v', str(folder.resolve()) + ':/probe', '--entrypoint', '/bin/sh', args.image, '-c', 'chmod 755 /probe; chown 10001:10001 /probe/key.pem; chmod 600 /probe/key.pem')
        run('docker', 'volume', 'create', volume)
        def cli(*command, data=None):
            return run('docker', 'run', '--rm', '-i', '--network', 'none', '--read-only', *mounts, args.image, *command, '--config', '/probe/config.json', data=data)
        def start(admin=False):
            run('docker', 'run', '-d', '--name', name, '--network', 'host', '--read-only', '--cpus', '2', '--memory', '512m', '--memory-swap', '512m', '--pids-limit', '128', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', *mounts, args.image, 'validation-serve', '--config', '/probe/config.json', '--init-if-missing', '--board-key', 'probe', *(['--admin'] if admin else []))
            for _ in range(100):
                checked = subprocess.run(['docker', 'exec', name, 'oimobbs', 'healthcheck', '--config', '/probe/config.json'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if checked.returncode == 0: return
                time.sleep(.1)
            raise RuntimeError('isolated operations service did not start: '+run('docker','logs',name).decode()[-1000:])
        def stop():
            run('docker', 'stop', '-t', '60', name);run('docker', 'rm', name)
        try:
            start();stop()
            settings['auto_reports'] = {'board_key': 'probe', 'since': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')}
            config.write_text(json.dumps(settings))
            cli('admin', 'init', '--login', 'owner', '--password-stdin', data=(secret+'\n').encode())
            cli('pack', 'enable')
            start(admin=True)
            jar = http.cookiejar.CookieJar()
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(jar), NoRedirect())
            def request(path, data=None, headers=None):
                req = urllib.request.Request(base + path, data=data, headers=headers or {})
                if data is not None:req.add_header('Origin', base)
                try:response = opener.open(req, timeout=15)
                except urllib.error.HTTPError as error:response = error
                with response:return response.status, response.headers, response.read()
            def login():
                status, _, body = request('/login');assert status == 200
                fields = Fields(body).values;fields.update(login='owner', password=secret)
                status, _, _ = request('/login', urllib.parse.urlencode(fields).encode(), {'Content-Type': 'application/x-www-form-urlencoded'});assert status == 303
            def view():
                status, headers, body = request('/api/v1/operations');assert status == 200
                return headers, json.loads(body)['data']
            def save(value):
                headers, _ = view()
                prepared = {'Content-Type': 'application/json', 'If-Match': headers['ETag'], 'X-CSRF-Token': headers['X-CSRF-Token'], 'Idempotency-Key': uuid.uuid4().hex}
                raw = json.dumps(value).encode()
                status, _, body = request('/api/v1/operations', raw, prepared);assert status == 200
                status, _, _ = request('/api/v1/operations', raw, prepared);assert status == 200
                prepared['Idempotency-Key'] = uuid.uuid4().hex
                status, _, _ = request('/api/v1/operations', raw, prepared);assert status == 412
                return json.loads(body)['data']
            # 公開側は管理Cookieなしで専用証明書を検証し、設定変更前の案内を保持する。
            public_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=cert)))
            def public(path, headers=None):
                """公開案内の本文・検証子を取得し、管理の認証情報は送信しない。"""
                request = urllib.request.Request(settings['public']['base_url'] + path, headers={'Accept-Encoding': 'identity', **(headers or {})})
                try: response = public_opener.open(request, timeout=15)
                except urllib.error.HTTPError as error: response = error
                with response: return response.status, response.headers, response.read()
            paths = ['/probe/dat/1.dat', '/test/read.cgi/probe/1/']
            before = {path: public(path) for path in paths}
            for path, (status, _, body) in before.items():
                text = body.decode('cp932' if path.endswith('.dat') else 'utf-8')
                assert status == 200 and all(value in text for value in ['24時間以内', '3票', '10分停止'])
            def check_guides():
                """現在条件のHTML・DATと、置換後の全文取得・条件付き再検証を照合する。"""
                result = {}
                for path in paths:
                    status, headers, body = public(path, {'If-None-Match': before[path][1]['ETag']})
                    text = body.decode('cp932' if path.endswith('.dat') else 'utf-8')
                    assert status == 200 and headers['ETag'] != before[path][1]['ETag']
                    assert all(value in text for value in ['2時間以内', '2票', '15分停止'])
                    assert public(path, {'If-None-Match': headers['ETag']})[0] == 304
                    if path.endswith('.dat'):
                        for extra in [{'Range': 'bytes='+str(len(before[path][2]))+'-'}, {'Range': 'bytes=1-', 'If-Range': before[path][1]['ETag']}]:
                            partial_status, _, replacement = public(path, extra)
                            assert partial_status == 200 and replacement == body
                        partial_status, _, partial = public(path, {'Range': 'bytes=1-', 'If-Range': headers['ETag']})
                        assert partial_status == 206 and partial == body[1:]
                    result[path] = headers['ETag']
                return result
            login();_, initial = view();assert initial['settings']['reports']['quorum'] == 3
            value = initial['settings'];value.update(cache_bytes=2<<20, cache_workers=1, egress_budget_bits_per_second=40_000_000)
            value['maintenance'] = {'enabled': True, 'interval_seconds': 60, 'max_threads': 1, 'max_seconds': 2}
            value['reports'] = {'window_seconds': 7200, 'quorum': 2, 'stop_seconds': 900}
            save(value)
            guide_etags = check_guides()
            for _ in range(100):
                status, _, body = request('/api/v1/maintenance');state = json.loads(body)
                if state['data']['completed'] and not state['data']['running']: break
                time.sleep(.1)
            else:raise RuntimeError('maintenance setting did not wake disabled loop')
            assert state['data']['enabled'] and not state['data']['failed']
            assert state['delivery']['budget_bits_per_second'] == 40_000_000
            assert state['feed_compression']['workers'] == 1 and state['feed_compression']['limit_bytes'] == 2<<20
            status, _, page = request('/operations');assert status == 200 and '運用設定'.encode() in page
            stop();start(admin=True);jar.clear();login();_, restored = view();assert restored['settings'] == value
            assert check_guides() == guide_etags
            assert subprocess.check_output(['docker', 'inspect', name, '--format', '{{.State.OOMKilled}}'], text=True).strip() == 'false'
            result = {'image': args.image, 'cpu_limit': 2, 'memory_limit_bytes': 536870912, 'live_limits': True, 'maintenance_woke_from_disabled': True, 'persistent_settings': True, 'retry_and_cas': True, 'admin_html': True, 'public_guides_updated': True, 'public_guides_survived_restart': True, 'replacement_range_returns_full': True, 'settings': value}
            fd = os.open(output, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as file:json.dump(result, file, indent=2)
            print('PASS isolated Docker: live settings, disabled-to-enabled maintenance, CAS/retry, public guide refresh/ranges, restart')
        finally:
            subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['docker', 'volume', 'rm', volume], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
if __name__ == '__main__':main()
