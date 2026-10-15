#!/usr/bin/env python3
"""localhostのDocker管理画面へログインし、設定・規制・監査の閲覧を検査する。"""
import argparse
import html.parser
import http.cookiejar
import json
import os
from pathlib import Path
import stat
import urllib.error
import urllib.parse
import urllib.request


class Fields(html.parser.HTMLParser):
    """ログインフォームのhidden値だけを読む。"""
    def __init__(self, page):
        super().__init__()
        self.values = {}
        self.feed(page)

    def handle_starttag(self, tag, attrs):
        row = dict(attrs)
        if tag == 'input' and row.get('type') == 'hidden':
            self.values[row['name']] = row.get('value', '')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--credentials', default='var/credentials/admin-login.txt')
args = parser.parse_args()
path = Path(args.credentials)
info = path.lstat()
assert stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.geteuid(), 'credentials must be a private regular file'
credentials = dict(line.split(': ', 1) for line in path.read_text().splitlines()
                   if line.strip() and not line.lstrip().startswith('#'))
base = 'http://127.0.0.1:9081'
assert credentials['URL'].rstrip('/') == base
secret = credentials['Password']
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(jar), NoRedirect())


def request(route, fields=None, headers=None):
    """認証情報を固定localhostにのみ送信し、本文・Cookie・秘密は表示しない。"""
    data = None if fields is None else urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(base + route, data=data, headers=headers or {})
    if fields is not None:
        req.add_header('Origin', base)
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
    try:
        res = opener.open(req, timeout=15)
    except urllib.error.HTTPError as error:
        res = error
    with res:
        body = res.read()
        assert secret.encode() not in body, 'credential exposed'
        assert res.headers.get('Cache-Control') == 'no-store', 'admin response is cacheable'
        return res.status, body


status, _ = request('/api/v1/audit')
assert status == 401, 'unauthenticated audit accepted'
status, page = request('/login')
assert status == 200
fields = Fields(page.decode()).values
fields.update(login=credentials['Login'], password=secret)
status, _ = request('/login', fields)
assert status == 303, 'login failed'
checks = ['login', 'unauthenticated rejection']
for route in ['/', '/boards', '/api/v1/site', '/audit', '/api/v1/audit', '/networks', '/api/v1/networks']:
    status, _ = request(route)
    assert status == 200, ('admin route failed', route, status)
    checks.append(route)
status, body = request('/networks')
assert status == 200
for label in ['管理用の説明', 'name="description"', 'カテゴリーを削除', 'ワッチョイ表示の元の意味を確認する', '無料の日本・VPNデータを追加して更新', '国・VPNの誤判定を修正する']:
    assert label in body.decode(), 'network category UI missing'
status, body = request('/api/v1/networks')
assert status == 200
network = json.loads(body)['data']
assert isinstance(network['config']['categories'], list), 'category list missing'
for key in ['japan_count', 'vpn4_count', 'vpn6_count']:
    assert isinstance(network[key], int), 'access feed counts missing'
checks.append('network category description/edit/delete UI')
if not network['config']['sources']:
    status, page = request('/networks')
    assert status == 200 and '無料の標準データで更新を開始' in page.decode(), 'standard data onboarding missing'
    checks.append('free standard source onboarding')
status, body = request('/api/v1/boards')
assert status == 200
boards = json.loads(body)['data']
for board in boards:
    for prefix in ['/boards/', '/api/v1/boards/']:
        for suffix in ['/settings', '/thread-settings', '/local-rules', '/rules']:
            route = prefix + board['id'] + suffix
            status, _ = request(route)
            assert status == 200, ('board admin route failed', suffix, status)
status, _ = request('/login', headers={'Host': 'patatanmc.f5.si'})
assert status == 403, 'foreign Host accepted'
print(json.dumps({'status': 'PASS', 'checks': checks + ['board settings', 'thread settings', 'local rules', 'denial rules', 'Host rejection'], 'boards': len(boards)}, ensure_ascii=False))
