#!/usr/bin/env python3
"""プロジェクト文書の相対リンクと見出しへのリンクを、外部通信なしで検査する。"""
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
import re
import unicodedata
from urllib.parse import unquote, urlsplit

REPOSITORY = "patatan168/OimoBBS"
REPOSITORY_URL = "https://github.com/" + REPOSITORY
PROJECT_ROOT = Path(__file__).resolve().parents[2]


class HTMLReferences(HTMLParser):
    """Markdown内の明示アンカーとHTMLリンクを収集する。"""

    def __init__(self):
        super().__init__()
        self.ids = set()
        self.links = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if attrs.get('id'):
            self.ids.add(attrs['id'])
        if tag == 'a' and attrs.get('name'):
            self.ids.add(attrs['name'])
        if tag == 'a' and attrs.get('href'):
            self.links.append(attrs['href'])


def prose(text):
    """コードフェンス内を空行に置き換え、リンクの行番号を維持する。"""
    fence = None
    lines = []
    for line in text.splitlines():
        marker = re.match(r'^\s{0,3}(`{3,}|~{3,})', line)
        if marker:
            token = marker[1]
            if fence is None:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence):
                fence = None
            lines.append('')
        else:
            lines.append(line if fence is None else '')
    return '\n'.join(lines)


def heading_ids(text):
    """見出しをGitHub形式のIDへ変換し、同名見出しには出現順の番号を付ける。"""
    ids = set()
    for line in prose(text).splitlines():
        match = re.match(r'^ {0,3}#{1,6}\s+(.+?)\s*#*\s*$', line)
        if not match:
            continue
        title = re.sub(r'!?\[([^]]+)\]\([^)]+\)', r'\1', match[1])
        title = unescape(re.sub(r'<[^>]+>', '', title)).lower()
        slug = ''.join(c for c in title if c in ' -_' or unicodedata.category(c)[0] in 'LMN').replace(' ', '-')
        candidate, number = slug, 0
        while candidate in ids:
            number += 1
            candidate = f'{slug}-{number}'
        ids.add(candidate)
    html = HTMLReferences()
    html.feed(prose(text))
    return ids | html.ids


def local_links(text):
    """本文のMarkdownリンクとHTMLリンクを行番号付きで返す。コード例は検査しない。"""
    for number, line in enumerate(prose(text).splitlines(), 1):
        line = re.sub(r'(`+).*?\1', '', line)
        for match in re.finditer(r'!?\[[^]\n]*\]\((?:<([^>]+)>|([^\s)]+))(?:\s+"[^"]*")?\)', line):
            yield number, match[1] or match[2]
        html = HTMLReferences()
        html.feed(line)
        for target in html.links:
            yield number, target


def repository_destination(url, root):
    """同一リポジトリのmainを指すGitHub絶対URLを、ローカルの保存先へ対応付ける。"""
    if url.netloc.lower() != 'github.com':
        return None
    for kind in ('blob', 'tree'):
        prefix = f'/{REPOSITORY}/{kind}/main/'
        if url.path.startswith(prefix):
            return root / unquote(url.path[len(prefix):])
    return None


def security_policy(root):
    """GitHubが自動表示するポリシーを優先ディレクトリ順に選ぶ。"""
    for directory in (root / '.github', root, root / 'docs'):
        for path in sorted(directory.glob('*.md')):
            if path.name.lower() == 'security.md':
                return path.resolve()
    return None


def check_links(paths, root=PROJECT_ROOT):
    """相対リンク・同一リポジトリURL・見出しと、Security policyの表示条件を検査する。"""
    errors, count = [], 0
    anchors = {}
    policy = security_policy(root)
    for path in paths:
        for number, target in local_links(path.read_text()):
            url = urlsplit(target)
            destination = repository_destination(url, root)
            if destination is None:
                if url.scheme or url.netloc:
                    continue
                destination = path.parent / unquote(url.path) if url.path else path
                # GitHubのSecurity policyでは、文書の親ディレクトリと解決基準が異なる。
                if url.path and path.resolve() == policy and destination.resolve() != (root / unquote(url.path)).resolve():
                    errors.append(f'{path}:{number}: Security policy resolves this relative link from the repository root: {target}')
            count += 1
            if not destination.exists():
                errors.append(f'{path}:{number}: missing link {target}')
                continue
            if url.fragment and destination.suffix.lower() == '.md':
                destination = destination.resolve()
                if destination not in anchors:
                    anchors[destination] = heading_ids(destination.read_text())
                if unquote(url.fragment) not in anchors[destination]:
                    errors.append(f'{path}:{number}: missing heading {target}')
    return count, errors


def documents(root):
    """実行データや退避ファイルを除き、同梱する説明文書を選ぶ。"""
    return sorted(root.glob('*.md')) + sorted(path for directory in ('.github', 'docs', 'deploy', 'tools', 'third_party') for path in (root / directory).rglob('*.md'))
