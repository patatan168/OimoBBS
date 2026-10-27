#!/usr/bin/env python3
"""隔離コピーでGoと依存を更新・検証し、成功した設定差分だけを作業ツリーへ戻す。"""
import argparse
import difflib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
PIN_FILES = [
    'go.mod', 'mise.toml', 'Dockerfile', 'scripts/setup.sh', 'scripts/check.sh',
    'scripts/check-security-continuous.sh', 'README.md', 'docs/setup.md',
    'docs/specification.md', 'docs/operations.md', 'docs/testing/README.md', 'docs/testing/performance.md',
    'tools/designcheck/README.md',
]
OUTPUT_FILES = PIN_FILES + ['go.sum', 'scripts/go-dependencies.json', 'third_party/go-modules/NOTICES.txt']


def run(args, cwd, **kwargs):
    """失敗時は中断し、作業ツリーへの反映を防ぐ。"""
    return subprocess.run(args, cwd=cwd, check=True, **kwargs)


def latest_go():
    """公式配布一覧から安定版を選び、実行コードをダウンロードせず版だけを取得する。"""
    with urllib.request.urlopen('https://go.dev/dl/?mode=json', timeout=30) as response:
        versions = json.load(response)
    return next(row['version'].removeprefix('go') for row in versions if row['stable'])


def pin_go(work, version):
    """現在の固定版を運用スクリプト・コンテナ・説明文でも同じ版へ揃える。"""
    old = re.search(r'^go (\S+)$', (work / 'go.mod').read_text(), re.M).group(1)
    for name in PIN_FILES:
        path = work / name
        path.write_text(path.read_text().replace(old, version))
    # go getが追加するtoolchain指定はmiseとgo directiveに一本化する。
    run(['mise', 'exec', '--', 'go', 'mod', 'edit', '-go=' + version, '-toolchain=none'], work)


def stage_sources(work):
    """Git管理下と未追跡のソースをコピーし、Gitで無視した稼働データとGit履歴は持ち込まない。"""
    result = run(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], ROOT, stdout=subprocess.PIPE)
    for name in set(os.fsdecode(result.stdout).split('\0')) - {''}:
        src = ROOT / name
        if not src.is_file() or src.is_symlink():
            continue
        dest = work / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)


def main(argv=None):
    """既定は差分表示だけ。--apply時も隔離検証が成功するまで元ファイルへ書かない。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', default='latest', help='Goの安定版番号、latest、またはcurrent')
    parser.add_argument('--modules', choices=['patch', 'minor', 'none'], default='minor')
    parser.add_argument('--full-checks', action='store_true', help='時間のかかる全件・race・fuzz検証も実行する')
    parser.add_argument('--apply', action='store_true', help='検証成功後に設定差分を反映する')
    parser.add_argument('--skip-checks', action='store_true', help='検証を省略する（差分の確認専用、--apply併用不可）')
    args = parser.parse_args(argv)
    if args.full_checks and args.skip_checks:
        parser.error('--full-checksと--skip-checksは併用できません')
    if args.apply and args.skip_checks:
        parser.error('--applyには検証が必要です')
    version = args.go
    if version == 'latest':
        version = latest_go()
    elif version == 'current':
        version = re.search(r'^go (\S+)$', (ROOT / 'go.mod').read_text(), re.M).group(1)
    if not re.fullmatch(r'1\.\d+\.\d+', version):
        parser.error('--goは1.x.y形式で指定してください')
    before = {name: (ROOT / name).read_bytes() for name in OUTPUT_FILES}
    with tempfile.TemporaryDirectory(prefix='oimobbs-update-') as temporary:
        work = Path(temporary)
        stage_sources(work)
        # miseの設定を先に変更してから対象Goを導入する。
        config = work / 'mise.toml'
        config.write_text(re.sub(r'go = "[^"]+"', f'go = "{version}"', config.read_text()))
        run(['mise', 'trust', str(config)], work)
        run(['mise', 'install', 'go@' + version], work)
        pin_go(work, version)
        go = ['mise', 'exec', '--', 'go']
        if args.modules != 'none':
            run(go + ['get', '-u=patch' if args.modules == 'patch' else '-u', './cmd/...', './internal/...', './tools/...'], work)
        run(go + ['mod', 'tidy'], work)
        module = json.loads(run(go + ['mod', 'edit', '-json'], work, stdout=subprocess.PIPE).stdout)
        resolved = module['Go']
        if tuple(map(int, resolved.split('.'))) > tuple(map(int, version.split('.'))):
            raise SystemExit(f'依存がGo{resolved}を要求しています。--go {resolved}でやり直してください。')
        run(go + ['mod', 'edit', '-toolchain=none'], work)
        lock = {row['Path']: row['Version'] for row in module.get('Require', [])}
        (work / 'scripts/go-dependencies.json').write_text(json.dumps(lock, indent=2, sort_keys=True) + '\n')
        run(['mise', 'exec', '--', 'python3', '-B', 'scripts/collect-go-licenses.py'], work)
        after = {name: (work / name).read_bytes() for name in OUTPUT_FILES}
        changed = [name for name in OUTPUT_FILES if before[name] != after[name]]
        if not changed and not args.full_checks:
            print('更新対象はありません。検証を省略しました。')
            return
        if not args.skip_checks:
            check = 'scripts/check.sh' if args.full_checks else 'scripts/check-update.sh'
            print('全検証を実行します。' if args.full_checks else '通常の更新検証を実行します（全件・race・fuzzは--full-checks）。', flush=True)
            run(['mise', 'exec', '--', 'bash', check], work)
        for name in changed:
            print(''.join(difflib.unified_diff(before[name].decode().splitlines(True), after[name].decode().splitlines(True), fromfile='a/' + name, tofile='b/' + name)), end='')
        if args.apply:
            if any((ROOT / name).read_bytes() != before[name] for name in OUTPUT_FILES):
                raise SystemExit('処理中に元ファイルが変更されました。反映せず終了します。')
            for name in changed:
                (ROOT / name).write_bytes(after[name])
            print('検証した設定差分を反映しました。ビルド・稼働反映は運用手順で行ってください。')
        else:
            print('作業ツリーは変更していません。反映には--applyを指定してください。')


if __name__ == '__main__':
    main()
