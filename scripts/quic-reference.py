#!/usr/bin/env python3
"""製品依存を変更せず、一時module内だけで既存QUIC実装との相互接続・比較を行う。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / 'tools/quicreference/fixtures'
PINS = json.loads((ROOT / 'tools/quicreference/dependencies.json').read_text())


def go_binary():
    """信頼済みの元projectから固定Goを解決し、一時configの再承認を不要にする。"""
    return subprocess.check_output(['mise', 'which', 'go'], cwd=ROOT, text=True).strip()


def snapshot(target):
    """Git管理対象と未ignoreの変更だけを複写し、稼働データ・秘密設定・varを持ち込まない。"""
    paths = subprocess.check_output(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=ROOT).split(b'\0')
    hashes = {}
    for raw in sorted(set(paths)):
        if not raw:
            continue
        relative = Path(os.fsdecode(raw))
        source = ROOT / relative
        if relative.parts[0] in ['var', '.git'] or not source.is_file():
            continue
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        if source.suffix == '.go' and not source.name.endswith('_test.go'):
            hashes[str(relative)] = hashlib.sha256(source.read_bytes()).hexdigest()
    generated = ROOT / 'internal/webui/generated'
    if generated.is_dir():
        shutil.copytree(generated, target / 'internal/webui/generated', dirs_exist_ok=True)
    return hashes


def reference_files(target):
    """外部clientを使う試験と比較専用backendを一時moduleだけに追加し、製品fileを上書きしない。"""
    for source in FIXTURES.rglob('*.go.txt'):
        destination = target / str(source.relative_to(FIXTURES)).removesuffix('.txt')
        if destination.exists():
            raise RuntimeError(f'reference fixture would replace product source: {destination}')
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def run_go(binary, args, directory, **options):
    """全Go操作を複写先のmoduleで実行し、元のgo.modとgo.sumを変えない。"""
    return subprocess.run([binary, *args], cwd=directory, check=True, **options)


def main():
    """検証tool生成、参照client試験、製品依存の整理を明示的なsubcommandで分ける。"""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    build = commands.add_parser('build-benchmark')
    build.add_argument('--output', required=True)
    test = commands.add_parser('test')
    test.add_argument('go_args', nargs=argparse.REMAINDER)
    commands.add_parser('tidy-product')
    args = parser.parse_args()
    binary = go_binary()
    (ROOT / 'var').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='quic-reference-', dir=ROOT / 'var') as temporary:
        directory = Path(temporary)
        hashes = snapshot(directory)
        if args.command == 'tidy-product':
            for module in PINS:
                run_go(binary, ['mod', 'edit', '-droprequire=' + module], directory)
            run_go(binary, ['mod', 'tidy'], directory)
            modules = subprocess.check_output([binary, 'list', '-m', 'all'], cwd=directory, text=True)
            if any(module in modules for module in PINS):
                raise RuntimeError('product still depends on the reference QUIC libraries')
            for name in ['go.mod', 'go.sum']:
                (ROOT / name).write_bytes((directory / name).read_bytes())
            return
        reference_files(directory)
        for module, version in PINS.items():
            run_go(binary, ['mod', 'edit', '-require=' + module + '@' + version], directory)
        if args.command == 'test':
            go_args = args.go_args
            if go_args and go_args[0] == '--':
                go_args = go_args[1:]
            if not go_args:
                parser.error('test requires explicit Go test arguments')
            run_go(binary, ['test', '-mod=mod', *go_args], directory)
            return
        output = Path(args.output).resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        run_go(binary, ['build', '-mod=mod', '-buildvcs=false', '-trimpath', '-o', str(output), './tools/httptransportbench'], directory, env={**os.environ, 'CGO_ENABLED': '0'})
        versions = {}
        for module, expected in PINS.items():
            actual = subprocess.check_output([binary, 'list', '-m', '-f', '{{.Version}}', module], cwd=directory, text=True).strip()
            if actual != expected:
                raise RuntimeError(f'reference dependency changed: {module} {actual} != {expected}')
            versions[module] = actual
        metadata = {'scope': 'reference benchmark only; not product dependencies', 'reference_versions': versions,
                    'product_source_sha256': hashes,
                    'fixture_sha256': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in FIXTURES.rglob('*.go.txt')},
                    'binary_sha256': hashlib.sha256(output.read_bytes()).hexdigest()}
        output.with_suffix('.reference.json').write_text(json.dumps(metadata, indent=2) + '\n')


if __name__ == '__main__':
    main()
