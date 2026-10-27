#!/usr/bin/env python3
"""固定されたGo moduleの著作権表示を配布用の単一ファイルへ収集する。"""
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def collect():
    """Goの検証済みmoduleキャッシュから原文を読み、版ごとにまとめる。"""
    pins = json.loads((ROOT / 'scripts/go-dependencies.json').read_text())
    sections = ['OimoBBS Go module licenses and notices\n']
    for module, version in sorted(pins.items()):
        info = json.loads(subprocess.check_output(['go', 'mod', 'download', '-json', module + '@' + version], cwd=ROOT))
        directory = Path(info['Dir'])
        files = sorted(path for path in directory.iterdir() if path.is_file() and path.name.lower().startswith(('license', 'copying', 'notice')))
        if not files:
            raise SystemExit(f'著作権表示が見つかりません: {module}@{version}')
        for path in files:
            sections.append(f'\n=== {module}@{version} / {path.name} ===\n\n' + path.read_text())
    target = ROOT / 'third_party/go-modules/NOTICES.txt'
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text('\n'.join(sections))


if __name__ == '__main__':
    collect()
