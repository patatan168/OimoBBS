#!/usr/bin/env python3
"""現行文書と合成fixtureを検査し、サーバ試験とは区別する。"""
import json
import os
from pathlib import Path
import re
import subprocess

from doclinks import check_links, documents

ROOT = Path(__file__).resolve().parents[2]
os.chdir(ROOT)
errors = []
markdown = documents(Path('.'))
required_docs = ('docs/README.md', 'docs/specification.md', 'docs/setup.md',
                 'docs/configuration.md', 'docs/operations.md',
                 'docs/architecture.md', 'docs/testing/README.md')
for name in required_docs:
    if not Path(name).is_file():
        errors.append(f'missing current document: {name}')
for path in markdown:
    text = path.read_text()
    if sum(line.startswith('```') for line in text.splitlines()) % 2:
        errors.append(f'{path}: unclosed code fence')

link_count, link_errors = check_links(markdown)
errors.extend(link_errors)


def strict_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'duplicate JSON key {key}')
        result[key] = value
    return result


json_files = sorted(Path('docs').rglob('*.json')) + sorted(Path('.').glob('config*.example.json'))
for path in json_files:
    try:
        json.loads(path.read_text(), object_pairs_hook=strict_pairs)
    except (ValueError, UnicodeError) as exc:
        errors.append(f'{path}: {exc}')
for path in markdown:
    for match in re.finditer(r'```json\s*\n(.*?)\n```', path.read_text(), re.S):
        try:
            json.loads(match[1], object_pairs_hook=strict_pairs)
        except ValueError as exc:
            errors.append(f'{path}: embedded JSON: {exc}')


if errors:
    raise SystemExit('\n'.join(errors))
print(f'PASS: {len(markdown)} Markdown files, {len(json_files)} JSON files, '
      f'current documents, {link_count} local links including headings, fences and strict JSON', flush=True)
env = dict(os.environ, GOTOOLCHAIN='local')
for name in ('wal', 'pack', 'contracts'):
    subprocess.run(['go', 'run', f'tools/designcheck/{name}/main.go'], env=env, check=True)
print('PASS: design checks only; application, crash, device and load tests NOT RUN')
