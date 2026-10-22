"""復元検査が完了したオンラインコピーを暗号化し、元の期限で回収する。秘密鍵は使用しない。"""
import argparse
import fcntl
import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path


def seal_backups(container, image, source, output, destination=None):
    """Docker外で完成記録を照合し、秘密鍵を持たないhelperの暗号文だけを保存する。"""
    root = Path(output)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if root.is_symlink() or root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o777 != 0o700:
        raise ValueError('output must be owned 0700 directory')
    if destination and not re.fullmatch(r'[A-Za-z0-9_.-]+:/[A-Za-z0-9_./-]+', destination):
        raise ValueError('destination requires an SSH config alias and absolute directory')
    fd = os.open(root / '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        logs = subprocess.run(['docker', 'logs', '--since', '24h', '--tail', '10000', container], capture_output=True, check=True)
        for raw in (logs.stdout + logs.stderr).splitlines():
            try:
                entry = json.loads(raw)
            except (ValueError, UnicodeError):
                continue
            if not isinstance(entry, dict) or entry.get('status') != 'completed' or not entry.get('preparation', {}).get('complete'):
                continue
            name = entry.get('name', '')
            if not re.fullmatch(r'backup-[0-9a-f]{32}', name):
                continue
            expires = int(entry['preparation']['capture']['expires_at_ns'])
            if expires <= time.time_ns():
                continue
            target = root / (name + '.seal')
            manifest = root / (name + '.json')
            if not manifest.exists():
                temporary = root / (name + '.partial')
                temporary.unlink(missing_ok=True)
                # 名前は固定形式を検証済み。保存正本と復号秘密鍵はhelperへmountしない。
                script = f'set -eu; set -o pipefail; oimobbs backup verify-with-keys --input /backup/copies/{name} --keys /backup/keys/{name} >/dev/null; tar -cf - -C /backup copies/{name} keys/{name} pairs/{name}.json | oimoseal seal --key /backup/encryption/public.key --input - --output -'
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                try:
                    with os.fdopen(fd, 'wb') as encrypted:
                        subprocess.run(['docker', 'run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--entrypoint', '/bin/sh', '-v', str(Path(source).resolve()) + ':/backup:ro', image, '-c', script], stdout=encrypted, check=True, timeout=180)
                        encrypted.flush()
                        os.fsync(encrypted.fileno())
                    temporary.replace(target)
                finally:
                    temporary.unlink(missing_ok=True)
                with target.open('rb') as f:
                    digest = hashlib.file_digest(f, 'sha256').hexdigest()
                data = {'name': name, 'expires_at_ns': expires, 'sha256': digest, 'restore_ready': entry['preparation']['restore_ready']}
                fd = os.open(manifest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'w') as f:
                    json.dump(data, f)
                    f.flush()
                    os.fsync(f.fileno())
                print(json.dumps({'sealed_backup': name, 'restore_ready': data['restore_ready']}))
            if destination:
                subprocess.run(['scp', '-oBatchMode=yes', '-oStrictHostKeyChecking=yes', str(target), str(manifest), destination], check=True, timeout=180)
        for manifest in root.glob('backup-*.json'):
            if not re.fullmatch(r'backup-[0-9a-f]{32}\.json', manifest.name):
                continue
            data = json.loads(manifest.read_text())
            if int(data['expires_at_ns']) <= time.time_ns():
                manifest.with_suffix('.seal').unlink(missing_ok=True)
                manifest.unlink()
                print(json.dumps({'expired_sealed_backup_removed': manifest.stem}))


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--container', required=True)
    p.add_argument('--image', required=True)
    p.add_argument('--source', required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--destination', help='SSH設定alias:/absolute/directory（任意）')
    a = p.parse_args()
    seal_backups(a.container, a.image, a.source, a.output, a.destination)
