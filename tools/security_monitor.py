"""Docker外へ固定項目だけの認証記録を保存し、失敗・過負荷をローカルjournalへ通知する。"""
import argparse
import fcntl
import datetime
import json
import os
import subprocess
from pathlib import Path


def monitor(container, output):
    """秘密を含む元ログは保存しない。時間cursorは正常保存後だけ進める。"""
    root = Path(output)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if root.is_symlink() or root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o777 != 0o700:
        raise ValueError('monitor output must be owned 0700 directory')
    fd = os.open(root / '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        collect(container, root)


def collect(container, root):
    """専用排他の下で読み、保存後だけcursorを進める。"""
    cursor = root / 'cursor.txt'
    since = cursor.read_text().strip() if cursor.exists() else '10m'
    until = datetime.datetime.now(datetime.timezone.utc).isoformat()
    result = subprocess.run(['docker', 'logs', '--since', since, '--until', until, '--tail', '10000', container], capture_output=True, check=True)
    records = []
    for line in (result.stdout + result.stderr).splitlines():
        if len(line) > 4096:
            continue
        try:
            entry = json.loads(line)
        except (ValueError, UnicodeError):
            continue
        if not isinstance(entry, dict) or entry.get('msg') not in ('security_auth', 'security_auth_summary'):
            continue
        records.append({k: entry[k] for k in ('time', 'msg', 'action', 'outcome', 'source_id', 'account_id', 'result', 'suppressed') if k in entry})
    log = root / 'authentication.jsonl'
    if log.exists() and log.stat().st_size > 8 << 20:
        for n in range(3, 0, -1):
            source = root / ('authentication.jsonl' if n == 1 else f'authentication.jsonl.{n-1}')
            if source.exists():
                source.replace(root / f'authentication.jsonl.{n}')
    fd = os.open(log, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as f:
        for entry in records:
            f.write(json.dumps(entry, separators=(',', ':')) + '\n')
        f.flush()
        os.fsync(f.fileno())
    failures = sum(v.get('outcome') == 'failed' for v in records)
    limited = sum(v.get('outcome') in ('limited', 'busy', 'error') or v.get('msg') == 'security_auth_summary' for v in records)
    if failures >= 5 or limited:
        print(json.dumps({'alert': 'administrator_authentication', 'failed': failures, 'limited_busy_error': limited}), flush=True)
    temporary = root / 'cursor.next'
    temporary.unlink(missing_ok=True)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(until)
        f.flush()
        os.fsync(f.fileno())
    temporary.replace(cursor)
    print(json.dumps({'authentication_records_saved': len(records)}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--container', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    monitor(args.container, args.output)
