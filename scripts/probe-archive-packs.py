#!/usr/bin/env python3
"""隔離Dockerへ上限1000件を実投稿し、旧gzip候補・新pack・独立復号・再起動・自動整理を検証する。"""
import argparse
import http.client
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import tempfile
import threading
import time
import uuid


def module(path, name):
    """同じ検証用クライアントを再利用し、実サービスのURLは受け取らない。"""
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--posts', type=int, default=1000)
    parser.add_argument('--old-image', required=True)
    parser.add_argument('--save-pack', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    if not 1 <= args.posts <= 1000:
        raise ValueError("posts must be 1..1000")
    root = Path(__file__).resolve().parent.parent
    saved, output = Path(args.save_pack), Path(args.output)
    if saved.exists() or output.exists():
        raise RuntimeError('output already exists')
    probe_module = module(root / 'scripts/probe-thread-resources.py', 'archive_resource_probe')
    decoder = module(root / 'scripts/codec_probe_decode.py', 'archive_independent_decoder')
    command = probe_module.command
    image = command('docker', 'image', 'inspect', args.image, '--format', '{{.Id}}')
    old_image = command('docker', 'image', 'inspect', args.old_image, '--format', '{{.Id}}')
    assert image != old_image
    name = 'oimobbs-archive-probe-' + uuid.uuid4().hex[:10]
    probe = None
    with tempfile.TemporaryDirectory(prefix='archive-probe-', dir=root / 'var') as temporary:
        folder = Path(temporary)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        cert, key = folder / 'cert.pem', folder / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-keyout', str(key), '-out', str(cert), '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        config = folder / 'config.json'
        settings = {'schema_version': 1, 'data_dir': '/data/site', 'public': {'listen': f'127.0.0.1:{port}', 'base_url': f'https://127.0.0.1:{port}', 'tls_cert_file': '/tls/cert.pem', 'tls_key_file': '/tls/key.pem'}, 'admin': {'listen': '127.0.0.1:19082', 'transport': 'loopback_tunnel', 'origin': 'http://127.0.0.1:19082'}, 'trusted_proxies': [], 'egress_budget_bits_per_second': 80000000}
        settings.update(edge=None, auto_reports=None, maintenance=settings.get('maintenance'))
        config.write_text(json.dumps(settings))
        for file in (config, cert, key):
            file.chmod(0o644)
        command('docker', 'run', '--rm', '--network', 'none', '--user', '0:0', '-v', f'{folder}:/probe', '--entrypoint', '/bin/sh', image, '-c', 'chown 10001:10001 /probe/key.pem; chmod 600 /probe/key.pem')
        mounts = ['-v', f'{name}-data:/data', '-v', f'{config}:/etc/oimobbs/config.json:ro', '-v', f'{cert}:/tls/cert.pem:ro', '-v', f'{key}:/tls/key.pem:ro']
        def cli(selected, *arguments, input_bytes=None, expect_success=True):
            """停止中だけCLIを実行し、秘密や本文を診断出力へ流さない。"""
            result = subprocess.run(['docker', 'run', '--rm', '-i', '--network', 'none', '--read-only', '--cpus', '2', '--memory', '512m', '--memory-swap', '512m', *mounts, selected, *arguments, '--config', '/etc/oimobbs/config.json'], input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if expect_success and result.returncode:
                raise RuntimeError('isolated archive CLI failed: ' + result.stderr.decode()[:500])
            return result
        try:
            command('docker', 'run', '-d', '--name', name, '--network', 'host', '--read-only', '--cpus', '2', '--memory', '512m', '--memory-swap', '512m', '--pids-limit', '128', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--tmpfs', '/tmp:uid=10001,gid=10001,mode=0700', *mounts, image, 'validation-serve', '--config', '/etc/oimobbs/config.json', '--init-if-missing', '--board-key', 'probe')
            pid = command('docker', 'inspect', name, '--format', '{{.State.Pid}}')
            group = Path('/sys/fs/cgroup') / Path(f'/proc/{pid}/cgroup').read_text().split('::', 1)[1].strip().lstrip('/')
            probe = probe_module.Probe(port, cert, group)
            def ready():
                for _ in range(900):
                    try:
                        if probe.request('GET', '/')[0] == 200:
                            return
                    except (OSError, http.client.HTTPException):
                        probe.local = threading.local()
                    time.sleep(.1)
                diagnostic = command('docker', 'logs', name)
                raise RuntimeError('archive server readiness timeout: ' + diagnostic[-2000:])
            ready()
            thread = ''
            for number in range(1, args.posts+1):
                thread, _ = probe.post(number, thread, namespace='archive-actual-probe')
            path = f'/probe/dat/{thread}.dat'
            status, headers, raw, _ = probe.request('GET', path, headers={'Accept-Encoding': 'identity'})
            assert status == 200 and raw.count(b'\n') == args.posts + (1 if args.posts == 1000 else 0)
            before_etag = headers['etag']
            board = command('docker', 'exec', name, '/bin/sh', '-c', 'ls /data/site/boards').strip()
            assert len(board) == 32 and all(c in '0123456789abcdef' for c in board)
            probe.stop.set(); probe.monitor.join(); probe.local.connection.close()
            command('docker', 'stop', '-t', '60', name)
            assert command('docker', 'inspect', name, '--format', '{{.State.OOMKilled}}') == 'false'
            cli(old_image, 'admin', 'init', '--login', 'archive-probe', '--password-stdin', input_bytes=(secrets.token_urlsafe(40)+'\n').encode())
            enabled_old = json.loads(cli(old_image, 'pack', 'enable').stdout)
            assert enabled_old['minimum_reader_version'] < 68
            old_preview = json.loads(cli(old_image, 'pack', 'compact', '--board', board, '--thread', thread, '--level', '9').stdout)
            enabled = json.loads(cli(image, 'pack', 'enable').stdout)
            assert enabled['minimum_reader_version'] == 68 and enabled['audit_complete']
            new_pack = json.loads(cli(image, 'pack', 'compact', '--board', board, '--thread', thread, '--level', '9', '--apply').stdout)
            assert new_pack['applied']
            directory = f'/data/site/boards/{board}/threads/{thread}'
            current = folder / 'current.json'
            command('docker', 'cp', f'{name}:{directory}/current.json', str(current))
            manifest = json.loads(current.read_text())['manifest']
            command('docker', 'cp', f"{name}:{directory}/{manifest['base']['file']}", str(saved))
            saved.chmod(0o600)
            packed = saved.read_bytes()
            assert len(packed) == new_pack['pack_bytes'] and packed[:8] == b'OIMOPAK1'
            # indexは仕様上の絶対位置。ホストlibzstdでも各保存blockを独立復号する。
            index_at = struct.unpack_from('<Q', packed, 120)[0]
            blocks = struct.unpack_from('<I', packed, 84)[0]
            for i in range(blocks):
                at = index_at + 96*i
                offset, stored, size = struct.unpack_from('<QII', packed, at+24)
                assert packed[at+40] == 2 and len(decoder.decode('zstd', packed[offset:offset+stored])) == size
            audit_at, audit_size = struct.unpack_from('<QQ', packed, 168)
            audit = packed[audit_at:audit_at+audit_size]
            at = 32
            for _ in range(struct.unpack_from('<I', audit, 24)[0]):
                size, stored = struct.unpack_from('<II', audit, at+4)
                assert audit[at+12] == 2 and len(decoder.decode('zstd', audit[at+24:at+24+stored])) == size
                at += 24+stored
            assert at == len(audit)
            refused = cli(old_image, 'pack', 'maintain', expect_success=False)
            assert refused.returncode and b'unsupported reader version' in refused.stderr
            settings['maintenance'] = {'enabled': True, 'max_seconds': 5, 'interval_seconds': 300, 'max_threads': 5}
            config.write_text(json.dumps(settings))
            command('docker', 'start', name)
            probe.local = threading.local(); ready()
            for coding in ['identity', 'gzip', 'zstd']:
                status, h, body, _ = probe.request('GET', path, headers={'Accept-Encoding': coding})
                decoded = body if coding == 'identity' else decoder.decode(coding, body)
                assert status == 200 and decoded == raw
            status, _, body, _ = probe.request('GET', path, headers={'If-None-Match': before_etag, 'Accept-Encoding': 'identity'})
            assert status == 304 and not body
            status, _, body, _ = probe.request('GET', path, headers={'Range': f'bytes={len(raw)-1}-', 'Accept-Encoding': 'zstd,gzip'})
            assert status == 206 and body == raw[-1:]
            new_thread, _ = probe.post(1, namespace='archive-after-restart')
            _, _ = probe.post(2, new_thread, namespace='archive-after-restart')
            probe.local.connection.close(); command('docker', 'stop', '-t', '60', name)
            assert command('docker', 'inspect', name, '--format', '{{.State.OOMKilled}}') == 'false'
            repeated = json.loads(cli(image, 'pack', 'maintain', '--limit', '5').stdout)
            entry = next(r for r in repeated['entries'] if str(r['thread']) == thread)
            assert not entry['decision']['compact']
            result = {'image': image, 'old_image': old_image, 'cpu_limit': 2, 'memory_limit_bytes': 536870912, 'user_posts': args.posts, 'dat_lines': raw.count(b'\n'), 'dat_bytes': len(raw), 'old_gzip_pack_bytes': old_preview['pack_bytes'], 'zstd_pack_bytes': new_pack['pack_bytes'], 'zstd_body_blocks': blocks, 'independent_libzstd_decode': True, 'restart_content_range_etag': True, 'post_restart_posts': 2, 'automatic_maintenance_started': True, 'unchanged_archive_not_repacked': True, 'old_reader_refused': True, 'saved_pack': str(saved), 'sha256': hashlib.sha256(packed).hexdigest()}
            fd = os.open(output, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as file:
                json.dump(result, file, indent=2)
            print('PASS actual archive, independent decoder, restart, old reader refusal; sizes', old_preview['pack_bytes'], new_pack['pack_bytes'])
        finally:
            if probe:
                probe.stop.set(); probe.monitor.join()
            subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['docker', 'volume', 'rm', name+'-data'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
