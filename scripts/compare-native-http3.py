#!/usr/bin/env python3
"""隔離Docker上の既存版と独自版をaioquic/LS-QPACKで比較する。WAN・稼働volumeは使わない。"""
import argparse
import hashlib
import platform
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent


def run(args, **kwargs):
    """失敗の終了コードを保持し、全操作をrepository内で実行する。"""
    return subprocess.run(args, cwd=ROOT, check=True, text=True, **kwargs)


def main():
    """同じ短命サーバーに同じ合成要求を送り、失敗の出力も保存する。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', default='var/native-quic-independent')
    parser.add_argument('--requests', type=int, default=1000)
    parser.add_argument('--rounds', type=int, default=3)
    parser.add_argument('--python', default=sys.executable)
    parser.add_argument('--all-ciphers', action='store_true')
    parser.add_argument('--key-update', action='store_true')
    args = parser.parse_args()
    if args.requests < 1 or args.rounds < 1:
        parser.error('requestsとroundsは正の数で指定してください')
    output = (ROOT / args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    binary = output / 'httptransportbench'
    run(['python3', 'scripts/quic-reference.py', 'build-benchmark', '--output', str(binary)])
    environment = {'scope': 'isolated Docker server, host Python client; UDP payload and QPACK counters; no WAN', 'server_cpus': 2, 'server_memory_bytes': 512*1024*1024, 'requests': args.requests, 'rounds': args.rounds, 'key_update': args.key_update, 'host': platform.platform(), 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'go_version': run(['mise', 'exec', '--', 'go', 'version'], capture_output=True).stdout.strip()}
    sources = ['go.mod', 'go.sum', 'tools/quicreference/fixtures/tools/httptransportbench/reference_main.go.txt', 'scripts/compare-native-http3.py', 'scripts/probe-native-http3.py', 'internal/httptransport/http3.go', 'internal/httptransport/http3_lifecycle.go']
    sources += [str(p.relative_to(ROOT)) for folder in ['internal/quicv1', 'internal/http3native'] for p in sorted((ROOT/folder).glob('*.go')) if not p.name.endswith('_test.go')]
    environment['source_sha256'] = {p: hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in sources}
    environment['reference_build'] = json.loads(binary.with_suffix('.reference.json').read_text())
    environment['client_versions'] = json.loads(run([args.python, '-c', 'import importlib.metadata,json,sys; print(json.dumps({"python":sys.version,"aioquic":importlib.metadata.version("aioquic"),"pylsqpack":importlib.metadata.version("pylsqpack")}))'], capture_output=True).stdout)
    (output / 'environment.json').write_text(json.dumps(environment, indent=2) + '\n')
    network = f'oimo-native-independent-{os.getpid()}'
    run(['docker', 'network', 'create', '--internal', network], stdout=subprocess.DEVNULL)
    records = []
    reference_hash = None
    try:
        for trial in range(args.rounds):
            order = ['h3-reference', 'native'] if trial % 2 == 0 else ['native', 'h3-reference']
            for implementation in order:
                server = network + '-server'
                options = ['-reference-http3'] if implementation == 'h3-reference' else []
                run(['docker', 'run', '-d', '--name', server, '--network', network, '--cpus', '2', '--memory', '512m', '--memory-swap', '512m', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '-v', f'{binary}:/probe:ro', 'alpine:3.23', '/probe', '-serve', *options], stdout=subprocess.DEVNULL)
                try:
                    for _ in range(100):
                        state = json.loads(run(['docker', 'inspect', server], capture_output=True).stdout)[0]
                        if not state['State']['Running']:
                            raise RuntimeError(run(['docker', 'logs', server], capture_output=True).stderr)
                        if 'ready' in run(['docker', 'logs', server], capture_output=True).stdout:
                            break
                        time.sleep(0.05)
                    else:
                        raise RuntimeError('server readiness timeout')
                    address = state['NetworkSettings']['Networks'][network]['IPAddress']
                    if not address:
                        raise RuntimeError('isolated server has no address')
                    ciphers = ['default']
                    if args.all_ciphers and trial == 0 and implementation == 'native':
                        ciphers += ['AES_128_GCM_SHA256', 'AES_256_GCM_SHA384', 'CHACHA20_POLY1305_SHA256']
                    for cipher in ciphers:
                        completed = subprocess.run([args.python, 'scripts/probe-native-http3.py', '--origin', f'https://{address}:8443', '--requests', str(args.requests), '--cipher', cipher, *(['--key-update'] if args.key_update else [])], cwd=ROOT, text=True, capture_output=True, timeout=60)
                        prefix = output / f'r{trial+1}-{implementation}-{cipher}'
                        prefix.with_suffix('.json').write_text(completed.stdout)
                        prefix.with_suffix('.stderr').write_text(completed.stderr)
                        if completed.returncode:
                            raise RuntimeError(completed.stderr)
                        value = json.loads(completed.stdout)
                        if reference_hash is None:
                            reference_hash = value['full_body_sha256']
                        if value['full_body_sha256'] != reference_hash:
                            raise RuntimeError('decoded body hash differs between implementations')
                        records.append({'round': trial+1, 'implementation': implementation, 'cipher': cipher, 'key_update': args.key_update, **value})
                        (output / 'results.json').write_text(json.dumps(records, indent=2) + '\n')
                        print(trial+1, implementation, cipher, value['success'], value['errors'], flush=True)
                finally:
                    run(['docker', 'rm', '-f', server], stdout=subprocess.DEVNULL)
    finally:
        run(['docker', 'network', 'rm', network], stdout=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
