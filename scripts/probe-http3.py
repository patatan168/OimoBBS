#!/usr/bin/env python3
"""2CPU・512MiBの隔離DockerネットワークでHTTP/1・2・3の全試行を保存する。"""
import argparse
import hashlib
import platform
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parent.parent


def run(args, **kwargs):
    """失敗時も呼出元へ終了コードを伝える。"""
    return subprocess.run(args, cwd=ROOT, text=True, check=True, **kwargs)


def main():
    """本番のvolume・port・設定を使わず、専用ネットワークと短命コンテナだけを作る。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', default='var/http3-20261103')
    parser.add_argument('--requests', type=int, default=1000)
    parser.add_argument('--rounds', type=int, default=3)
    parser.add_argument('--protocols', default='h1,h2,h3')
    parser.add_argument('--baseline-binary', help='同じclientで比較する変更前serverバイナリ（h3-baseline用）')
    parser.add_argument('--workloads', default='')
    parser.add_argument('--trace', action='store_true')
    parser.add_argument('--client-cpus', type=int, default=2)
    parser.add_argument('--workers', type=int, default=8)
    parser.add_argument('--client-procs', type=int, default=0)
    args = parser.parse_args()
    if args.requests < 1 or args.rounds < 1 or args.client_cpus < 1 or args.client_procs < 0 or not 1 <= args.workers <= 32:
        parser.error("requests・rounds・client-cpusは正の整数、workersは1〜32で指定してください")
    output = (ROOT / args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    binary = output / 'httptransportbench'
    run(['python3', 'scripts/quic-reference.py', 'build-benchmark', '--output', str(binary)])
    baseline = Path(args.baseline_binary).resolve() if args.baseline_binary else None
    if baseline is not None and (not baseline.is_file() or not baseline.with_suffix('.reference.json').is_file()):
        parser.error('baseline-binaryにはbuild-benchmarkのバイナリと.reference.jsonが必要です')
    network = f'oimo-http3-probe-{os.getpid()}'
    server = network + '-server'
    client = network + '-client'
    run(['docker', 'network', 'create', '--internal', network], stdout=subprocess.DEVNULL)
    records = []
    sources = ['go.mod', 'go.sum', 'tools/quicreference/fixtures/tools/httptransportbench/reference_main.go.txt', 'scripts/probe-http3.py', 'internal/httptransport/http3.go', 'internal/httptransport/http3_lifecycle.go', 'internal/delivery/quic_admission.go']
    sources += [str(p.relative_to(ROOT)) for folder in ['internal/quicv1', 'internal/http3native'] for p in sorted((ROOT/folder).glob('*.go')) if not p.name.endswith('_test.go')]
    environment = {'requests': args.requests, 'rounds': args.rounds, 'workloads': args.workloads, 'trace': args.trace, 'cpu_limit': 2, 'client_cpu_limit': args.client_cpus, 'client_gomaxprocs': args.client_procs, 'workers': args.workers, 'memory_bytes': 512*1024*1024,
                   'host': platform.platform(), 'go_version': run(['mise', 'exec', '--', 'go', 'version'], capture_output=True).stdout.strip(),
                   'git_head': run(['git', 'rev-parse', 'HEAD'], capture_output=True).stdout.strip(),
                   'source_sha256': {p: hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in sources},
                   'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                   'reference_build': json.loads(binary.with_suffix('.reference.json').read_text()),
                   'protocol_backend': {'h3': 'native', 'h3-native': 'native alias', 'h3-reference': 'test-only quic-go'},
                   'network_scope': 'isolated Docker bridge, virtual eth0 counters; no WAN, packet loss or RTT emulation'}
    if baseline is not None:
        environment['baseline'] = {'binary_sha256': hashlib.sha256(baseline.read_bytes()).hexdigest(),
                                   'reference_build': json.loads(baseline.with_suffix('.reference.json').read_text())}
        environment['protocol_backend']['h3-baseline'] = 'native baseline server; same candidate client'
    (output / 'environment.json').write_text(json.dumps(environment, indent=2) + '\n')
    try:
        # 順序による偏りを減らすため、各周で先頭protocolを回す。
        protocols = args.protocols.split(',')
        if not protocols or any(p not in ['h1', 'h2', 'h3', 'h3-native', 'h3-reference', 'h3-baseline'] for p in protocols):
            raise ValueError('protocols must contain h1, h2, h3, h3-native, h3-reference, or h3-baseline')
        if 'h3-baseline' in protocols and baseline is None:
            raise ValueError('h3-baseline requires --baseline-binary')
        for round_index in range(args.rounds):
            order = protocols[round_index % len(protocols):] + protocols[:round_index % len(protocols)]
            for protocol in order:
                prefix = output / f'r{round_index+1}-{protocol}'
                server_binary = baseline if protocol == 'h3-baseline' else binary
                run(['docker', 'run', '-d', '--name', server, '--network', network, '--cpus', '2', '--memory', '512m', '--memory-swap', '512m', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '-v', f'{server_binary}:/probe:ro', 'alpine:3.23', '/probe', '-serve', *(['-reference-http3'] if protocol == 'h3-reference' else [])], stdout=subprocess.DEVNULL)
                try:
                    for _ in range(100):
                        logs = run(['docker', 'logs', server], capture_output=True)
                        if 'ready' in logs.stdout:
                            break
                        time.sleep(0.05)
                    else:
                        raise RuntimeError('server did not become ready')
                    address = json.loads(run(['docker', 'inspect', server], capture_output=True).stdout)[0]['NetworkSettings']['Networks'][network]['IPAddress']
                    trace_args = []
                    if args.client_procs:
                        trace_args += ['-e', f'GOMAXPROCS={args.client_procs}']
                    client_args = ['-origin', f'https://{address}:8443', '-protocol', 'h3' if protocol in ['h3-native', 'h3-reference', 'h3-baseline'] else protocol, '-requests', str(args.requests), '-workloads', args.workloads, '-workers', str(args.workers)]
                    if args.trace:
                        trace_folder = output / f'r{round_index+1}-{protocol}-trace'
                        trace_folder.mkdir(exist_ok=True)
                        trace_args += ['--user', f'{os.getuid()}:{os.getgid()}', '-v', f'{trace_folder}:/trace:rw']
                        if protocol == 'h2':
                            trace_args += ['-e', 'GODEBUG=http2debug=2']
                        client_args += ['-trace-dir', '/trace']
                    completed = subprocess.run(['docker', 'run', '--rm', '--name', client, '--network', network, '--cpus', str(args.client_cpus), '--memory', '512m', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '-v', f'{binary}:/probe:ro', *trace_args, 'alpine:3.23', '/probe', *client_args], cwd=ROOT, text=True, capture_output=True)
                    prefix.with_suffix('.jsonl').write_text(completed.stdout)
                    prefix.with_suffix('.stderr').write_text(completed.stderr)
                    for line in completed.stdout.splitlines():
                        records.append({'round': round_index+1, **json.loads(line), 'implementation': protocol})
                    (output / 'results.json').write_text(json.dumps(records, indent=2) + '\n')
                    print(f'round={round_index+1} protocol={protocol} exit={completed.returncode}', flush=True)
                    if completed.returncode:
                        raise RuntimeError(completed.stderr)
                finally:
                    subprocess.run(['docker', 'rm', '-f', client], cwd=ROOT, text=True, capture_output=True)
                    logs = run(['docker', 'logs', server], capture_output=True)
                    prefix.with_suffix('.server.log').write_text(logs.stdout + logs.stderr)
                    run(['docker', 'rm', '-f', server], stdout=subprocess.DEVNULL)
    finally:
        run(['docker', 'network', 'rm', network], stdout=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
