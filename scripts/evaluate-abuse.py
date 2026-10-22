#!/usr/bin/env python3
"""独立Docker上で匿名投稿の連投・分散攻撃と既存規制を評価する。通信先はloopback限定。"""
import argparse
import concurrent.futures
import html.parser
import http.client
import http.cookies
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import threading
import time
import urllib.parse


class HiddenFields(html.parser.HTMLParser):
    """管理フォームのhidden値だけを抽出する。"""
    def __init__(self, page):
        super().__init__()
        self.values = {}
        self.feed(page)

    def handle_starttag(self, tag, attrs):
        row = dict(attrs)
        if tag == 'input' and row.get('type') == 'hidden':
            self.values[row['name']] = row.get('value', '')


class Client:
    """loopback送信元を固定し、Cookieをメモリ内だけに保持する試験利用者。"""
    def __init__(self, port, source='127.0.0.1'):
        assert source.startswith('127.')
        self.port, self.source, self.cookies = port, source, {}

    def request(self, route, fields=None, headers=None, method=None):
        """固定localhostへ送信し、応答Cookieを保存する。秘密・本文は記録しない。"""
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=30,
                                          source_address=(self.source, 0))
        hdr = {'User-Agent': 'OimoLocalAbuseEvaluation/1.0', **(headers or {})}
        if self.cookies:
            hdr['Cookie'] = '; '.join(k + '=' + v for k, v in self.cookies.items())
        data = fields
        if isinstance(fields, dict):
            data = urllib.parse.urlencode(fields).encode()
            hdr['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
        try:
            conn.request(method or ('GET' if fields is None else 'POST'), route, data, hdr)
            res = conn.getresponse()
            raw = res.read()
            for name, value in res.getheaders():
                if name.lower() == 'set-cookie':
                    parsed = http.cookies.SimpleCookie(value)
                    for key, cookie in parsed.items():
                        if cookie['max-age'] == '0' or not cookie.value:
                            self.cookies.pop(key, None)
                        else:
                            self.cookies[key] = cookie.value
            return res.status, dict((k.lower(), v) for k, v in res.getheaders()), raw
        finally:
            conn.close()

    def post(self, board, key, body, request_id):
        """新しい要求IDで最大3往復の確認を行い、最終結果と時間を返す。"""
        fields = {'bbs': board, 'MESSAGE': body, 'oimo_request_id': request_id}
        fields['key' if key else 'subject'] = key or 'Local abuse evaluation'
        started = time.monotonic()
        for _ in range(3):
            status, headers, raw = self.request('/test/bbs.cgi', fields)
            if b'2ch_X:cookie' not in raw:
                break
        text = raw.decode('shift_jis', errors='replace')
        accepted = '投稿を受け付けました。' in text or '同一内容を受理済みです。' in text
        reason = 'accepted' if accepted else ('guard' if '埋め立て対策' in text else 'reissue_wait' if '再発行後の待機中' in text
                  else 'rate' if status == 429 else 'denied' if '規制' in text else 'other')
        return {'accepted': accepted, 'status': status, 'reason': reason,
                'duplicate': '同一内容を受理済みです。' in text,
                'restriction_details_disclosed': any(word in text for word in ('反復違反', 'この匿名Cookie', '再発行後の待機中', '埋め立て対策')),
                'latency_ms': (time.monotonic()-started)*1000,
                'retry_after': int(headers.get('retry-after', '0'))}


def summarize(results):
    """Cookieや本文を含めず、件数・拒否理由・応答時間を集計する。"""
    times = sorted(r['latency_ms'] for r in results)
    reasons = {}
    for row in results:
        reasons[row['reason']] = reasons.get(row['reason'], 0)+1
    return {'attempts': len(results), 'accepted': sum(r['accepted'] for r in results),
            'reasons': reasons, 'p95_ms': round(times[min(len(times)-1, int(len(times)*0.95))], 2)}


def free_port():
    """空きloopbackポートを選ぶ。起動前の競合はDocker起動失敗として扱う。"""
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class Resources:
    """製品コンテナのcgroup v2からCPU・メモリ・物理I/Oだけをサンプリングする。"""
    def __init__(self, container):
        pid = subprocess.check_output(['docker', 'inspect', container, '--format', '{{.State.Pid}}'], text=True).strip()
        group = Path('/proc/'+pid+'/cgroup').read_text().strip().split('::', 1)[1]
        self.root = Path('/sys/fs/cgroup'+group)
        self.stop = threading.Event()
        self.memory_max, self.samples, self.cpu_max = 0, 0, 0.0
        self.finished = None
        self.start = self.read()
        self.started = time.monotonic()
        self.thread = threading.Thread(target=self.sample)
        self.thread.start()

    def read(self):
        cpu = dict(line.split() for line in (self.root/'cpu.stat').read_text().splitlines())
        io = {'rbytes': 0, 'wbytes': 0, 'rios': 0, 'wios': 0}
        for line in (self.root/'io.stat').read_text().splitlines():
            for pair in line.split()[1:]:
                key, value = pair.split('=')
                if key in io:
                    io[key] += int(value)
        return {'cpu_usec': int(cpu['usage_usec']), **io}

    def sample(self):
        previous_cpu, previous_at = self.start['cpu_usec'], self.started
        while not self.stop.wait(0.1):
            cpu, at = self.read()['cpu_usec'], time.monotonic()
            self.cpu_max = max(self.cpu_max, (cpu-previous_cpu)/1e6/(at-previous_at))
            previous_cpu, previous_at = cpu, at
            self.memory_max = max(self.memory_max, int((self.root/'memory.current').read_text()))
            self.samples += 1

    def finish(self):
        """サンプラーを終了し、期間平均CPUとメモリ/I/O差分を返す。"""
        if self.finished is not None:
            return self.finished
        self.stop.set()
        self.thread.join()
        end = self.read()
        elapsed = time.monotonic()-self.started
        self.finished = {'seconds': round(elapsed, 2), 'cpu_average_cores': round((end['cpu_usec']-self.start['cpu_usec'])/1e6/elapsed, 3),
                'cpu_sampled_peak_cores': round(self.cpu_max, 3), 'memory_sampled_peak_bytes': self.memory_max, 'memory_samples': self.samples,
                'physical_io_delta': {k: end[k]-self.start[k] for k in ['rbytes', 'wbytes', 'rios', 'wios']}}
        return self.finished


def evaluate(public, admin, name, before_restart):
    """4条件を別板・別送信元で評価し、分散本文攻撃の既存規制による封じ込めを検証する。"""
    keys, board_ids = {}, {}
    for index, board in enumerate(['hold', 'distributed', 'mutated', 'shared'], 1):
        seed = Client(public, f'127.250.{index}.1')
        assert seed.post(board, '', 'Normal seed', name+'-seed-'+board)['accepted']
        status, _, raw = seed.request('/'+board+'/subject.txt')
        assert status == 200
        keys[board] = raw.split(b'.dat<>', 1)[0].decode('ascii')
    status, _, raw = admin.request('/api/v1/boards')
    assert status == 200
    board_ids = {row['key']: row['id'] for row in json.loads(raw)['data']}
    result = {}
    held = Client(public, '127.210.0.1')
    result['cookie_maintained_burst'] = summarize([held.post('hold', keys['hold'], 'Repeated text', name+f'-hold-{i}') for i in range(60)])
    assert result['cookie_maintained_burst']['accepted'] < 60
    normal = Client(public, '127.211.0.1')
    result['normal_during_single_ip_attack'] = summarize([normal.post('hold', keys['hold'], 'Normal unaffected', name+'-hold-normal')])
    assert result['normal_during_single_ip_attack']['accepted'] == 1

    # 32種類の送信元・/24を使用する。偽造ヘッダーではなく実TCPのloopback送信元。
    clients = [Client(public, f'127.{i+1}.0.1') for i in range(32)]
    spectator = Client(public, '127.212.0.1')
    flood, regular = [], []
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        for tick in range(4):
            flood += list(pool.map(lambda item: item[1].post('distributed', keys['distributed'], 'Campaign marker fixed spam', name+f'-distributed-{tick}-{item[0]}'), enumerate(clients)))
            regular.append(spectator.post('distributed', keys['distributed'], 'Normal discussion '+str(tick), name+f'-distributed-normal-{tick}'))
            time.sleep(1.1)
    burst = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        def burst_client(item):
            index, client = item
            return [client.post('distributed', keys['distributed'], 'Campaign marker burst', name+f'-distributed-burst-{index}-{n}') for n in range(4)]
        for rows in pool.map(burst_client, enumerate(clients)):
            burst.extend(rows)
    result['distributed_burst'] = summarize(burst)
    # 実時間の補充・保存待ちが変わるため、受理数を固定せずDATの実件数で検証する。
    result['distributed_low_rate'] = summarize(flood)
    result['normal_during_distributed_attack'] = summarize(regular)
    assert result['distributed_low_rate']['accepted'] > 64
    assert result['normal_during_distributed_attack']['accepted'] == 4

    changed = Client(public, '127.213.0.1')
    changed_results = []
    for i in range(8):
        changed_results.append(changed.post('mutated', keys['mutated'], 'Campaign marker changed '+str(i), name+f'-mutated-{i}'))
        time.sleep(1.1)
    result['mutated_low_rate'] = summarize(changed_results)
    assert result['mutated_low_rate']['accepted'] == 8

    # 新規発行10回の起点を、既存2利用者＋新規8利用者で作る。
    established = [Client(public, '127.214.0.1') for _ in range(2)]
    for i, client in enumerate(established):
        fields = {'bbs': 'shared', 'key': keys['shared'], 'MESSAGE': 'Warm user '+str(i), 'oimo_request_id': name+f'-shared-warm-{i}'}
        assert b'2ch_X:cookie' in client.request('/test/bbs.cgi', fields)[2]
        time.sleep(0.15)
    for i in range(7):
        fresh = Client(public, '127.214.0.1')
        fields = {'bbs': 'shared', 'key': keys['shared'], 'MESSAGE': 'New issue '+str(i), 'oimo_request_id': name+f'-shared-issue-{i}'}
        assert b'2ch_X:cookie' in fresh.request('/test/bbs.cgi', fields)[2]
        time.sleep(0.15)
    tenth = Client(public, '127.214.0.1')
    blocked = tenth.post('shared', keys['shared'], 'Normal new visitor', name+'-shared-tenth')
    assert blocked['reason'] in ('reissue_wait', 'rate') and 590 <= blocked['retry_after'] <= 600
    time.sleep(1.1)
    existing = [client.post('shared', keys['shared'], 'Normal existing '+str(i), name+f'-shared-existing-{i}') for i, client in enumerate(established)]
    assert all(r['accepted'] for r in existing)
    result['shared_ip'] = {'new_visitor': summarize([blocked]), 'existing_visitors': summarize(existing), 'new_visitor_wait_seconds': blocked['retry_after']}

    # 本文の既知の共通部分を、既存の管理APIで期間限定規制。IP分散・末尾変更にも適用。
    for board in ['distributed', 'mutated']:
        route = '/api/v1/boards/'+board_ids[board]+'/rules'
        status, headers, _ = admin.request(route)
        assert status == 200
        data = {'target': 'Campaign marker', 'operations': ['reply'], 'duration_minutes': 60,
                'reason_code': 'spam', 'match': {'field': 'body', 'operator': 'contains', 'effect': 'deny'},
                'extra_conditions': [], 'allow_rule_ids': [], 'rate_override': None}
        status, _, _ = admin.request(route, json.dumps(data).encode(), {'Content-Type': 'application/json', 'Origin': f'http://127.0.0.1:{admin.port}', 'If-Match': headers['etag'], 'X-CSRF-Token': headers['x-csrf-token'], 'Idempotency-Key': name+'-rule-'+board})
        assert status == 200, ('rule', status)
    blocked_campaign = [client.post('distributed', keys['distributed'], 'Campaign marker variant '+str(i), name+f'-mitigated-{i}') for i, client in enumerate(clients)]
    result['distributed_after_targeted_rule'] = summarize(blocked_campaign)
    assert result['distributed_after_targeted_rule']['accepted'] == 0
    changed_results = [changed.post('mutated', keys['mutated'], 'Campaign marker variant '+str(i), name+f'-mutated-mitigated-{i}') for i in range(8)]
    result['mutated_after_targeted_rule'] = summarize(changed_results)
    assert result['mutated_after_targeted_rule']['accepted'] == 0
    normal_after = [spectator.post('distributed', keys['distributed'], 'Normal discussion after rule', name+'-normal-after-rule')]
    result['normal_after_targeted_rule'] = summarize(normal_after)
    assert result['normal_after_targeted_rule']['accepted'] == 1
    # HTTP成功の判定と公開DAT上の実件数を独立に照合する。
    expected = {'hold': 1+result['cookie_maintained_burst']['accepted']+1,
                'distributed': 1+result['distributed_low_rate']['accepted']+result['distributed_burst']['accepted']+4+1,
                'mutated': 1+8, 'shared': 1+2}
    actual = {}
    for board, count in expected.items():
        status, _, raw = spectator.request('/'+board+'/dat/'+keys[board]+'.dat')
        assert status == 200 and raw.count(b'\n') == count, ('DAT count', board, count, raw.count(b'\n'))
        actual[board] = count
    # 実製品を再起動し、規制と既存Cookieが維持されることを確認する。
    result['_resources'] = before_restart()
    subprocess.run(['docker', 'restart', '--timeout', '35', name], check=True, stdout=subprocess.DEVNULL)
    for _ in range(60):
        try:
            if spectator.request('/distributed/')[0] == 200:
                break
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(0.25)
    else:
        raise RuntimeError('isolated restart timeout')
    post_restart = clients[0].post('distributed', keys['distributed'], 'Campaign marker after restart', name+'-restart-denied')
    normal_restart = spectator.post('distributed', keys['distributed'], 'Normal after restart', name+'-restart-normal')
    assert post_restart['reason'] == 'denied' and normal_restart['accepted']
    status, _, raw = spectator.request('/distributed/dat/'+keys['distributed']+'.dat')
    assert status == 200 and raw.count(b'\n') == actual['distributed']+1
    actual['distributed'] += 1
    result['restart_preserves_mitigation_and_normal_cookie'] = True
    result['verified_dat_posts'] = actual
    return result


def main():
    """独立volumeだけを初期化し、評価・private結果保存後にコンテナとvolumeを除去する。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', default='oimobbs-validation:local')
    parser.add_argument('--output', default='var/abuse-evaluation/result.json')
    parser.add_argument('--suite', choices=['legacy', 'script-flood', 'repeated-rule'], default='legacy')
    parser.add_argument('--guard-mode', choices=['current', 'observe', 'reject', 'reject128'], default='current',
                        help='script-flood用。currentは2026-10-11に確認した保存済み条件の再現')
    args = parser.parse_args()
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    assert not output.exists(), 'output already exists'
    name = 'oimo-abuse-evaluation-'+secrets.token_hex(6)
    public, private = free_port(), free_port()
    while private == public:
        private = free_port()
    config_path = output.parent/(name+'.json')
    config = {'schema_version': 1, 'data_dir': '/data/site', 'public': {'listen': f'127.0.0.1:{public}', 'base_url': f'http://127.0.0.1:{public}', 'tls_cert_file': '', 'tls_key_file': ''}, 'admin': {'listen': f'127.0.0.1:{private}', 'transport': 'loopback_tunnel', 'origin': f'http://127.0.0.1:{private}'}, 'trusted_proxies': [], 'egress_budget_bits_per_second': 80000000}
    config.update(auto_reports=None, edge=None, maintenance=None)
    if args.suite == 'script-flood':
        config['egress_budget_bits_per_second'] = 100000000
    fd = os.open(config_path, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o644)
    with os.fdopen(fd, 'w') as file:
        json.dump(config, file)
    image = subprocess.check_output(['docker', 'image', 'inspect', args.image, '--format', '{{.Id}}'], text=True).strip()
    run = lambda argv, **kw: subprocess.run(argv, check=True, stdout=subprocess.DEVNULL, **kw)
    run(['docker', 'volume', 'create', name])
    base = ['docker', 'run', '--rm', '--network', 'none', '-i', '-v', name+':/data', '-v', str(config_path)+':/etc/oimobbs/config.json:ro', image]
    def cli(argv, data=None):
        run(base+argv+['--config', '/etc/oimobbs/config.json'], input=data)
    monitor = None
    try:
        cli(['init', '--name', 'Local abuse evaluation'])
        secret = secrets.token_urlsafe(32)
        cli(['admin', 'init', '--login', 'owner', '--password-stdin'], (secret+'\n').encode())
        boards = ['hold', 'distributed', 'mutated', 'shared']
        evaluator = evaluate
        if args.suite == 'script-flood':
            from abuse_scenarios import BOARDS, evaluate_flood
            boards = BOARDS
            evaluator = lambda public, admin, name, finish: evaluate_flood(
                public, admin, name, finish, args.guard_mode)
        elif args.suite == 'repeated-rule':
            from repeat_scenarios import BOARDS, evaluate_repeated
            boards = BOARDS
            evaluator = evaluate_repeated
        for board in boards:
            cli(['board', 'create', '--key', board, '--name', board])
        cli(['admission', 'enable'])
        cli(['anonymous', 'enable', '--mode', 'required'])
        run(['docker', 'run', '-d', '--name', name, '--network', 'host', '--cpus', '2', '--memory', '512m', '--read-only', '--tmpfs', '/tmp:uid=10001,gid=10001,mode=0700', '-v', name+':/data', '-v', str(config_path)+':/etc/oimobbs/config.json:ro', image, 'validation-serve', '--config', '/etc/oimobbs/config.json', '--admin'])
        admin = Client(private)
        for _ in range(60):
            try:
                status, _, raw = admin.request('/login')
                if status == 200:
                    break
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(0.25)
        else:
            raise RuntimeError('isolated startup timeout')
        def login():
            """隔離管理画面へ認証し、再起動で失効したsessionも再取得する。"""
            status, _, page = admin.request('/login')
            assert status == 200
            fields = HiddenFields(page.decode()).values
            fields.update(login='owner', password=secret)
            status, _, _ = admin.request('/login', fields, {'Origin': f'http://127.0.0.1:{private}'})
            assert status == 303
        login()
        admin.reauthenticate = login
        monitor = Resources(name)
        results = evaluator(public, admin, name, monitor.finish)
        resources = results.pop('_resources')
        monitor = None
        state = json.loads(subprocess.check_output(['docker', 'inspect', name, '--format', '{{json .State}}'], text=True))
        assert state['Running'] and not state['OOMKilled']
        record = {'image': image, 'limits': {'cpus': 2, 'memory_bytes': 536870912, 'egress_bits_per_second': config['egress_budget_bits_per_second']}, 'transport': 'local HTTP, real loopback source addresses', 'results': results, 'resources': resources, 'oom_killed': False}
        fd = os.open(output, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as file:
            json.dump(record, file, indent=2)
        print(json.dumps(record, indent=2))
    except Exception:
        # 失敗した隔離環境の起動理由を、破棄前に非公開artifactへ残す。
        logs = subprocess.run(['docker', 'logs', '--tail', '80', name], capture_output=True)
        fd = os.open(str(output)+'.server.log', os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as file:
            file.write(logs.stdout+logs.stderr)
        raise
    finally:
        if monitor is not None:
            monitor.finish()
        subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['docker', 'volume', 'rm', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        config_path.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
