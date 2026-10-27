"""隔離HTTPでスクリプト連投を再現し、実DATと通常投稿・閲覧を照合する。"""
import concurrent.futures
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import threading
import time

# ハイフン付き既存CLIの通信・資源計測を共有する。
spec = importlib.util.spec_from_file_location('abuse_evaluation', Path(__file__).with_name('evaluate-abuse.py'))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
BOARDS = ['single', 'rotate', 'identical', 'variant', 'random', 'slow',
          'splitone', 'splittwo', 'splitthree', 'splitfour', 'control']
CURRENT_SETTINGS = {
    'similar': {'mode': 'observe', 'window_seconds': 300, 'sample_posts': 50,
                'threshold_percent': 90, 'match_posts': 3, 'min_runes': 12},
    'flood': {'mode': 'reject', 'window_seconds': 30, 'thread_posts': 100,
              'subject_posts': 30, 'share_min_posts': 15, 'share_percent': 80},
    'exempt_caps': True,
    'rates': {'enabled': True, 'reply_seconds': 1, 'reply_burst': 3,
              'create_seconds': 600, 'create_burst': 1, 'create_window_limit': 6},
    'token_wait_seconds': 0,
}


def random_body(label):
    """条件間の偶然の類似を避ける、再現可能な合成本文を返す。"""
    return hashlib.sha256(label.encode()).hexdigest()


def read_settings(admin):
    """管理認証済みの隔離APIから設定と検出一覧を読む。"""
    status, headers, raw = admin.request('/api/v1/abuse-guard')
    assert status == 200, ('guard get', status)
    return json.loads(raw)['data'], headers


def save_settings(admin, settings, request_id):
    """共通条件を隔離環境へCAS/CSRF付きで保存し、保存値を照合する。"""
    _, headers = read_settings(admin)
    status, _, raw = admin.request('/api/v1/abuse-guard', json.dumps(settings).encode(),
        {'Content-Type': 'application/json', 'Origin': f'http://127.0.0.1:{admin.port}',
         'If-Match': headers['etag'], 'X-CSRF-Token': headers['x-csrf-token'],
         'Idempotency-Key': request_id}, method='PATCH')
    assert status == 200, ('guard save', status)
    assert json.loads(raw)['data']['settings'] == settings


def summary(rows):
    """拒否率と応答分類を集計する。通信失敗は拒否成功として扱わない。"""
    value = base.summarize(rows)
    value['rejected'] = len(rows)-value['accepted']
    value['rejected_percent'] = round(100*value['rejected']/len(rows), 2)
    value['statuses'] = {str(s): sum(r['status'] == s for r in rows)
                         for s in sorted({r['status'] for r in rows})}
    return value


def evaluate_flood(public, admin, name, finish, mode):
    """実TCP送信元を分け、攻撃と同時に通常投稿・閲覧を発行する。"""
    keys, counts = {}, {}
    for index, board in enumerate(BOARDS, 1):
        seed = base.Client(public, f'127.250.{index}.1')
        assert seed.post(board, '', random_body('seed-'+board), name+'-seed-'+board)['accepted']
        status, _, raw = seed.request('/'+board+'/subject.txt')
        assert status == 200
        keys[board] = raw.split(b'.dat<>', 1)[0].decode('ascii')
        counts[board] = 1
    settings = json.loads(json.dumps(CURRENT_SETTINGS))
    # 2026-10-11に稼働中controlの最新保存値を読み取り確認した条件。
    settings['similar']['mode'] = 'reject' if mode == 'reject128' else 'observe' if mode == 'current' else mode
    settings['flood']['mode'] = 'reject' if mode in ('current', 'reject128') else mode
    if mode == 'reject128':
        settings['similar']['sample_posts'] = 128
    save_settings(admin, settings, name+'-configure')
    results = {'settings': settings, 'mode': mode, 'scenarios': {}}

    def run(label, board, jobs, workers=16, pause=0):
        """通常投稿は独立スレッドから同時発行し、別スレッドの正常系も測る。"""
        index = len(results['scenarios'])+1
        observer = base.Client(public, f'127.230.{index}.1')
        other = base.Client(public, f'127.231.{index}.1')
        stopped, ready = threading.Event(), threading.Event()
        normal, control, reads, failures = [], [], [], []
        started = time.monotonic()

        def watch():
            try:
                tick = 0
                next_post = 0
                while True:
                    if tick < 5 and time.monotonic() >= next_post:
                        normal.append(observer.post(board, keys[board], random_body(f'{label}-normal-{tick}'), random_body(name+f'-{label}-normal-{tick}')[:32]))
                        control.append(other.post('control', keys['control'], random_body(f'{label}-control-{tick}'), random_body(name+f'-{label}-control-{tick}')[:32]))
                        tick += 1
                        next_post = time.monotonic()+1.1
                    at = time.monotonic()
                    status, _, raw = observer.request('/'+board+'/dat/'+keys[board]+'.dat')
                    reads.append({'status': status, 'latency_ms': (time.monotonic()-at)*1000})
                    assert status == 200 and raw.endswith(b'\n')
                    ready.set()
                    if stopped.wait(.1):
                        break
            except Exception as error:
                failures.append(type(error).__name__)
                ready.set()
        thread = threading.Thread(target=watch)
        thread.start()
        assert ready.wait(30), 'observer startup timeout'
        try:
            def attack(job):
                client, target, body, ident = job
                row = client.post(target, keys[target], body, random_body(name+'-'+label+'-'+str(ident))[:32])
                return target, row
            rows = []
            if workers == 1:
                for job in jobs:
                    rows.append(attack(job))
                    if pause:
                        time.sleep(pause)
            else:
                with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                    rows = list(pool.map(attack, jobs))
        finally:
            stopped.set()
            thread.join()
        assert not failures, ('observer failure', failures)
        assert all(r['reason'] != 'other' for _, r in rows), 'unclassified attack response'
        assert all(r['reason'] != 'other' for r in normal+control), 'unclassified normal response'
        after_same = base.Client(public, f'127.232.{index}.1').post(board, keys[board],
            random_body(label+'-after'), random_body(name+label+'-after')[:32])
        after_other = base.Client(public, f'127.233.{index}.1').post('control', keys['control'],
            random_body(label+'-after-control'), random_body(name+label+'-after-control')[:32])
        assert after_same['reason'] != 'other' and after_other['reason'] != 'other'
        for target, row in rows:
            counts[target] += int(row['accepted'])
        counts[board] += sum(r['accepted'] for r in normal)+int(after_same['accepted'])
        counts['control'] += sum(r['accepted'] for r in control)+int(after_other['accepted'])
        current, _ = read_settings(admin)
        events = current['events'] or []
        event_counts = {reason: sum(e['reason'] == reason for e in events)
                        for reason in sorted({e['reason'] for e in events})}
        results['scenarios'][label] = {'attack': summary([r for _, r in rows]),
            'normal_same_thread': summary(normal), 'normal_other_thread': summary(control),
            'normal_same_thread_after_burst': summary([after_same]),
            'normal_other_thread_after_burst': summary([after_other]),
            'reads': {'attempts': len(reads), 'ok': sum(r['status'] == 200 for r in reads),
                      'p95_ms': round(sorted(r['latency_ms'] for r in reads)[min(len(reads)-1, int(len(reads)*.95))], 2)},
            'seconds': round(time.monotonic()-started, 2),
            'recent_events_cumulative_last_100': event_counts}
        print(json.dumps({'scenario': label, 'attack': results['scenarios'][label]['attack']}, ensure_ascii=False), flush=True)

    held = base.Client(public, '127.201.0.1')
    run('same_ip_cookie_burst', 'single', [(held, 'single', 'Repeated script message', i) for i in range(200)], workers=1)
    run('same_ip_cookie_rotation', 'rotate', [(base.Client(public, '127.202.0.1'), 'rotate', random_body('rotate'+str(i)), i) for i in range(60)], workers=1)
    for board, label, body in [
        ('identical', 'distributed_identical', lambda i: 'This synthetic campaign repeats its fixed advertising message across many independent clients.'),
        ('variant', 'distributed_partial_change', lambda i: 'Another synthetic campaign repeats a long advertising message with only its final identifier changed to variant number '+str(i)),
        ('random', 'distributed_random', lambda i: random_body('random'+str(i)))]:
        number = {'identical': 20, 'variant': 21, 'random': 22}[board]
        jobs = [(base.Client(public, f'127.{number}.{i+1}.1'), board, body(i), i) for i in range(160)]
        run(label, board, jobs)
    targets = ['splitone', 'splittwo', 'splitthree', 'splitfour']
    jobs = [(base.Client(public, f'127.23.{i+1}.1'), targets[i % 4], random_body('split'+str(i)), i) for i in range(160)]
    run('distributed_random_across_four_boards', 'splitone', jobs)
    # 20種類を順に使うと、直近50件に同じ本文が3件揃う条件を回避し得る。
    jobs = [(base.Client(public, f'127.24.{i+1}.1'), targets[i % 4],
             random_body('template-'+str(i % 20)), i) for i in range(160)]
    run('distributed_20_templates_across_four_boards', 'splitone', jobs)
    slow = base.Client(public, '127.204.0.1')
    run('same_ip_random_1_per_second', 'slow', [(slow, 'slow', random_body('slow'+str(i)), i) for i in range(20)], workers=1, pause=1.1)

    def verify_dat():
        """受付表示から独立に公開DATの実件数を照合する。"""
        reader = base.Client(public)
        for board, count in counts.items():
            status, _, raw = reader.request('/'+board+'/dat/'+keys[board]+'.dat')
            assert status == 200 and raw.count(b'\n') == count, ('DAT mismatch', board, count, raw.count(b'\n'))
    verify_dat()
    results['_resources'] = finish()
    subprocess.run(['docker', 'restart', '--timeout', '35', name], check=True, stdout=subprocess.DEVNULL)
    for _ in range(60):
        try:
            if slow.request('/slow/')[0] == 200:
                break
        except OSError:
            pass
        time.sleep(.25)
    else:
        raise RuntimeError('restart timeout')
    admin.reauthenticate()
    after, _ = read_settings(admin)
    assert after['settings'] == settings, 'restart settings mismatch'
    retry = slow.post('slow', keys['slow'], random_body('slow-restart'), name+'-slow-restart')
    counts['slow'] += int(retry['accepted'])
    results['restart'] = {'settings_preserved': True, 'same_subject_post': summary([retry])}
    verify_dat()
    results['verified_dat_posts'] = counts
    return results
