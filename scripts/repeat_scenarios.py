"""既知の本文・URL規制への反復違反後、Cookieを維持したIP変更と正常利用を実HTTPで比較する。"""
import concurrent.futures
import json
import subprocess
import time
from abuse_scenarios import base, random_body, save_settings, CURRENT_SETTINGS, summary

BOARDS = ['campaign', 'domain', 'control', 'short']


def add_rule(admin, board_id, field, operator, target, request_id):
    """合成攻撃だけに適用する既存規制を隔離管理APIへ保存する。"""
    route = '/api/v1/boards/'+board_id+'/rules'
    status, headers, _ = admin.request(route)
    assert status == 200
    value = {'target': target, 'operations': ['reply'], 'duration_minutes': 60,
             'reason_code': 'spam', 'match': {'field': field, 'operator': operator, 'effect': 'deny'},
             'extra_conditions': [], 'allow_rule_ids': [], 'rate_override': None}
    status, _, _ = admin.request(route, json.dumps(value).encode(),
        {'Content-Type': 'application/json', 'Origin': f'http://127.0.0.1:{admin.port}',
         'If-Match': headers['etag'], 'X-CSRF-Token': headers['x-csrf-token'],
         'Idempotency-Key': request_id})
    assert status == 200, ('rule', status)


def evaluate_repeated(public, admin, name, finish):
    """同じCookieの不同IPを実TCPで再現し、再送と共有回線の別Cookieを照合する。"""
    keys, counts, output = {}, {}, {}
    save_settings(admin, CURRENT_SETTINGS, name+'-settings')
    for index, board in enumerate(BOARDS):
        seed = base.Client(public, f'127.250.{index+1}.1')
        assert seed.post(board, '', random_body('seed'+board), random_body(name+board+'seed')[:32])['accepted']
        status, _, raw = seed.request('/'+board+'/subject.txt')
        assert status == 200
        keys[board] = raw.split(b'.dat<>', 1)[0].decode('ascii')
        counts[board] = 1
    status, _, raw = admin.request('/api/v1/boards')
    assert status == 200
    ids = {row['key']: row['id'] for row in json.loads(raw)['data']}
    marker = 'OimoSyntheticCampaignMarkerLong'
    add_rule(admin, ids['campaign'], 'body', 'contains', marker, name+'-body-rule')
    add_rule(admin, ids['domain'], 'domain', 'exact', 'campaign.invalid', name+'-domain-rule')
    add_rule(admin, ids['short'], 'body', 'exact', '草', name+'-short-rule')

    def post(client, board, body, label):
        row = client.post(board, keys[board], body, random_body(name+label)[:32])
        assert row['reason'] != 'other', ('unclassified', label, row)
        # この隔離設定では通常レート待機は短い。公開理由ではなく試験条件と待機時間で判別する。
        row['cooldown'] = row['status'] == 429 and row['retry_after'] >= 500
        assert not row['restriction_details_disclosed'], ('public restriction details', label)
        if row['accepted'] and not row['duplicate']:
            counts[board] += 1
        return row

    enemies = [base.Client(public, f'127.20.{i+1}.1') for i in range(16)]
    warm = [post(c, 'control', random_body('warm'+str(i)), 'warm'+str(i)) for i, c in enumerate(enemies)]
    assert all(r['accepted'] for r in warm)
    violations = []
    # Cookieを維持し、各ラウンドで実接続元だけを変更する。内容と要求IDも毎回異なる。
    for tick in range(5):
        for i, client in enumerate(enemies):
            client.source = f'127.{21+tick}.{i+1}.1'
        # countsを書き換えるpost()は拒否だけを期待するため、ここでは共有カウンタを触らない。
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            rows = list(pool.map(lambda item: post(item[1], 'domain' if tick % 2 else 'campaign',
                'https://campaign.invalid/a/'+str(tick) if tick % 2 else marker+' '+str(tick),
                f'violation-{item[0]}-{tick}'), enumerate(enemies)))
        assert all(not r['accepted'] for r in rows)
        violations += rows
    output['known_campaign_violations'] = summary(violations)
    evasions = []
    for tick in range(2):
        for i, client in enumerate(enemies):
            client.source = f'127.{40+tick}.{i+1}.1'
        rows = [post(c, 'control', random_body(f'evasion-{i}-{tick}'), f'evasion-{i}-{tick}') for i, c in enumerate(enemies)]
        evasions += rows
    output['unrelated_body_after_five_violations_ip_changed'] = summary(evasions)
    active = any(r['cooldown'] for r in evasions)
    assert all((r['cooldown']) == active for r in evasions)
    output['feature_active'] = active

    # 同じIPの別Cookieには停止を伝播させない。
    shared = base.Client(public, enemies[0].source)
    output['same_ip_other_cookie_normal'] = summary([post(shared, 'control', random_body('shared'), 'shared-normal')])
    assert output['same_ip_other_cookie_normal']['accepted'] == 1
    # IPも内容も同じで、受理済み要求の固定再送を照会する。
    enemies[0].source = '127.20.1.1'
    duplicate = post(enemies[0], 'control', random_body('warm0'), 'warm0')
    assert duplicate['accepted'] and duplicate['duplicate']
    output['accepted_retry_preserved'] = duplicate

    retry = base.Client(public, '127.200.1.1')
    replay = []
    for i in range(10):
        retry.source = f'127.201.{i+1}.1'
        replay.append(post(retry, 'campaign', marker+' retry', 'fixed-denied-retry'))
    assert all(not r['accepted'] for r in replay)
    good = post(retry, 'control', random_body('retry-good'), 'retry-normal')
    assert good['accepted']
    output['same_denied_request_ten_retries_then_normal'] = {'denied_retries': summary(replay), 'normal': good}
    short = base.Client(public, '127.202.1.1')
    rows = [post(short, 'short', '草', 'short-denied-'+str(i)) for i in range(10)]
    assert all(not r['accepted'] for r in rows)
    good = post(short, 'control', random_body('short-good'), 'short-normal')
    assert good['accepted']
    output['short_rule_rejections_do_not_escalate'] = {'rejections': summary(rows), 'normal': good}

    normals = []
    for i in range(12):
        client = base.Client(public, f'127.203.{i+1}.1')
        normals.append(post(client, 'control', ['草', 'きた', 'おめ', '乙'][i % 4], 'normal-short-'+str(i)))
    for i in range(12):
        client = base.Client(public, f'127.204.{i+1}.1')
        normals.append(post(client, 'control', '正当な会話で何度も使われる引用の長い文章です。同じ引用であることは悪意の証明ではありません。', 'normal-quote-'+str(i)))
    assert all(r['accepted'] for r in normals)
    output['normal_short_and_repeated_quotes'] = summary(normals)

    # 通常の429を繰り返しても、この追加対策の停止へ昇格しない。
    rates = base.Client(public, '127.205.1.1')
    rows = [post(rates, 'control', random_body('rate'+str(i)), 'rate-'+str(i)) for i in range(20)]
    assert any(r['reason'] == 'rate' for r in rows)
    assert all(not r['cooldown'] for r in rows)
    time.sleep(1.1)
    good = post(rates, 'control', random_body('rate-after'), 'rate-after')
    assert good['accepted']
    output['ordinary_rate_rejections_do_not_escalate'] = {'burst': summary(rows), 'normal_after_refill': good}

    def verify():
        reader = base.Client(public)
        for board, count in counts.items():
            status, _, raw = reader.request('/'+board+'/dat/'+keys[board]+'.dat')
            assert status == 200 and raw.count(b'\n') == count, ('DAT', board, count, raw.count(b'\n'))
    verify()
    output['_resources'] = finish()
    subprocess.run(['docker', 'restart', '--timeout', '35', name], check=True, stdout=subprocess.DEVNULL)
    for _ in range(60):
        try:
            if shared.request('/control/')[0] == 200:
                break
        except OSError:
            pass
        time.sleep(.25)
    else:
        raise RuntimeError('restart timeout')
    restarted = post(enemies[1], 'control', random_body('restart-bad'), 'restart-bad')
    assert (restarted['cooldown']) == active
    other = post(shared, 'control', random_body('restart-shared'), 'restart-shared')
    assert other['accepted']
    output['restart'] = {'offender': restarted, 'same_ip_other_cookie': other}
    verify()
    output['verified_dat_posts'] = counts
    return output
