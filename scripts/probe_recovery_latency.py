"""集中終了後の復帰開始と再悪化を分け、測定末尾までの低遅延も集計する。"""
from probe_posting_capacity import summarize


def recovery_latency(events, start, seconds, rate, threshold_ms=100, minimum_stable_seconds=3):
    """全予定成功・p95上限を秒ごとに検査し、最初の連続正常区間と末尾の安定を返す。"""
    bins = []
    for second in range(seconds):
        rows = [e for e in events if start + second <= e['scheduled_s'] < start + second + 1]
        summary = summarize(rows)
        healthy = (len(rows) == rate and summary['success'] == rate and summary['errors'] == 0
                   and summary['skipped'] == 0 and summary['scheduled_p95_ms'] is not None
                   and summary['scheduled_p95_ms'] <= threshold_ms)
        bins.append({'after_stop_s': second, 'healthy': healthy, **summary})
    first_stable = next((i for i in range(seconds - minimum_stable_seconds + 1)
                         if all(row['healthy'] for row in bins[i:i + minimum_stable_seconds])), None)
    late_bad = [i for i, row in enumerate(bins) if not row['healthy'] and first_stable is not None
                and i >= first_stable + minimum_stable_seconds]
    last_bad = max((i for i, row in enumerate(bins) if not row['healthy']), default=-1)
    stable_start = last_bad + 1
    recovered = seconds - stable_start >= minimum_stable_seconds
    return {'threshold_ms': threshold_ms, 'minimum_stable_seconds': minimum_stable_seconds,
            'observed_seconds': seconds, 'recovered': recovered,
            'first_healthy_streak_start_ms': first_stable * 1000 if first_stable is not None else None,
            'late_unhealthy_seconds': late_bad,
            'sustained_start_ms': stable_start * 1000 if recovered else None,
            'censored_at_ms': None if recovered else seconds * 1000,
            'per_second': bins}


def security_log_summary(directory):
    """隔離サイトの保存済み検出ログから件数だけを返し、本文例は結果へ残さない。"""
    import json
    totals = {}
    files = sorted(directory.glob('*.json'))
    for path in files:
        for row in json.loads(path.read_text()).values():
            if row.get('dummy'):
                continue
            key = (row['source'], row['reason'], bool(row['rejected']))
            totals[key] = totals.get(key, 0) + row['count']
    return {'files': len(files), 'file_bytes': sum(p.stat().st_size for p in files), 'reason_counts': [
        {'source': source, 'reason': reason, 'rejected': rejected, 'count': count}
        for (source, reason, rejected), count in sorted(totals.items())]}
