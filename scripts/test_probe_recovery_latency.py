"""失敗・未発行・遅い再発・短い観測を、回復成功と誤認しないことを検査する。"""
import unittest
from probe_recovery_latency import recovery_latency


class RecoveryLatencyTest(unittest.TestCase):
    def events(self):
        """秒内2件の実行予定が全件成功した判定入力を作る。"""
        return [{'scheduled_s': 17 + second + actor / 2, 'ok': True,
                 'http_ms': 40, 'scheduled_ms': 50, 'issuance_wait_ms': 0}
                for second in range(5) for actor in range(2)]

    def test_healthy_from_stop(self):
        got = recovery_latency(self.events(), 17, 5, 2)
        self.assertTrue(got['recovered'])
        self.assertEqual(got['sustained_start_ms'], 0)

    def test_requires_complete_planned_second(self):
        rows = self.events()[1:]
        got = recovery_latency(rows, 17, 5, 2)
        self.assertFalse(got['per_second'][0]['healthy'])
        self.assertEqual(got['sustained_start_ms'], 1000)

    def test_bad_seconds_restart_stability(self):
        for failure in [{'ok': False}, {'skipped': True, 'ok': False}, {'scheduled_ms': 101}]:
            rows = self.events()
            rows[2].update(failure)
            got = recovery_latency(rows, 17, 5, 2)
            self.assertEqual(got['sustained_start_ms'], 2000)
            self.assertFalse(got['per_second'][1]['healthy'])

    def test_late_regression_censors_recovery(self):
        rows = self.events()
        rows[-1]['scheduled_ms'] = 101
        got = recovery_latency(rows, 17, 5, 2)
        self.assertFalse(got['recovered'])
        self.assertIsNone(got['sustained_start_ms'])
        self.assertEqual(got['censored_at_ms'], 5000)
        self.assertEqual(got['first_healthy_streak_start_ms'], 0)
        self.assertEqual(got['late_unhealthy_seconds'], [4])

    def test_threshold_and_observation_boundary(self):
        rows = self.events()
        for row in rows:
            row['scheduled_ms'] = 100
        self.assertTrue(recovery_latency(rows, 17, 5, 2)['recovered'])
        self.assertFalse(recovery_latency(rows, 17, 2, 2)['recovered'])


class SecurityLogSummaryTest(unittest.TestCase):
    def test_counts_survive_without_samples(self):
        """保存済みの理由別件数を照合し、本文例やダミーを集計結果へ残さない。"""
        import json
        import tempfile
        from pathlib import Path
        from probe_recovery_latency import security_log_summary
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            (path / 'one.json').write_text(json.dumps({
                'a': {'source': 'waf', 'reason': 'traffic_limit', 'rejected': True, 'count': 7, 'body': 'PRIVATE'},
                'b': {'source': 'waf', 'reason': 'traffic_limit', 'rejected': True, 'count': 9, 'dummy': True}}))
            got = security_log_summary(path)
            self.assertEqual(got['reason_counts'], [{'source': 'waf', 'reason': 'traffic_limit', 'rejected': True, 'count': 7}])
            self.assertNotIn('PRIVATE', json.dumps(got))


if __name__ == '__main__':
    unittest.main()
