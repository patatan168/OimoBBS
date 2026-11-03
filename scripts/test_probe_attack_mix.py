"""200のエラー画面や遅延した拒否を、正常投稿・防御成功と誤認しないことを検査する。"""
import copy
import http.client
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from probe_attack_mix import acceptance, attack_summary, tls_churn_summary, verify_after_load


class AttackMixVerdictTest(unittest.TestCase):
    """予定未発行、ACK欠落、低速拒否、OOMを独立して失敗へ反映する。"""
    def fixture(self):
        """正常な判定入力を作り、各故障だけを個別に変更可能にする。"""
        normal = {"success": 440, "planned": 440, "errors": 0, "skipped": 0, "scheduled_p95_ms": 30}
        attacks = {"valid_flood": {"status": {"429": 1000}, "acknowledged": 139, "sent": 1200, "planned": 1200},
                   "slow_body": {"early_429": 8, "slow_429": 0, "early_rejections": 8, "slow_rejections": 0, "timeouts": 0, "acknowledged": 0, "sent": 16, "planned": 16},
                   "slow_header": {"timeouts": 0, "acknowledged": 0, "sent": 64, "planned": 64}}
        return normal, attacks, {"ok": True}, {"oom_kill_delta": 0}

    def test_errors_are_not_acknowledgements(self):
        """専ブラの200エラーを、投稿の成功へ数えない。"""
        got = attack_summary([{"status": 200, "acknowledged": False, "elapsed_ms": 10},
                              {"status": 200, "acknowledged": True, "elapsed_ms": 20},
                              {"skipped": True}, {"status": None, "timeout": True, "elapsed_ms": 13000}, {"sent": False}])
        self.assertEqual((got["planned"], got["sent"], got["skipped"], got["acknowledged"], got["timeouts"]), (5, 3, 2, 1, 1))

    def test_early_rejection_boundary(self):
        """本文未送信の429は、単なる最終的な拒否と区別する。"""
        got = attack_summary([{"kind": "slow_body", "status": 429, "header_ms": 1000}, {"kind": "slow_body", "status": 429, "header_ms": 1001}, {"kind": "slow_body", "status": 429}])
        self.assertEqual((got["early_429"], got["slow_429"]), (1, 2))
        got = attack_summary([{"kind": "slow_body", "status": 503, "header_ms": 500}])
        self.assertEqual((got["early_rejections"], got["slow_rejections"], got["early_429"]), (1, 0, 0))

    def test_success_requires_every_boundary(self):
        """正常投稿だけでなく、早期拒否・保存・回復・資源を全て満たす必要がある。"""
        self.assertTrue(all(acceptance(*self.fixture()).values()))
        for index, key, value in [(0, "success", 439), (0, "errors", 1), (0, "skipped", 1),
                                  (0, "scheduled_p95_ms", 1001), (2, "ok", False), (3, "oom_kill_delta", 1)]:
            args = copy.deepcopy(self.fixture())
            args[index][key] = value
            self.assertFalse(all(acceptance(*args).values()))

        for kind, key, value in [("valid_flood", "status", {}), ("slow_body", "early_rejections", 7),
                                 ("valid_flood", "acknowledged", 156), ("valid_flood", "sent", 1139),
                                 ("slow_body", "slow_rejections", 1), ("slow_body", "timeouts", 1),
                                 ("slow_header", "timeouts", 1), ("slow_body", "sent", 15), ("slow_body", "acknowledged", 1)]:
            args = copy.deepcopy(self.fixture())
            args[1][kind][key] = value
            self.assertFalse(all(acceptance(*args).values()))

    def test_tls_churn_distinguishes_connection_end_and_supply(self):
        """TLS前の切断・未発行・期限超過を分け、正常投稿と攻撃発行の両方を要求する。"""
        summary = tls_churn_summary([{"tls_connected": True, "timeout": False},
                                     {"tls_connected": False, "timeout": False, "connection_end": "SSLEOFError"},
                                     {"tls_connected": False, "timeout": True}, {"skipped": True}])
        self.assertEqual(summary, {"planned": 4, "sent": 3, "skipped": 1, "tls_connected": 1,
                                   "timeouts": 1, "connection_end": {"SSLEOFError": 1}})
        args = self.fixture()
        args[1]["tls_churn"] = {"sent": 4800, "tls_connected": 255, "timeouts": 0}
        self.assertTrue(all(acceptance(*args).values()))
        for key, value in [("sent", 4559), ("tls_connected", 265), ("timeouts", 1)]:
            changed = copy.deepcopy(args)
            changed[1]["tls_churn"][key] = value
            self.assertFalse(all(acceptance(*changed).values()))


class AttackMixVerificationTest(unittest.TestCase):
    """長い負荷後の古い接続と読取失敗で、測定結果を失わないことを検査する。"""
    def test_reopens_only_the_verification_connection(self):
        connection = Mock()
        probe = SimpleNamespace(local=SimpleNamespace(state=SimpleNamespace(connection=connection)))

        def inspect(*_):
            connection.close.assert_called_once_with()
            return {"ok": True}

        with patch("probe_attack_mix.verify", side_effect=inspect):
            self.assertEqual(verify_after_load(probe, [], {}, {}, []), {"ok": True})

    def test_read_failure_remains_an_integrity_failure(self):
        connection = Mock()
        probe = SimpleNamespace(local=SimpleNamespace(state=SimpleNamespace(connection=connection)))
        with patch("probe_attack_mix.verify", side_effect=http.client.RemoteDisconnected("closed")):
            got = verify_after_load(probe, [], {}, {}, [])
        self.assertFalse(got["ok"])
        self.assertEqual(got["read_error"], "RemoteDisconnected")


if __name__ == "__main__":
    unittest.main()
