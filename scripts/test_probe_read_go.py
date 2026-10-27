"""Go負荷生成の非正常終了と予定到着率を測定結果へ正しく結ぶことを検査する。"""
import json
import pathlib
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from probe_read_go import load_go


class GoReadingProbeTests(unittest.TestCase):
    def probe(self):
        states = iter([{"at": 1, "cpu_usec": 100, "memory_bytes": 1000},
                       {"at": 2, "cpu_usec": 1100, "memory_bytes": 1000}])

        def counters(_):
            return {**dict.fromkeys(("rbytes", "wbytes", "rios", "wios", "throttled_usec", "oom_kill"), 0), **next(states)}

        return SimpleNamespace(port=8443, certificate="/isolated/ca.pem", cgroup="isolated", samples=[],
                               read_counters=counters, go_read_client="isolated-readload", read_rate=1500,
                               request=lambda *a, **k: (200, {"etag": '"v"'}, b"public", 1))

    def test_rate_and_process_failure_are_retained(self):
        def run(args, **kwargs):
            config = json.loads(pathlib.Path(args[-1]).read_text())
            self.assertEqual(config["rate"], 1500)
            self.assertEqual(config["body_bytes"], 6)
            self.assertEqual(config["response_headers"]["etag"], '"v"')
            return SimpleNamespace(stdout=json.dumps({"requests": 10, "errors": 0, "p95_ms": 1}), returncode=1)

        with patch("probe_read_go.subprocess.run", side_effect=run):
            result = load_go(self.probe(), "test", "/probe", {}, 200, b"public", 10)
        self.assertEqual((result["errors"], result["go_exit_code"]), (1, 1))
        self.assertEqual(result["server_cpu_us_per_request"], 100)

    def test_bad_fixture_stops_before_go(self):
        with patch("probe_read_go.subprocess.run") as run:
            with self.assertRaisesRegex(RuntimeError, "fixture mismatch"):
                load_go(self.probe(), "test", "/probe", {}, 200, b"wrong", 10)
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
