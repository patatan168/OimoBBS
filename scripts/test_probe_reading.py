"""閲覧測定の検証子・差分位置と、fixture不一致時の中止を検査する。"""
import unittest

from probe_reading import reading_phases


class FakeProbe:
    def __init__(self, mismatch=False):
        self.calls = []
        self.mismatch = mismatch

    def request(self, method, path, headers):
        body = b"first\nlast\n" if "/dat/" in path else b"public"
        if self.mismatch and "/dat/" in path:
            body = b"wrong"
        return 200, {"etag": '"version"'}, body, 1

    def load(self, name, path, headers, status, body, requests):
        self.calls.append((name, path, headers, status, body, requests))
        return {"name": name}


class ReadingProbeTests(unittest.TestCase):
    def test_revalidation_and_delta_inputs(self):
        probe = FakeProbe()
        phases = reading_phases(probe, "123", b"first\nlast\n", 100)
        self.assertEqual(len(phases), 20)
        for name, _, headers, status, body, count in probe.calls:
            self.assertEqual(count, 100)
            if name.endswith("_304"):
                self.assertEqual((status, body, headers["If-None-Match"]), (304, b"", '"version"'))
            if name == "dat_delta_last_post":
                self.assertEqual((headers["Range"], status, body), ("bytes=6-", 206, b"last\n"))
            if name == "dat_delta_unchanged":
                self.assertEqual((headers["Range"], status, body), ("bytes=10-", 206, b"\n"))

    def test_invalid_fixture_stops_before_load(self):
        probe = FakeProbe(mismatch=True)
        with self.assertRaisesRegex(RuntimeError, "fixture mismatch"):
            reading_phases(probe, "123", b"first\nlast\n", 100)
        self.assertEqual(probe.calls, [])

    def test_selected_paths(self):
        probe = FakeProbe()
        phases = reading_phases(probe, "123", b"first\nlast\n", 100, ["html", "subject"])
        self.assertEqual(len(phases), 12)
        self.assertTrue(all(not item[0].startswith("dat_") for item in probe.calls))

    def test_selected_cases_and_typos(self):
        probe = FakeProbe()
        result = reading_phases(probe, "123", b"first\nlast\n", 100, cases=["dat_identity_304"])
        self.assertEqual([p["name"] for p in result], ["dat_identity_304"])
        with self.assertRaisesRegex(ValueError, "invalid reading case"):
            reading_phases(probe, "123", b"first\nlast\n", 100, cases=["typo"])


if __name__ == "__main__":
    unittest.main()
