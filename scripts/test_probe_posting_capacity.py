"""限界測定が欠落・重複・未応答保存を成功に読み替えないことを合成DATで検証する。"""
import unittest
from unittest import mock

from probe_posting_capacity import restart_and_verify, summarize, verify


def dat(*numbers):
    """製品DATと同じ区切りを使う最小の合成本文を作る。"""
    return b"".join(f"name<>sage<>date<>ダミー返信 {number} text<>title\n".encode("cp932") for number in numbers)


class DatProbe:
    """検査するDATだけを返し、ネットワークも永続データも変更しない。"""
    def __init__(self, body):
        self.body = body

    def request(self, *args, **kwargs):
        return 200, {}, self.body, 1


class CapacityEvidenceTest(unittest.TestCase):
    """測定に必要な証拠の判定を、応答数だけでは見えない異常で検証する。"""
    def test_restart_compares_bytes_and_etag_independently(self):
        for body, tag, expected in ((dat(1), '"v1"', True), (dat(2), '"v1"', False), (dat(1), '"v2"', False)):
            with self.subTest(body=body, etag=tag):
                probe = mock.Mock()
                probe.request.side_effect = [(200, {"etag": '"v1"'}, dat(1), 1),
                                             (200, {}, b"ready", 1),
                                             (200, {"etag": tag}, body, 1)]
                restart = mock.Mock()
                result = restart_and_verify(probe, ["1"], restart)
                restart.assert_called_once_with()
                self.assertEqual(result["ok"], expected)

    def test_trip_profile_checks_visible_name(self):
        probe = DatProbe(dat(1))
        probe.expected_trip = b"d75etXAowg"
        self.assertFalse(verify(probe, ["1"], {"1": [1]}, {"1": dat(1)}, [])["ok"])
        probe.body = probe.body.replace(b"name<>", b"name d75etXAowg<>")
        self.assertTrue(verify(probe, ["1"], {"1": [1]}, {"1": probe.body}, [])["ok"])

    def test_acknowledgement_is_not_dat_integrity(self):
        posts = [{"key": "1", "number": 2, "ok": True}]
        for body, field in ((dat(1), "missing_acknowledged"),
                            (dat(1, 2, 2), "duplicates"),
                            (dat(1, 2, 3), "stored_without_acknowledgement")):
            with self.subTest(field=field):
                result = verify(DatProbe(body), ["1"], {"1": [1]}, {"1": dat(1)}, posts)
                self.assertFalse(result["ok"])
                self.assertTrue(result["threads"][0][field])
        self.assertTrue(verify(DatProbe(dat(1, 2)), ["1"], {"1": [1]}, {"1": dat(1)}, posts)["ok"])

    def test_changed_old_prefix_is_rejected(self):
        result = verify(DatProbe(dat(2, 1)), ["1"], {"1": [1, 2]}, {"1": dat(1)}, [])
        self.assertFalse(result["ok"])
        self.assertFalse(result["threads"][0]["prefix_ok"])

    def test_durable_receipt_and_redirect_failure_are_separate(self):
        posts = [{"key": "1", "number": 2, "ok": False, "acknowledged": True}]
        self.assertTrue(verify(DatProbe(dat(1, 2)), ["1"], {"1": [1]}, {"1": dat(1)}, posts)["ok"])
        self.assertFalse(verify(DatProbe(dat(1)), ["1"], {"1": [1]}, {"1": dat(1)}, posts)["ok"])
        result = summarize(posts)
        self.assertEqual((result["success"], result["errors"], result["acknowledged"], result["completion_errors_after_ack"]), (0, 1, 1, 1))

    def test_unsent_and_failed_are_separate(self):
        result = summarize([{"ok": True, "scheduled_ms": 10, "http_ms": 9},
                            {"ok": False, "scheduled_ms": 800},
                            {"ok": False, "skipped": True}])
        self.assertEqual((result["planned"], result["sent"], result["success"], result["errors"], result["skipped"]),
                         (3, 2, 1, 1, 1))
        self.assertEqual(result["scheduled_p95_ms"], 800)

    def test_backpressure_read_is_retried_without_hiding_missing_posts(self):
        probe = DatProbe(dat(1, 2))
        with mock.patch.object(probe, "request", side_effect=[(503, {}, b"busy", 1), (200, {}, dat(1, 2), 1)]), mock.patch("probe_posting_capacity.time.sleep"):
            result = verify(probe, ["1"], {"1": [1]}, {"1": dat(1)}, [{"key": "1", "number": 2, "ok": True}])
        self.assertTrue(result["ok"])
        self.assertEqual(result["threads"][0]["read_attempts"], 2)

    def test_unavailable_read_is_not_reported_as_missing_acknowledgements(self):
        probe = DatProbe(b"busy")
        with mock.patch.object(probe, "request", return_value=(503, {}, b"busy", 1)), mock.patch("probe_posting_capacity.time.monotonic", side_effect=[0, 6]):
            result = verify(probe, ["1"], {"1": [1]}, {"1": dat(1)}, [{"key": "1", "number": 2, "ok": True}])
        self.assertFalse(result["ok"])
        self.assertEqual(result["unavailable_threads"], 1)
        self.assertEqual(result["threads"][0]["missing_acknowledged"], [])


if __name__ == "__main__":
    unittest.main()
