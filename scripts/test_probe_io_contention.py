"""I/O競合生成が終了後へ負荷を持ち越さず、書込・同期エラーを隠さないことを検査する。"""
import unittest
from unittest.mock import patch

from probe_peak_mix import contend_file


class Clock:
    def __init__(self):
        self.now = 10.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class File:
    def __init__(self, clock, short=False):
        self.clock, self.short = clock, short
        self.writes, self.offsets = [], []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def seek(self, offset):
        self.offsets.append(offset)

    def write(self, data):
        self.writes.append((self.clock.now, len(data)))
        return len(data) - int(self.short)

    def fileno(self):
        return 7


class ContentionTests(unittest.TestCase):
    def test_slow_sync_stays_in_peak_and_bounded_file(self):
        clock = Clock()
        target = File(clock)

        def slow_sync(fd):
            self.assertEqual(fd, 7)
            clock.now += .012

        with patch("probe_peak_mix.time", clock), patch("builtins.open", return_value=target), patch("probe_peak_mix.os.fsync", side_effect=slow_sync):
            count, latencies = contend_file("synthetic-only", 10)
        self.assertEqual(count, len(target.writes))
        self.assertEqual(count, len(latencies))
        self.assertGreater(count, 700)
        self.assertLess(count, 1100)  # 遅れた2400予定の追い込み発行をしない。
        self.assertTrue(all(14 <= at < 26 and size == 65536 for at, size in target.writes))
        self.assertLess(max(target.offsets), 1 << 20)
        self.assertLessEqual(clock.now, 26.0121)

    def test_write_and_sync_failures_propagate(self):
        for short in (True, False):
            with self.subTest(short=short):
                clock = Clock()
                target = File(clock, short)
                with patch("probe_peak_mix.time", clock), patch("builtins.open", return_value=target), patch("probe_peak_mix.os.fsync", side_effect=OSError("synthetic sync failure")):
                    with self.assertRaises((RuntimeError, OSError)):
                        contend_file("synthetic-only", 10)


if __name__ == "__main__":
    unittest.main()
