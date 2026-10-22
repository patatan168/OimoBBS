"""隔離HTTP投稿を固定予定・有界主体で発行し、完了処理量と未発行・拒否を分離する。"""
import collections
import concurrent.futures
import hashlib
import http.client
import re
import threading
import time

from probe_peak_mix import quantile, web_post


def summarize(events):
    """失敗を分位値から隠さず、成功数とHTTP時間・予定時刻基準の遅延を返す。"""
    sent = [row for row in events if not row.get("skipped")]
    return {"planned": len(events), "sent": len(sent),
            "success": sum(row.get("ok", False) for row in events),
            "acknowledged": sum(row.get("acknowledged", row.get("ok", False)) for row in events),
            "completion_errors_after_ack": sum(row.get("acknowledged", False) and not row.get("ok", False) for row in events),
            "errors": sum(not row.get("ok", False) for row in sent),
            "skipped": len(events) - len(sent),
            **{key + "_p95_ms": quantile([row[key + "_ms"] for row in sent if key + "_ms" in row], .95)
               for key in ("http", "scheduled", "issuance_wait")}}


def send_post(probe, kind, number, key, namespace):
    """専ブラ応答またはWebのフォーム・CSRF・303・遷移先を検証する。"""
    if kind == "web":
        return web_post(probe, number, key, namespace, verify_number=False)
    return probe.post(number, key, namespace, verify_number=False)[1]


def prepare(probe, args):
    """試験専用スレッドと確認済み主体を作り、準備投稿を測定区間から除く。"""
    keys, expected, prefixes = [], {}, {}
    for index in range(args.posting_capacity_threads):
        # スレ立てを一主体へ集中させず、準備中の連投拒否と本測定の処理能力を分ける。
        probe.actor(args.posting_capacity_workers + index)
        number = 900000 + index
        key, _ = probe.post(number, namespace="capacity-seed", verify_number=False)
        keys.append(key)
        expected[key] = [number]
        time.sleep(.1)
    actors = []
    for index in range(args.posting_capacity_workers):
        probe.actor(index)
        kind = "web" if index % 5 == 4 else "legacy"
        number, key = 100000 + index, keys[index % len(keys)]
        send_post(probe, kind, number, key, "capacity-warm")
        expected[key].append(number)
        actors.append(probe.local.state)
        time.sleep(.025 if not args.waf else .1)
    for key in keys:
        status, headers, raw, _ = probe.request("GET", f"/probe/dat/{key}.dat", headers={"Accept-Encoding": "identity"})
        if status != 200 or headers.get("content-encoding"):
            raise RuntimeError("capacity seed DAT unavailable")
        prefixes[key] = raw
    return keys, expected, prefixes, actors


def prepare_reads(probe, args):
    """並行閲覧時だけ、従来と同じ実投稿1000レスの独立した全文fixtureを作る。"""
    if not args.posting_capacity_reads:
        return None
    key = ""
    started = time.monotonic()
    for number in range(1, 1001):
        probe.actor(number % 40)
        time.sleep(max(0, started + (number - 1) / args.prepare_post_rate - time.monotonic()))
        key, _ = probe.post(number, key, "capacity-read-fixture")
    status, _, raw, _ = probe.request("GET", f"/probe/dat/{key}.dat", headers={"Accept-Encoding": "identity"})
    if status != 200 or raw.count(b"\n") != 1001:
        raise RuntimeError("capacity read fixture mismatch")
    # 測定開始時に全圧縮表現を温め、冷却時の初回作成を比較へ混ぜない。
    from codec_probe_decode import decode
    for route in (f"/probe/dat/{key}.dat", f"/test/read.cgi/probe/{key}/l50"):
        status, headers, body, _ = probe.request("GET", route, headers={"Accept-Encoding": "gzip,identity;q=0"})
        if status != 200 or not decode(headers.get("content-encoding"), body):
            raise RuntimeError("capacity read warmup mismatch")
    return key, raw


def verify(probe, keys, expected, prefixes, posts):
    """全試行番号をDATで照合し、応答済み欠落・未応答保存・重複・旧版prefixを分ける。"""
    acknowledgements = collections.defaultdict(list)
    for row in posts:
        if row.get("acknowledged", row.get("ok")):
            acknowledgements[row["key"]].append(row["number"])
    checks = []
    read_deadline = time.monotonic() + 5
    for key in keys:
        attempts = 1
        status, headers, raw, _ = probe.request("GET", f"/probe/dat/{key}.dat", headers={"Accept-Encoding": "identity"})
        # 503は本文の破損ではなく未確認。負荷終了後の読取りだけ最大5秒待ち、拒否回数も残す。
        while status == 503 and time.monotonic() < read_deadline:
            time.sleep(.1)
            attempts += 1
            status, headers, raw, _ = probe.request("GET", f"/probe/dat/{key}.dat", headers={"Accept-Encoding": "identity"})
        if status != 200:
            checks.append({"key": key, "read_status": status, "read_attempts": attempts,
                           "available": False, "lines": None, "invalid_bodies": 0,
                           "missing_acknowledged": [], "stored_without_acknowledgement": [],
                           "duplicates": [], "prefix_ok": False, "sha256": None})
            continue
        numbers, invalid, invalid_names = [], 0, 0
        for line in raw.splitlines():
            fields = line.split(b"<>")
            if getattr(probe, "expected_trip", None) and probe.expected_trip not in fields[0]:
                invalid_names += 1
            body = fields[3].decode("cp932") if len(fields) == 5 else ""
            match = re.match(r"(?:ダミー返信 |Web混合負荷 \S+ )(\d+)\b", body)
            if match:
                numbers.append(int(match[1]))
            else:
                invalid += 1
        counts = collections.Counter(numbers)
        wanted = set(expected[key] + acknowledgements[key])
        checks.append({"key": key, "read_status": status, "read_attempts": attempts,
                       "available": True, "lines": len(numbers), "invalid_bodies": invalid,
                       "invalid_names": invalid_names,
                       "missing_acknowledged": sorted(wanted - counts.keys()),
                       "stored_without_acknowledgement": sorted(counts.keys() - wanted),
                       "duplicates": sorted(n for n, count in counts.items() if count != 1),
                       "prefix_ok": status == 200 and not headers.get("content-encoding") and raw.startswith(prefixes[key]),
                       "sha256": hashlib.sha256(raw).hexdigest()})
    ok = all(row["prefix_ok"] and not any(row[field] for field in
             ("invalid_bodies", "missing_acknowledged", "stored_without_acknowledgement", "duplicates")) and not row.get("invalid_names", 0) for row in checks)
    return {"ok": ok, "threads": checks, "unavailable_threads": sum(not row["available"] for row in checks),
            "read_retries": sum(row["read_attempts"] - 1 for row in checks), "read_retry_window_seconds": 5}


def measure(probe, args, counters):
    """指定秒数の固定到着率と5秒の回復を測り、サーバーcgroupと生成器CPUを分離する。"""
    fixture = prepare_reads(probe, args)
    keys, expected, prefixes, actors = prepare(probe, args)
    rate, seconds = args.posting_capacity_rate, args.posting_capacity_seconds
    workers, read_rate = args.posting_capacity_workers, args.posting_capacity_reads
    total = rate * seconds
    posts, reads, fatal = [], [], []
    begin = threading.Event()
    ready = threading.Barrier(workers + (40 if fixture else 0) + 1)
    started = 0

    def poster(worker):
        """主体ごとに一要求だけを実行し、追いつけない予定は未発行として記録する。"""
        probe.local.state = actors[worker]
        kind = "web" if worker % 5 == 4 else "legacy"
        ready.wait(timeout=30)
        begin.wait()
        for index in range(worker, total, workers):
            target = started + index / rate
            time.sleep(max(0, target - time.monotonic()))
            issued = time.monotonic()
            thread_index = index // 750 if args.posting_capacity_distribution == "rotate" else index % len(keys)
            key = keys[thread_index]
            row = {"index": index, "number": index + 1, "key": key, "kind": kind,
                   "planned_s": index / rate, "issued_s": issued - started}
            if issued >= target + workers / rate:
                posts.append({**row, "skipped": True, "ok": False})
                continue
            try:
                ms = send_post(probe, kind, index + 1, key, "capacity-measured")
                row.update({"ok": True, "http_ms": ms})
            except Exception as error:
                row.update({"ok": False, "error": type(error).__name__, "reason": str(error)[:700]})
            done = time.monotonic()
            row["acknowledged"] = row.get("ok", False) or any(stage.get("acknowledged", False) for stage in getattr(probe.local, "post_stages", []))
            row.update({"done_s": done - started, "scheduled_ms": (done - target) * 1000,
                        "issuance_wait_ms": max(0, issued - target) * 1000,
                        "stages": list(getattr(probe.local, "post_stages", []))})
            posts.append(row)

    def reader(worker):
        """専ブラ80%の無圧縮全文とWeb20%のgzipを、固定主体の一要求ずつで読む。"""
        key, raw = fixture
        kind = "legacy" if worker < 32 else "web"
        ready.wait(timeout=30)
        begin.wait()
        for index in range(worker, read_rate * seconds, 40):
            target = started + index / read_rate
            time.sleep(max(0, target - time.monotonic()))
            if time.monotonic() >= target + 40 / read_rate:
                reads.append({"kind": kind, "ok": False, "skipped": True})
                continue
            try:
                path = f"/probe/dat/{key}.dat" if kind == "legacy" else f"/test/read.cgi/probe/{key}/l50"
                code, headers, body, ms = probe.request("GET", path, headers={"Accept-Encoding": "identity" if kind == "legacy" else "gzip,identity;q=0"})
                if kind == "legacy":
                    ok = code == 200 and not headers.get("content-encoding") and body == raw
                else:
                    from codec_probe_decode import decode
                    ok = code == 200 and headers.get("content-encoding") == "gzip" and b"<main" in decode(headers.get("content-encoding"), body)
                reads.append({"kind": kind, "ok": ok, "bytes": len(body), "http_ms": ms,
                              "done_s": time.monotonic() - started})
            except Exception as error:
                reads.append({"kind": kind, "ok": False, "error": type(error).__name__})

    def checked(function, worker):
        """主体の例外を主スレッドへ集約し、途中終了を性能限界として扱わない。"""
        try:
            function(worker)
        except Exception as error:
            fatal.append(type(error).__name__ + ": " + str(error))

    threads = [threading.Thread(target=checked, args=(poster, worker)) for worker in range(workers)]
    threads += [threading.Thread(target=checked, args=(reader, worker)) for worker in range(40) if fixture]
    for thread in threads:
        thread.start()
    ready.wait(timeout=30)
    probe.phase = "posting_capacity"
    before = counters(probe.cgroup)
    client_cpu = time.process_time()
    started = time.monotonic()
    begin.set()
    for thread in threads:
        thread.join()
    finished = time.monotonic()
    after = counters(probe.cgroup)
    generator_cpu = time.process_time() - client_cpu
    if fatal:
        raise RuntimeError("capacity generator failed: " + str(fatal))
    probe.phase = "posting_capacity_recovery"
    recovery = []
    recovery_started = time.monotonic()
    for index in range(100):
        time.sleep(max(0, recovery_started + index / 20 - time.monotonic()))
        probe.local.state = actors[index % workers]
        key = keys[index % len(keys)]
        row = {"key": key, "number": 200000 + index, "kind": "web" if index % 5 == 4 else "legacy"}
        target = recovery_started + index / 20
        try:
            ms = send_post(probe, row["kind"], row["number"], key, "capacity-recovery")
            row.update({"ok": True, "http_ms": ms})
        except Exception as error:
            row.update({"ok": False, "reason": str(error)[:700]})
        row["scheduled_ms"] = (time.monotonic() - target) * 1000
        row["acknowledged"] = row.get("ok", False) or any(stage.get("acknowledged", False) for stage in getattr(probe.local, "post_stages", []))
        recovery.append(row)
    integrity = verify(probe, keys, expected, prefixes, posts + recovery)
    summary = summarize(posts)
    in_window = [row for row in posts if row.get("ok") and row["done_s"] < seconds]
    windows = []
    for start in range(0, seconds, 5):
        end = min(start + 5, seconds)
        current = [row for row in posts if start <= row["planned_s"] < end]
        windows.append({"begin_s": start, "end_s": end, **summarize(current),
                        "completed_in_window": sum(start <= row.get("done_s", -1) < end and row.get("ok", False) for row in posts)})
    stable = (summary["success"] == total and not summary["skipped"] and not summary["errors"]
              and len(in_window) >= total * .99 and summary["scheduled_p95_ms"] <= 250
              and integrity["ok"] and all(row["ok"] for row in recovery))
    return {"scope": "isolated actual TLS HTTP/1.1, synthetic data, fsync enabled; no WAN or production capacity guarantee",
            "post_mix": "80% legacy / 20% Web including form, CSRF and redirect",
            "rate": rate, "seconds": seconds, "workers": workers, "thread_count": len(keys),
            "board_count": 1,
            "distribution": args.posting_capacity_distribution,
            "planned_reads_per_second": read_rate, "load_started_monotonic": started,
            "duration_with_drain_seconds": finished - started, "summary": summary,
            "completed_in_window": len(in_window), "completed_per_second": len(in_window) / seconds,
            "success_per_second_with_drain": summary["success"] / max(seconds, finished - started),
            "stable_at_tested_rate": stable, "stability_definition": "all planned accepted, no skips/errors, >=99% completed during window, scheduled p95 <=250ms, DAT exact and recovery100/100",
            "windows": windows, "by_kind": {kind: summarize([row for row in posts if row["kind"] == kind]) for kind in ("legacy", "web")},
            "read_summary": {**summarize(reads), "completed_body_mbps": sum(row.get("bytes", 0) for row in reads if row.get("ok") and row.get("done_s", seconds) < seconds) * 8 / seconds / 1e6},
            "recovery": summarize(recovery), "integrity": integrity,
            "resources": {"cpu_cores_average": (after["cpu_usec"] - before["cpu_usec"]) / 1e6 / (finished - started),
                          "generator_cpu_seconds": generator_cpu,
                          **{key + "_delta": after[key] - before[key] for key in ("wbytes", "wios", "oom_kill", "throttled_usec", "io_some_usec")}},
            "post_events": posts, "recovery_events": recovery, "read_events": reads}


def restart_and_verify(probe, keys, restart_server):
    """正常再起動後の全DATとETagを元byteで比較する。電源断やSIGKILLの検査ではない。"""
    snapshots = {}
    for key in keys:
        code, headers, body, _ = probe.request("GET", f"/probe/dat/{key}.dat", headers={"Accept-Encoding": "identity"})
        if code != 200 or not headers.get("etag") or headers.get("content-encoding"):
            raise RuntimeError("pre-restart DAT unavailable")
        snapshots[key] = headers["etag"], body
    started = time.monotonic()
    restart_server()
    probe.local = threading.local()
    ready = False
    while time.monotonic() - started < 60:
        try:
            if probe.request("GET", "/")[0] == 200:
                ready = True
                break
        except (OSError, http.client.HTTPException):
            probe.local = threading.local()
        time.sleep(.1)
    ready_seconds = time.monotonic() - started
    checks = []
    if ready:
        for key, (etag, expected) in snapshots.items():
            code, headers, body, _ = probe.request("GET", f"/probe/dat/{key}.dat", headers={"Accept-Encoding": "identity"})
            checks.append({"key": key, "status": code, "body_equal": code == 200 and body == expected,
                           "etag_equal": headers.get("etag") == etag, "identity": not headers.get("content-encoding")})
    return {"ok": ready and all(row["body_equal"] and row["etag_equal"] and row["identity"] for row in checks),
            "mode": "graceful container restart on the same data volume", "ready": ready,
            "ready_seconds": ready_seconds, "verification_seconds": time.monotonic() - started, "threads": checks}
