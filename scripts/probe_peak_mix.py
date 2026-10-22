"""専ブラ80%・Web20%の有界混合負荷で、指定した送信予算の飽和中と直後を比較する。"""
import collections
import concurrent.futures
import html.parser
import math
import os
import re
import threading
import time
import urllib.parse


class Fields(html.parser.HTMLParser):
    """実フォームのhidden値だけを抽出し、CSRFを製品入口へそのまま渡す。"""
    def __init__(self, raw):
        super().__init__()
        self.values = {}
        self.feed(raw.decode())

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "input" and values.get("type") == "hidden":
            self.values[values["name"]] = values.get("value", "")


def web_post(probe, number, key, namespace, verify_number=True, coding="gzip"):
    """フォーム表示・確認Cookie・CSRF検証・303と遷移先閲覧まで実行する。"""
    started = time.monotonic()
    stages = []
    probe.local.post_stages = stages
    route = "/web/post?bbs=probe&key=" + key
    code, _, page, ms = probe.request("GET", route)
    stages.append({"stage": "form", "http_ms": ms})
    if code != 200:
        raise RuntimeError("web form unavailable")
    fields = Fields(page).values
    fields.update({"FROM": getattr(probe, "posting_name", "性能試験"), "mail": "sage", "MESSAGE": f"Web混合負荷 {namespace} {number}",
                   "oimo_request_id": f"{namespace}-{number:08d}"})
    headers = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
               "Origin": f"https://127.0.0.1:{probe.port}", "Sec-Fetch-Site": "same-origin"}
    for _ in range(3):
        code, received, page, ms = probe.request("POST", route, urllib.parse.urlencode(fields).encode(), headers)
        stages.append({"stage": "submit" if code == 303 else "confirmation", "http_ms": ms})
        if code == 303:
            location = urllib.parse.urlsplit(received["location"])
            match = re.fullmatch(r"/test/read.cgi/probe/(\d+)/l50", location.path)
            if not match or match[1] != key:
                raise RuntimeError("web receipt mismatch")
            stages[-1]["acknowledged"] = True
            allowed = "identity" if coding == "identity" else coding + ",identity;q=0"
            code, received, page, ms = probe.request("GET", location.path, headers={"Accept-Encoding": allowed})
            stages.append({"stage": "redirect", "http_ms": ms})
            from codec_probe_decode import decode
            page = decode(received.get("content-encoding"), page)
            expected_coding = None if coding == "identity" else coding
            if code != 200 or received.get("content-encoding") != expected_coding or b'<main' not in page:
                raise RuntimeError("web redirect unavailable")
            if verify_number and f'<article id="{number}">'.encode() not in page:
                raise RuntimeError("web reply missing from latest 50")
            return (time.monotonic() - started) * 1000
        if code != 200 or "書き込み確認" not in page.decode():
            raise RuntimeError(f"web post rejected: {code}")
        fields = Fields(page).values
    raise RuntimeError("web confirmation did not finish")


def quantile(values, fraction):
    """nearest-rankで分位値を返し、標本なしはnullにする。"""
    return sorted(values)[max(0, math.ceil(len(values) * fraction) - 1)] if values else None


def peak_mix(probe, key, raw, headers, peak_polls=2000, full_every=10, post_workers=1, capacity_workers=5, full_coding="identity", full_conditional=False, web_coding="gzip", capacity_during_load=False, capacity_enabled=True):
    """固定40読者・一主体一要求で予定を保持し、待ちによる未発行も集計する。"""
    active, _ = probe.post(1, "", "peakmix-create")
    _, _, initial, _ = probe.request("GET", f"/probe/dat/{active}.dat", headers={"Accept-Encoding": "identity"})
    rows, posts, caches = [], [], {}
    stages = [("normal", 4, 200), ("peak", 12, peak_polls), ("recovery", 5, 200)]
    started = time.monotonic()
    limits = []
    elapsed = 0
    for name, seconds, rate in stages:
        limits.append((name, elapsed, elapsed + seconds, rate))
        elapsed += seconds
    lock = threading.Lock()
    ready, begin_load, begin_capacity = threading.Event(), threading.Event(), threading.Event()
    capacity = {}
    contention = {}

    def poster():
        """40主体から20投稿/秒を計画し、専ブラ4件ごとにWeb1件を投稿する。"""
        try:
            for index in range(40):
                probe.actor(index)
                if index % 5 == 4:
                    web_post(probe, index + 2, active, "peakmix-warm-web", coding=web_coding)
                else:
                    probe.post(index + 2, active, "peakmix-warm-legacy")
        except Exception as error:
            capacity["warm_error"] = type(error).__name__
            ready.set()
            return
        ready.set()
        begin_load.wait()
        warmed_actors = [probe.local.actors[index] for index in range(40)]

        def planned_post(index):
            """固定予定で投稿し、並行時は重複しない確認済み主体を使う。"""
            target = started + index / 20
            time.sleep(max(0, target - time.monotonic()))
            probe.local.state = warmed_actors[index % (20 if capacity_during_load else 40)]
            number = index + 42
            kind = "web" if index % 5 == 4 else "legacy"
            phase = next(name for name, begin, end, _ in limits if begin <= index / 20 < end)
            issued = time.monotonic()
            try:
                if kind == "web":
                    ms = web_post(probe, number, active, "peakmix-web", verify_number=post_workers == 1, coding=web_coding)
                else:
                    _, ms = probe.post(number, active, "peakmix-legacy", verify_number=post_workers == 1)
                posts.append({"kind": kind, "phase": phase, "number": number, "ok": True, "http_ms": ms,
                              "scheduled_ms": (time.monotonic() - target) * 1000,
                              "issuance_wait_ms": max(0, issued - target) * 1000,
                              "stages": list(probe.local.post_stages),
                              "started_s": index / 20, "done_s": time.monotonic() - started})
            except Exception as error:
                posts.append({"kind": kind, "phase": phase, "number": number, "ok": False, "error": type(error).__name__,
                              "reason": str(error).split("<", 1)[0][:120],
                              "stages": list(getattr(probe.local, "post_stages", [])),
                              "started_s": index / 20, "done_s": time.monotonic() - started})

        def planned_worker(worker):
            """主体群を5分割し、一主体の同時投稿と予定の無制限投入を避ける。"""
            for index in range(worker, elapsed * 20, post_workers):
                planned_post(index)

        def measure_capacity():
            """ピーク中または回復後に、予定投稿と接続を共有しない主体で集中投稿する。"""
            if capacity_during_load:
                time.sleep(max(0, started + 6 - time.monotonic()))
            else:
                begin_capacity.wait()
            capacity_started = time.monotonic()
            actors = warmed_actors[20:] if capacity_during_load else warmed_actors

            def capacity_worker(worker):
                """確認済み主体を重複なく分割し、80%/20%の実投稿で容量を測る。"""
                outcomes = []
                kind = "web" if worker % 5 == 4 else "legacy"
                for index in range(200 // capacity_workers):
                    probe.local.state = actors[worker + (index % (len(actors) // capacity_workers)) * capacity_workers]
                    number = elapsed * 20 + 42 + worker * (200 // capacity_workers) + index
                    try:
                        if kind == "web":
                            ms = web_post(probe, number, active, "peakmix-capacity-web", verify_number=False, coding=web_coding)
                        else:
                            _, ms = probe.post(number, active, "peakmix-capacity-legacy", verify_number=False)
                        outcomes.append({"kind": kind, "ok": True, "http_ms": ms})
                    except Exception as error:
                        outcomes.append({"kind": kind, "ok": False, "error": type(error).__name__,
                                         "reason": str(error).split("<", 1)[0][:120]})
                        break
                return outcomes

            with concurrent.futures.ThreadPoolExecutor(max_workers=capacity_workers) as pool:
                outcomes = [row for batch in pool.map(capacity_worker, range(capacity_workers)) for row in batch]
            capacity_finished = time.monotonic()
            capacity.update({"seconds": capacity_finished - capacity_started, "outcomes": outcomes,
                             "started_s": capacity_started - started, "finished_s": capacity_finished - started})

        capacity_thread = None
        if capacity_enabled and capacity_during_load:
            capacity_thread = threading.Thread(target=measure_capacity)
            capacity_thread.start()
        if post_workers == 1:
            planned_worker(0)
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=post_workers) as pool:
                list(pool.map(planned_worker, range(post_workers)))

        if capacity_thread is not None:
            capacity_thread.join()
        elif capacity_enabled:
            measure_capacity()

    def reader(index):
        """更新差分は独立に連結し、Webは指定方式を展開して実HTMLを検査する。"""
        kind = "legacy" if index < 32 else "web"
        dat, count = initial, 0
        full_tag = None
        for phase, begin, end, rate in limits:
            interval = 40 / rate
            slots = int((end - begin) * rate / 40)
            slot = 0
            while slot < slots:
                scheduled_s = begin + (index + slot * 40) / rate
                target = started + scheduled_s
                time.sleep(max(0, target - time.monotonic()))
                scheduled = target
                sent_s = time.monotonic() - started
                try:
                    if kind == "web":
                        path = f"/test/read.cgi/probe/{active}/l50"
                        chosen = {"Accept-Encoding": "identity" if web_coding == "identity" else web_coding + ",identity;q=0"}
                    elif phase == "peak" and full_every and count % full_every == 0:
                        path = f"/probe/dat/{key}.dat"
                        chosen = {"Accept-Encoding": full_coding if full_coding == "identity" else full_coding + ",identity;q=0"}
                        if full_conditional and full_tag:
                            chosen["If-None-Match"] = full_tag
                    else:
                        path = f"/probe/dat/{active}.dat"
                        chosen = {"Accept-Encoding": "identity", "Range": f"bytes={len(dat)-1}-"}

                    code, received, body, ms = probe.request("GET", path, headers=chosen)
                    wire_size = len(body)
                    if kind == "web":
                        from codec_probe_decode import decode
                        body = decode(received.get("content-encoding"), body)
                        expected_coding = None if web_coding == "identity" else web_coding
                        good = code == 200 and received.get("content-encoding") == expected_coding and b'<main' in body and '隔離性能試験1000レス'.encode() in body
                    elif "Range" in chosen:
                        offset = len(dat) - 1
                        total = offset + len(body)
                        good = code == 206 and body[:1] == dat[-1:] and received.get("content-range") == f"bytes {offset}-{total-1}/{total}"
                        if good:
                            dat += body[1:]
                    else:
                        if code == 304:
                            good = full_conditional and full_tag is not None and received.get("etag") == full_tag and not body
                        else:
                            coding = received.get("content-encoding")
                            if coding:
                                from codec_probe_decode import decode
                                body = decode(coding, body)
                            good = code == 200 and body == raw and coding == (None if full_coding == "identity" else full_coding)
                            if good:
                                full_tag = received.get("etag")
                    row = {"kind": kind, "phase": phase, "ok": good, "status": code, "bytes": wire_size,
                           "mode": "web" if kind == "web" else "range" if "Range" in chosen else "full",
                           "coding": received.get("content-encoding") or "identity",
                           "http_ms": ms, "scheduled_ms": (time.monotonic() - scheduled) * 1000,
                           "started_s": scheduled_s, "sent_s": sent_s, "done_s": time.monotonic() - started}
                except Exception as error:
                    state = getattr(probe.local, "state", probe.local)
                    if hasattr(state, "connection"):
                        state.connection.close()
                        del state.connection
                    row = {"kind": kind, "phase": phase, "ok": False, "error": type(error).__name__,
                           "started_s": scheduled_s, "sent_s": sent_s}
                with lock:
                    rows.append(row)
                count += 1
                slot += 1
                # 応答待ちの予定をためず、未発行数を明示する。
                now = time.monotonic()
                while slot < slots and started + begin + (index + slot * 40) / rate < now:
                    with lock:
                        rows.append({"kind": kind, "phase": phase, "skipped": True, "ok": False,
                                     "started_s": begin + (index + slot * 40) / rate})
                    slot += 1
        caches[index] = dat

    posting = threading.Thread(target=poster)
    posting.start()
    ready.wait(60)
    if not ready.is_set() or "warm_error" in capacity:
        raise RuntimeError("posting warmup failed: " + str(capacity))
    started = time.monotonic()
    def contend_io():
        """専用一時ファイルだけに64KiB/5msの同期を計画し、ピーク区間のI/O競合を再現する。"""
        path = getattr(probe, "io_contention_path", None)
        if path is None:
            return
        workers = getattr(probe, "io_contention_workers", 1)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            completed = list(pool.map(lambda index: contend_file(path if workers == 1 else path.with_name(path.name + f".{index}"), started), range(workers)))
        latencies = [ms for _, values in completed for ms in values]
        contention.update({"scope": "separate temporary files on host storage, peak only",
                           "workers": workers, "planned_syncs_per_second": 200 * workers,
                           "bytes_per_sync": 65536, "completed_syncs": len(latencies),
                           "worker_completed_syncs": [count for count, _ in completed],
                           "sync_p95_ms": quantile(latencies, .95),
                           "finished_load_s": time.monotonic() - started})
    def checked_contention():
        """負荷生成の失敗を測定成功に読み替えず、結果へ伝える。"""
        try:
            contend_io()
        except Exception as error:
            contention["error"] = type(error).__name__
    io_thread = threading.Thread(target=checked_contention)
    io_thread.start()
    begin_load.set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=40) as pool:
        list(pool.map(reader, range(40)))
    begin_capacity.set()
    posting.join()
    io_thread.join()
    if "error" in contention:
        raise RuntimeError("I/O contention generator failed: " + contention["error"])
    _, _, final, _ = probe.request("GET", f"/probe/dat/{active}.dat", headers={"Accept-Encoding": "identity"})
    bad_prefixes = sum(not final.startswith(dat) for dat in caches.values())
    # 受理件数だけでなく、生成器の独立した連番が各一度だけ保存されたことを検査する。
    saved_numbers = []
    invalid_post_bodies = 0
    for line in final.splitlines():
        fields = line.split(b"<>")
        body = fields[3].decode("cp932") if len(fields) == 5 else ""
        match = re.match(r"(?:ダミー返信 |Web混合負荷 \S+ )(\d+)\b", body)
        if not match:
            invalid_post_bodies += 1
            continue
        saved_numbers.append(int(match[1]))
    extra_posts = 200 if capacity_enabled else 0
    expected_numbers = set(range(1, elapsed * 20 + 42 + extra_posts))
    number_counts = collections.Counter(saved_numbers)
    missing_numbers = sorted(expected_numbers - number_counts.keys())
    unexpected_numbers = sorted(number_counts.keys() - expected_numbers)
    duplicate_numbers = sorted(number for number, count in number_counts.items() if count != 1)
    numbers_match = not (missing_numbers or unexpected_numbers or duplicate_numbers or invalid_post_bodies)

    def summary(items, seconds):
        """成功分と失敗/未発行を分離し、予定起点とHTTP起点の双方を返す。"""
        accepted = [v for v in items if v.get("ok")]
        sent = [v for v in items if not v.get("skipped")]
        return {"planned": len(items), "sent": len(sent), "success": len(accepted),
                "errors": sum(not v["ok"] for v in sent), "skipped": len(items) - len(sent),
                "success_per_second": len(accepted) / seconds,
                "body_mbps": sum(v.get("bytes", 0) for v in accepted) * 8 / seconds / 1e6,
                "http_p95_ms": quantile([v["http_ms"] for v in sent if "http_ms" in v], .95),
                "scheduled_p95_ms": quantile([v["scheduled_ms"] for v in sent if "scheduled_ms" in v], .95)}

    phases = []
    for name, begin, end, rate in limits:
        phases.append({"name": name, "seconds": end - begin, "read_rate": rate,
                       **{kind: summary([v for v in rows if v["phase"] == name and v["kind"] == kind], end - begin)
                          for kind in ["legacy", "web"]},
                       "posting": {kind: summary([v for v in posts if v["phase"] == name and v["kind"] == kind], end - begin)
                                   for kind in ["legacy", "web"]}})
        for kind in ["legacy", "web"]:
            for category, events in [(kind, rows), ("posting", posts)]:
                current = phases[-1][category] if category == kind else phases[-1][category][kind]
                completed = [v for v in events if v.get("ok") and v["kind"] == kind
                             and begin <= v.get("done_s", -1) < end]
                current["completed_in_window"] = len(completed)
                current["completed_per_second"] = len(completed) / (end - begin)
                if category == kind:
                    current["completed_body_mbps"] = sum(v["bytes"] for v in completed) * 8 / (end - begin) / 1e6
    recovery = [v for v in rows if v["phase"] == "recovery"]
    recovery_seconds = []
    for second in range(5):
        recovery_seconds.append(summary([v for v in recovery if 16 + second <= v["started_s"] < 17 + second], 1))
    recovery_arrivals = [summary([v for v in rows if 16 + second <= v.get("sent_s", -1) < 17 + second], 1)
                         for second in range(5)]
    inflight = [v for v in rows if v["phase"] == "peak" and v.get("ok") and v.get("done_s", 0) > 16]
    capacity_result = summary(capacity.get("outcomes", []), capacity.get("seconds", 1))
    capacity_result["enabled"] = capacity_enabled
    capacity_result["seconds"] = capacity.get("seconds")
    capacity_result["workers"] = capacity_workers
    capacity_result["during_peak"] = capacity_during_load
    capacity_result["started_s"] = capacity.get("started_s")
    capacity_result["finished_s"] = capacity.get("finished_s")
    capacity_result["legacy_posts"] = sum(v["ok"] and v["kind"] == "legacy" for v in capacity.get("outcomes", []))
    capacity_result["web_posts"] = sum(v["ok"] and v["kind"] == "web" for v in capacity.get("outcomes", []))
    full_reads = [v for v in rows if v.get("mode") == "full"]
    return {"scope": "isolated actual server, verified TLS HTTP/1.1; resources in cpu_max/memory_max; loopback, no WAN/NIC/device proof",
            "reader_mix": {"legacy": 32, "web": 8}, "post_mix": "80% legacy / 20% Web including CSRF, confirmation and redirect",
            "posting_workers": post_workers,
            "io_contention": contention or None,
            "load_started_monotonic": started,
            "peak_legacy_full_fraction": 1 / full_every if full_every else 0,
            "peak_legacy_full_coding": full_coding,
            "web_coding": web_coding,
            "peak_legacy_full_conditional": full_conditional,
            "full_transfer": {"requests": len(full_reads), "body_bytes": sum(v["bytes"] for v in full_reads),
                              "not_modified": sum(v["status"] == 304 for v in full_reads),
                              "success": sum(v["ok"] for v in full_reads)},
            "phases": phases, "recovery_seconds": recovery_seconds,
            "recovery_actual_arrivals": recovery_arrivals,
            "peak_inflight_at_end": len(inflight),
            "last_peak_completion_delay_ms": max([(v["done_s"] - 16) * 1000 for v in inflight], default=0),
            "posting_success": sum(v["ok"] for v in posts), "posting_planned": elapsed * 20,
            "posting_drain_seconds": max((v.get("done_s", 0) for v in posts), default=0),
            "post_numbers_verified": len(saved_numbers), "post_numbers_match": numbers_match,
            "missing_post_numbers": missing_numbers,
            "acknowledged_missing_post_numbers": sorted(v["number"] for v in posts if v.get("ok") and v["number"] in missing_numbers),
            "unexpected_post_numbers": unexpected_numbers,
            "duplicate_post_numbers": duplicate_numbers, "invalid_post_bodies": invalid_post_bodies,
            "final_lines": final.count(b"\n"), "invalid_prefixes": bad_prefixes,
            "posting_capacity": capacity_result, "read_events": rows, "post_events": posts}


def contend_file(path, started):
    """独立した最大1MiBの一時ファイルだけをピーク中に上書き・同期する。"""
    operations, latencies, slot = 0, [], 0
    with open(path, "xb", buffering=0) as target:
        while slot < 2400:
            planned = started + 4 + slot * .005
            time.sleep(max(0, planned - time.monotonic()))
            if time.monotonic() >= started + 16:
                break
            before = time.monotonic()
            target.seek((operations % 16) * 65536)
            if target.write(b"\x5a" * 65536) != 65536:
                raise RuntimeError("contention write incomplete")
            os.fsync(target.fileno())
            latencies.append((time.monotonic() - before) * 1000)
            operations += 1
            slot += 1
            # 遅れた分を連続発行して終了後までI/O負荷を持ち越さない。
            while started + 4 + slot * .005 < time.monotonic():
                slot += 1
    return operations, latencies
