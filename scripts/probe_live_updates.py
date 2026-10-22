"""隔離サーバー上で、更新中の大きなDATへバースト状の差分取得を行う。"""
import concurrent.futures
import threading
import time


def live_updates(probe, counters):
    """600レスの確定済み版から20投稿/秒と50取得/50msを同時に走らせる。"""
    probe.phase = "live_prepare_600"
    key = ""
    preparation = time.monotonic()
    for number in range(1, 601):
        probe.actor(number % 40)
        time.sleep(max(0, preparation + (number - 1) / 40 - time.monotonic()))
        key, _ = probe.post(number, key, "live-update-probe")
    path = f"/probe/dat/{key}.dat"
    status, _, initial, _ = probe.request("GET", path, headers={"Accept-Encoding": "identity"})
    if status != 200 or initial.count(b"\n") != 600:
        raise RuntimeError("live DAT initial snapshot mismatch")
    probe.phase = "live_updates_1000_polls_20_posts_per_second"
    before = counters(probe.cgroup)
    caches = threading.local()
    lock = threading.Lock()
    confirmed = {}
    posts = {"times_ms": [], "errors": []}
    started = time.monotonic()

    def poster():
        """耐久保存の確定応答を待つ。予定時刻からの遅れも記録する。"""
        for number in range(601, 801):
            target = started + (number - 601) / 20
            time.sleep(max(0, target - time.monotonic()))
            probe.actor(number % 40)
            try:
                probe.post(number, key, "live-update-probe")
                posts["times_ms"].append((time.monotonic() - target) * 1000)
            except Exception:
                posts["errors"].append("posting failed")
                break
        posts["seconds"] = time.monotonic() - started

    def poll(index):
        """接続ごとの取得済み位置から差分を受け、最後に正本のprefixへ照合する。"""
        try:
            if not hasattr(caches, "dat"):
                caches.dat = initial
            offset = len(caches.dat) - 1
            status, headers, body, elapsed = probe.request("GET", path, headers={
                "Range": f"bytes={offset}-", "Accept-Encoding": "identity"})
            total = offset + len(body)
            good = (status == 206 and body[:1] == caches.dat[-1:]
                    and not headers.get("content-encoding")
                    and headers.get("content-range") == f"bytes {offset}-{total-1}/{total}")
            caches.dat += body[1:]
            with lock:
                confirmed[threading.get_ident()] = caches.dat
            scheduled = (time.monotonic() - started - (index // 50) * .05) * 1000
            return good, len(body), elapsed, scheduled
        except Exception:
            return False, 0, 0, 0

    posting = threading.Thread(target=poster)
    posting.start()
    lag = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
        futures = []
        for batch in range(200):
            target = started + batch * .05
            time.sleep(max(0, target - time.monotonic()))
            lag.append(max(0, time.monotonic() - target) * 1000)
            futures.extend(pool.submit(poll, batch * 50 + j) for j in range(50))
        outcomes = [future.result() for future in futures]
    posting.join()
    duration = time.monotonic() - started
    after = counters(probe.cgroup)
    status, _, final, _ = probe.request("GET", path, headers={"Accept-Encoding": "identity"})
    wrong = sum(not final.startswith(dat) for dat in confirmed.values())
    elapsed = sorted(item[2] for item in outcomes)
    scheduled = sorted(item[3] for item in outcomes)
    result = {"name": probe.phase, "requests": len(outcomes), "workers": 64,
              "burst_requests": 50, "burst_interval_ms": 50, "seconds": duration,
              "requests_per_second": len(outcomes) / duration,
              "rate_scope": "requests per whole phase, including posting drain",
              "errors": sum(not item[0] for item in outcomes) + wrong,
              "body_bytes": sum(item[1] for item in outcomes),
              "http_p95_ms": elapsed[int(len(elapsed) * .95)],
              "p95_ms": scheduled[int(len(scheduled) * .95)],
              "generator_max_lag_ms": max(lag), "posting_count": len(posts["times_ms"]),
              "posting_errors": posts["errors"], "posting_seconds": posts["seconds"],
              "posting_scheduled_p95_ms": sorted(posts["times_ms"])[int(len(posts["times_ms"]) * .95)] if posts["times_ms"] else None,
              "initial_dat_bytes": len(initial), "final_dat_bytes": len(final),
              "final_lines": final.count(b"\n"),
              "cpu_cores_average": (after["cpu_usec"] - before["cpu_usec"]) / duration / 1e6,
              **{k + "_delta": after[k] - before[k] for k in ("rbytes", "wbytes", "rios", "wios", "throttled_usec", "oom_kill")}}
    if status != 200 or result["final_lines"] != 800 or result["errors"] or posts["errors"]:
        raise RuntimeError("live update verification failed")
    return result
