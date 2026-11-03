"""隔離HTTPSだけで攻撃を混ぜ、正常投稿・早期拒否・保存整合性と回復を照合する。"""
import concurrent.futures
import hashlib
import http.client
import re
import socket
import threading
import time
import urllib.parse
from types import SimpleNamespace

from probe_peak_mix import contend_file, quantile, web_post
from probe_posting_capacity import summarize, verify
from probe_recovery_latency import recovery_latency

NORMAL_RATE = 10
FLOOD_RATE = 100
FLOOD_WORKERS = 8
TLS_CHURN_RATE = 400
TLS_CHURN_WORKERS = 16
PHASES = (("normal", 5), ("attack", 12), ("recovery", 5))
SLOW_BODY_COUNT = 16
SLOW_HEADER_COUNT = 64
EARLY_REJECTION_MS = 1000


def fields(number, key, namespace):
    """通常投稿と同じ構文の一意な本文と要求IDを生成する。"""
    unique = hashlib.sha256(f"{namespace}:{number}".encode()).hexdigest()
    return {"bbs": "probe", "key": key, "FROM": "性能試験", "mail": "sage",
            "MESSAGE": f"ダミー返信 {number} 攻撃混在の保存照合 {unique}",
            "oimo_request_id": f"{namespace}-{number:08d}"}


def connection(probe, ip):
    """割り当て済みの隔離loopback TLSポートだけへ接続する。"""
    if not 1 <= probe.port <= 65535 or not ip.startswith("127."):
        raise ValueError("attack probe requires an isolated loopback endpoint")
    return http.client.HTTPSConnection("127.0.0.1", probe.port, context=probe.context,
                                      source_address=(ip, 0), timeout=15)


def prepare(probe, normal_rate):
    """指定数の正常主体と攻撃専用の主体を確認し、準備投稿を負荷区間から除く。"""
    keys, expected, prefixes, actors = [], {}, {}, []
    for index in range(5):
        probe.actor(100 + index)
        key, _ = probe.post(900000 + index, namespace="attack-seed", verify_number=False)
        keys.append(key)
        expected[key] = [900000 + index]
        time.sleep(.1)
    for index in range(normal_rate):
        probe.actor(index)
        key, number = keys[index % 4], 100000 + index
        if index % 5 == 4:
            web_post(probe, number, key, "attack-normal-warm", verify_number=False)
        else:
            probe.post(number, key, "attack-normal-warm", verify_number=False)
        actors.append(probe.local.state)
        expected[key].append(number)
        time.sleep(.1)
    probe.local.state = SimpleNamespace(connection=connection(probe, "127.250.0.1"))
    probe.post(200000, keys[4], "attack-flood-warm", verify_number=False)
    expected[keys[4]].append(200000)
    attacker_cookies = dict(probe.local.state.cookies)
    probe.local.state.connection.close()
    probe.actor(999)
    for key in keys:
        code, headers, raw, _ = probe.request("GET", f"/probe/dat/{key}.dat", headers={"Accept-Encoding": "identity"})
        if code != 200 or headers.get("content-encoding"):
            raise RuntimeError("attack fixture DAT unavailable")
        prefixes[key] = raw
    return keys, expected, prefixes, actors, attacker_cookies


def normal_post(probe, number, key, kind):
    """応答番号を固定しない実投稿を行い、WebはCSRFとgzip遷移先まで通す。"""
    if kind == "web":
        return web_post(probe, number, key, "attack-normal", verify_number=False)
    return probe.post(number, key, "attack-normal", verify_number=False)[1]


def slow_request(probe, kind, index):
    """本文またはヘッダー末尾を送らず、応答・切断・タイムアウトを別々に記録する。"""
    ip = "127.249.0.1" if kind == "slow_body" else "127.248.0.1"
    conn = connection(probe, ip)
    started = time.monotonic()
    row = {"kind": kind, "index": index, "status": None, "timeout": False, "acknowledged": False, "sent": False}
    try:
        conn.connect()
        conn.sock.settimeout(13)
        raw = (f"POST /test/bbs.cgi HTTP/1.1\r\nHost: 127.0.0.1:{probe.port}\r\n"
               "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 65536\r\n")
        if kind == "slow_body":
            raw += "\r\n"
        else:
            raw += "X-Partial: "
        sent = time.monotonic()
        conn.sock.sendall(raw.encode("ascii"))
        row["sent"] = True
        response = http.client.HTTPResponse(conn.sock)
        response.begin()
        row["status"] = response.status
        row["header_ms"] = (time.monotonic() - sent) * 1000
        body = response.read()
        row["acknowledged"] = bool(re.search(rb"/test/read.cgi/probe/[0-9]+/[0-9]+", body))
        response.close()
    except (socket.timeout, TimeoutError):
        row["timeout"] = True
    except (OSError, http.client.HTTPException) as error:
        row["connection_end"] = type(error).__name__
    finally:
        conn.close()
    row["elapsed_ms"] = (time.monotonic() - started) * 1000
    return row


def slow_wave(probe, kind, count):
    """有限個の接続だけを作り、全ソケットを閉じてから戻る。"""
    with concurrent.futures.ThreadPoolExecutor(max_workers=count) as pool:
        return list(pool.map(lambda index: slow_request(probe, kind, index), range(count)))


def tls_churn(probe, attack_begin, attack_time):
    """隔離サイトへ同一IPから毎秒400回、12秒だけTLSを作り直し、未発行・切断・期限を分ける。"""
    def worker(number):
        """固定予定でTLS確立直後に閉じ、拒否時も同じ予定を維持する。"""
        events = []
        attack_begin.wait()
        started = attack_time()
        for index in range(number, TLS_CHURN_RATE * 12, TLS_CHURN_WORKERS):
            target = started + index / TLS_CHURN_RATE
            time.sleep(max(0, target - time.monotonic()))
            row = {"kind": "tls_churn", "index": index, "tls_connected": False, "timeout": False}
            begin = time.monotonic()
            if begin > target + .5:
                row["skipped"] = True
                events.append(row)
                continue
            conn = connection(probe, "127.247.0.1")
            conn.timeout = 2
            try:
                conn.connect()
                row["tls_connected"] = True
            except (socket.timeout, TimeoutError):
                row["timeout"] = True
            except (OSError, http.client.HTTPException) as error:
                row["connection_end"] = type(error).__name__
            finally:
                conn.close()
            row["elapsed_ms"] = (time.monotonic() - begin) * 1000
            events.append(row)
        return events

    with concurrent.futures.ThreadPoolExecutor(max_workers=TLS_CHURN_WORKERS) as pool:
        rows = [row for part in pool.map(worker, range(TLS_CHURN_WORKERS)) for row in part]
    return sorted(rows, key=lambda row: row["index"])


def tls_churn_summary(rows):
    """TLSの成功・接続終了・期限超過を区別し、失敗をHTTP429へ数えない。"""
    sent = [row for row in rows if not row.get("skipped")]
    errors = sorted({row["connection_end"] for row in sent if "connection_end" in row})
    return {"planned": len(rows), "sent": len(sent), "skipped": len(rows) - len(sent),
            "tls_connected": sum(row["tls_connected"] for row in sent),
            "timeouts": sum(row["timeout"] for row in sent),
            "connection_end": {name: sum(row.get("connection_end") == name for row in sent) for name in errors}}


def attack_summary(events):
    """HTTP拒否と接続切断を分け、200のエラー画面を投稿成功へ数えない。"""
    sent = [row for row in events if not row.get("skipped") and row.get("sent", True)]
    body_rejections = [row for row in sent if row.get("kind") == "slow_body" and row.get("status") == 429]
    rejections = [row for row in sent if row.get("kind") == "slow_body" and row.get("status") in (429, 503)]
    statuses = sorted({str(row.get("status")) for row in sent})
    return {"planned": len(events), "sent": len(sent), "skipped": len(events) - len(sent),
            "acknowledged": sum(row.get("acknowledged", False) for row in sent),
            "status": {status: sum(str(row.get("status")) == status for row in sent) for status in statuses},
            "timeouts": sum(row.get("timeout", False) for row in sent),
            "early_429": sum(row.get("header_ms", float("inf")) <= EARLY_REJECTION_MS for row in body_rejections),
            "slow_429": sum(row.get("header_ms", float("inf")) > EARLY_REJECTION_MS for row in body_rejections),
            "early_rejections": sum(row.get("header_ms", float("inf")) <= EARLY_REJECTION_MS for row in rejections),
            "slow_rejections": sum(row.get("header_ms", float("inf")) > EARLY_REJECTION_MS for row in rejections),
            "max_elapsed_ms": max((row["elapsed_ms"] for row in sent if "elapsed_ms" in row), default=None)}


def acceptance(normal, attacks, integrity, resources, flood_limit=155):
    """全予定の正常投稿と保存を要求し、本文未送信の429も一秒以内であることを要求する。"""
    checks = {"normal_posts": normal["success"] == normal["planned"] and normal["errors"] == 0 and normal["skipped"] == 0,
              "normal_latency": normal["scheduled_p95_ms"] is not None and normal["scheduled_p95_ms"] <= 1000,
              "integrity": integrity["ok"], "no_oom": resources["oom_kill_delta"] == 0,
              "flood_limited": attacks["valid_flood"]["status"].get("429", 0) > 0 and attacks["valid_flood"]["acknowledged"] <= flood_limit,
              "flood_supplied": attacks["valid_flood"]["sent"] >= .95 * attacks["valid_flood"]["planned"],
              "slow_rejection": attacks["slow_body"]["early_rejections"] >= SLOW_BODY_COUNT // 2 and attacks["slow_body"]["slow_rejections"] == 0,
              "slow_closed": all(attacks[k]["sent"] == attacks[k]["planned"] == count and attacks[k]["timeouts"] == 0 and attacks[k]["acknowledged"] == 0 for k, count in (("slow_body", SLOW_BODY_COUNT), ("slow_header", SLOW_HEADER_COUNT)))}
    if "tls_churn" in attacks:
        churn = attacks["tls_churn"]
        checks.update(tls_churn_supplied=churn["sent"] >= .95 * TLS_CHURN_RATE * 12,
                      tls_churn_limited=churn["tls_connected"] <= 64 + 16 * 12.5,
                      tls_churn_no_timeout=churn["timeouts"] == 0)
    return checks


def contend_io(probe, started):
    """攻撃区間だけ別の一時ファイルを同期し、発行量と遅延を記録する。"""
    path = getattr(probe, "io_contention_path", None)
    if path is None:
        return None
    workers = probe.io_contention_workers
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        completed = list(pool.map(lambda index: contend_file(path.with_name(path.name + f".{index}"), started + 1), range(workers)))
    latencies = [ms for _, values in completed for ms in values]
    if not latencies:
        raise RuntimeError("I/O contention issued no syncs")
    return {"scope": "isolated temporary host files, attack phase only", "workers": workers,
            "planned_syncs_per_second": 200 * workers, "bytes_per_sync": 65536,
            "completed_syncs": len(latencies), "worker_completed_syncs": [n for n, _ in completed],
            "sync_p95_ms": quantile(latencies, .95), "sync_max_ms": max(latencies)}


def verify_after_load(probe, keys, expected, prefixes, posts):
    """照合専用の接続を開き直し、読取失敗も測定結果に残す。投稿の再試行はしない。"""
    probe.local.state.connection.close()
    try:
        return verify(probe, keys, expected, prefixes, posts)
    except (OSError, http.client.HTTPException) as error:
        return {"ok": False, "read_error": type(error).__name__, "read_error_message": str(error)[:200]}


def measure(probe, counters, normal_rate=NORMAL_RATE, posting_limits=None):
    """正常5秒・攻撃混在12秒・指定した回復期間を同じ主体で実行し、全DATを照合する。"""
    keys, expected, prefixes, actors, attacker_cookies = prepare(probe, normal_rate)
    phases = (*PHASES[:2], ("recovery", getattr(probe, "attack_recovery_seconds", 5)))
    total_seconds = sum(seconds for _, seconds in phases)
    normal_events, flood_events, slow_events, phase_rows = [], [], [], []
    normal_begin, attack_begin = threading.Event(), threading.Event()
    ready = threading.Barrier(normal_rate + 1)
    started = attack_started = 0

    def poster(worker):
        """一主体一要求で予定を保持し、発行遅延とHTTP時間を別々に残す。"""
        probe.local.state = actors[worker]
        ready.wait(timeout=30)
        normal_begin.wait()
        for index in range(worker, total_seconds * normal_rate, normal_rate):
            scheduled = index // normal_rate + .1 if getattr(probe, "attack_capacity_pulse", False) else index / normal_rate
            target = started + scheduled
            time.sleep(max(0, target - time.monotonic()))
            issued = time.monotonic()
            kind = "web" if index % 5 == 4 else "legacy"
            phase = "normal" if index / normal_rate < 5 else "attack" if index / normal_rate < 17 else "recovery"
            row = {"index": index, "number": index + 1, "key": keys[index % 4], "kind": kind, "phase": phase, "scheduled_s": scheduled}
            if issued > target + 1:
                row.update(skipped=True, ok=False)
                normal_events.append(row)
                continue
            request_started = time.monotonic()
            try:
                elapsed = normal_post(probe, index + 1, row["key"], kind)
                row.update(ok=True, acknowledged=True, http_ms=elapsed, stages=list(probe.local.post_stages))
            except Exception as error:
                row.update(ok=False, error=type(error).__name__, error_message=str(error)[:200], http_ms=(time.monotonic() - request_started) * 1000,
                           acknowledged=any(s.get("acknowledged", False) for s in getattr(probe.local, "post_stages", [])))
                row["stages"] = getattr(probe.local, "post_stages", [])
                probe.local.state.connection.close()
            row.update(issued_s=issued - started, done_s=time.monotonic() - started, scheduled_ms=(time.monotonic() - target) * 1000, issuance_wait_ms=(issued - target) * 1000)
            normal_events.append(row)

    def flood(worker):
        """確認済みの同じ攻撃主体から、正規形式の固有投稿を上限100要求/秒で発行する。"""
        state = SimpleNamespace(connection=connection(probe, "127.250.0.1"), cookies=dict(attacker_cookies))
        probe.local.state = state
        if getattr(probe, "attack_capacity_pulse", False):
            state.upload_pause_seconds = .25
        attack_begin.wait()
        for index in range(worker, FLOOD_RATE * 12, FLOOD_WORKERS):
            target = attack_started + index / FLOOD_RATE
            time.sleep(max(0, target - time.monotonic()))
            number = 1000000 + index
            row = {"kind": "valid_flood", "index": index, "number": number, "key": keys[4]}
            if time.monotonic() > target + .5:
                row.update(skipped=True, ok=False)
                flood_events.append(row)
                continue
            begin = time.monotonic()
            try:
                status, headers, body, elapsed = probe.request("POST", "/test/bbs.cgi", urllib.parse.urlencode(fields(number, keys[4], "attack-valid")).encode(),
                                                               {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"})
                ack = status == 200 and bool(re.search(rb"/test/read.cgi/probe/[0-9]+/[0-9]+", body))
                row.update(status=status, acknowledged=ack, ok=ack, http_ms=elapsed,
                           retry_after=headers.get("retry-after"), close=headers.get("connection") == "close")
            except Exception as error:
                row.update(status=None, acknowledged=False, ok=False, error=type(error).__name__)
                state.connection.close()
            row.update(issued_s=begin - started, done_s=time.monotonic() - started)
            row["elapsed_ms"] = (time.monotonic() - begin) * 1000
            flood_events.append(row)
        state.connection.close()

    def slow(kind, count):
        """攻撃区間の開始だけを待ち、固定した接続数以上を作らない。"""
        attack_begin.wait()
        return slow_wave(probe, kind, count)

    with concurrent.futures.ThreadPoolExecutor(max_workers=normal_rate + FLOOD_WORKERS + 4) as pool:
        normal_jobs = [pool.submit(poster, index) for index in range(normal_rate)]
        attack_jobs = [pool.submit(flood, index) for index in range(FLOOD_WORKERS)]
        slow_jobs = [pool.submit(slow, "slow_body", SLOW_BODY_COUNT), pool.submit(slow, "slow_header", SLOW_HEADER_COUNT)]
        churn_job = pool.submit(tls_churn, probe, attack_begin, lambda: attack_started) if getattr(probe, "attack_tls_churn", False) else None
        ready.wait(timeout=30)
        before = counters(probe.cgroup)
        started = time.monotonic()
        started_wall_ns = time.time_ns()
        contention = pool.submit(contend_io, probe, started)
        normal_begin.set()
        for name, seconds in phases:
            probe.phase = name
            begin = counters(probe.cgroup)
            if name == "attack":
                attack_started = time.monotonic()
                attack_begin.set()
            time.sleep(max(0, started + sum(n for label, n in phases[:len(phase_rows) + 1]) - time.monotonic()))
            end = counters(probe.cgroup)
            phase_rows.append({"name": name, "seconds": end["at"] - begin["at"],
                               "cpu_seconds": (end["cpu_usec"] - begin["cpu_usec"]) / 1e6,
                               "io_pressure_ms": (end["io_some_usec"] - begin["io_some_usec"]) / 1000})
        for future in normal_jobs + attack_jobs:
            future.result()
        for future in slow_jobs:
            slow_events.extend(future.result())
        churn_events = churn_job.result() if churn_job else []
        io_contention = contention.result()
        after = counters(probe.cgroup)
    probe.phase = "verification"
    normal_events.sort(key=lambda row: row["index"])
    flood_events.sort(key=lambda row: row["index"])
    integrity = verify_after_load(probe, keys, expected, prefixes, normal_events + flood_events)
    resources = {"cpu_seconds": (after["cpu_usec"] - before["cpu_usec"]) / 1e6,
                 "oom_kill_delta": after["oom_kill"] - before["oom_kill"],
                 "io_pressure_ms": (after["io_some_usec"] - before["io_some_usec"]) / 1000,
                 "write_bytes": after["wbytes"] - before["wbytes"]}
    attacks = {"valid_flood": attack_summary(flood_events),
               **{kind: attack_summary([row for row in slow_events if row["kind"] == kind]) for kind in ("slow_body", "slow_header")}}
    if churn_job:
        attacks["tls_churn"] = tls_churn_summary(churn_events)
    normal = summarize(normal_events)
    limits = posting_limits or {"client_rate": 10, "client_burst": 30}
    flood_limit = limits["client_burst"] + limits["client_rate"] * 12.5
    checks = acceptance(normal, attacks, integrity, resources, flood_limit)
    return {"scope": "isolated loopback HTTPS HTTP/1.1 and default WAF; synthetic data, no production/WAN/DDoS guarantee",
            "conditions": {"normal_posts_per_second": normal_rate, "normal_actors": normal_rate, "recovery_seconds": phases[-1][1],
                           "normal_arrivals": "one-second batch at +100ms" if getattr(probe, "attack_capacity_pulse", False) else "evenly spaced",
                           "initial_flood_upload_pause_ms": 250 if getattr(probe, "attack_capacity_pulse", False) else 0, "legacy_web_mix": "80/20",
                           "valid_flood_per_second": FLOOD_RATE, "flood_workers": FLOOD_WORKERS, "slow_body_connections": SLOW_BODY_COUNT,
                           "slow_header_connections": SLOW_HEADER_COUNT, "attacker_ips": 4 if churn_job else 3, "normal_threads": 4,
                           "tls_churn_per_second": TLS_CHURN_RATE if churn_job else 0, "tls_churn_workers": TLS_CHURN_WORKERS if churn_job else 0,
                           "early_rejection_max_ms": EARLY_REJECTION_MS, "normal_issue_lag_limit_ms": 1000, "normal_scheduled_p95_limit_ms": 1000,
                           "flood_accepted_limit": flood_limit, "minimum_flood_supply_fraction": .95},
            "timeline": {"started_wall_ns": started_wall_ns, "attack_started_s": attack_started - started,
                         "attack_planned_end_s": attack_started - started + 12,
                         "last_flood_done_s": max((r["done_s"] for r in flood_events if "done_s" in r), default=None)},
            "recovery_latency": recovery_latency(normal_events, 17, phases[-1][1], normal_rate),
            "io_contention": io_contention, "ok": all(checks.values()), "checks": checks, "normal": normal, "normal_by_phase": {name: summarize([r for r in normal_events if r["phase"] == name]) for name, _ in phases},
            "attacks": attacks, "phase_resources": phase_rows, "resources": resources, "integrity": integrity,
            "events": normal_events + flood_events + slow_events + churn_events}
