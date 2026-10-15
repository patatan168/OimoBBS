#!/usr/bin/env python3
"""隔離Dockerで1000レスを実投稿し、HTTPS配信とcgroup資源のピークを測る。"""
import argparse
import concurrent.futures
import gzip
import hashlib
import http.client
import http.cookies
import json
import pathlib
import re
import socket
import ssl
import statistics
import subprocess
import tempfile
import threading
import time
import urllib.parse
import uuid
from types import SimpleNamespace


def command(*args):
    """ローカルコマンドを実行し、失敗時は検証を中断する。"""
    return subprocess.check_output(args, text=True).strip()


def counters(path):
    """cgroup v2のCPU・メモリ・物理I/Oを読み、取得不能を成功扱いにしない。"""
    cpu = dict(line.split() for line in (path / "cpu.stat").read_text().splitlines())
    io = {"rbytes": 0, "wbytes": 0, "rios": 0, "wios": 0}
    for line in (path / "io.stat").read_text().splitlines():
        for field in line.split()[1:]:
            key, value = field.split("=")
            if key in io:
                io[key] += int(value)
    events = dict(line.split() for line in (path / "memory.events").read_text().splitlines())
    memory = dict(line.split() for line in (path / "memory.stat").read_text().splitlines())
    pressure = {}
    for line in (path / "io.pressure").read_text().splitlines():
        fields = line.split()
        values = dict(field.split("=") for field in fields[1:])
        pressure["io_" + fields[0] + "_usec"] = int(values["total"])
    return {"at": time.monotonic(), "cpu_usec": int(cpu["usage_usec"]),
            "throttled_usec": int(cpu.get("throttled_usec", 0)),
            "memory_bytes": int((path / "memory.current").read_text()),
            "memory_anon_bytes": int(memory["anon"]),
            "memory_file_bytes": int(memory["file"]),
            "oom_kill": int(events["oom_kill"]), **io, **pressure}


class Probe:
    """指定したloopbackの隔離サイト以外へ接続しない測定クライアント。"""
    def __init__(self, port, certificate, cgroup):
        self.port = port
        self.context = ssl.create_default_context(cafile=str(certificate))
        self.local = threading.local()
        self.source_lock = threading.Lock()
        self.source_count = 0
        self.cgroup = cgroup
        self.phase = "idle"
        self.samples = []
        self.stop = threading.Event()
        self.monitor = threading.Thread(target=self.watch, daemon=True)
        self.monitor.start()

    def watch(self):
        """200ms間隔でサーバーだけの資源を記録する。"""
        while not self.stop.is_set():
            self.samples.append({"phase": self.phase, **counters(self.cgroup)})
            self.stop.wait(0.2)

    def actor(self, index):
        """準備投稿を複数主体へ分け、接続と確認Cookieを主体ごとに保持する。"""
        if not hasattr(self.local, "actors"):
            self.local.actors = {}
        if index not in self.local.actors:
            self.local.actors[index] = SimpleNamespace()
        self.local.state = self.local.actors[index]

    def request(self, method, path, body=None, headers=None):
        """接続を再利用し、gzipを展開する前の本文byteと所要時間を返す。"""
        state = getattr(self.local, "state", self.local)
        if not hasattr(state, "connection"):
            with self.source_lock:
                source = self.source_count % 200 + 1
                self.source_count += 1
            state.connection = http.client.HTTPSConnection(
                "127.0.0.1", self.port, context=self.context, timeout=30,
                source_address=(f"127.{source}.0.1", 0))
        conn = state.connection
        start = time.monotonic()
        chosen = dict(headers or {})
        cookies = getattr(state, "cookies", {})
        if cookies:
            chosen["Cookie"] = "; ".join(k + "=" + v for k, v in cookies.items())
        conn.request(method, path, body, chosen)
        response = conn.getresponse()
        data = response.read()
        for key, value in response.getheaders():
            if key.lower() == "set-cookie":
                parsed = http.cookies.SimpleCookie(value)
                for name, cookie in parsed.items():
                    if cookie["max-age"] == "0" or not cookie.value:
                        cookies.pop(name, None)
                    else:
                        cookies[name] = cookie.value
        state.cookies = cookies
        return response.status, {key.lower(): value for key, value in response.getheaders()}, data, (time.monotonic() - start) * 1000

    def post(self, number, key="", namespace="resource-probe", verify_number=True):
        """確認Cookieの再送を含め、実HTTP・実Syncで一件だけ確定させる。"""
        self.local.post_stages = []
        # 連番だけの高圧縮な文章にせず、一意な検証用文字列も混ぜる。
        unique = " ".join(hashlib.sha256(f"{number}:{i}".encode()).hexdigest() for i in range(5))
        fields = {"bbs": "probe", "key": key, "FROM": "性能試験", "mail": "sage",
                  "MESSAGE": f"ダミー返信 {number} >>{max(1, number - 1)} 本文とURLの確認 https://example.invalid/{number} {unique}",
                  "oimo_request_id": f"{namespace}-{number:08d}"}
        if not key:
            fields["subject"] = "隔離性能試験1000レス"
        body = urllib.parse.urlencode(fields).encode()
        headers = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}
        elapsed = 0
        for _ in range(3):
            status, received, data, part = self.request("POST", "/test/bbs.cgi", body, headers)
            elapsed += part
            self.local.post_stages.append({"stage": "confirmation" if b"2ch_X:cookie" in data else "submit", "http_ms": part})
            if b"2ch_X:cookie" not in data:
                break
        page = data.decode("cp932")
        match = re.search(r"/test/read.cgi/probe/(\d+)/(\d+)", page)
        if status != 200 or not match or key and match[1] != key or verify_number and int(match[2]) != number:
            raise RuntimeError(f"post {number} failed: HTTP {status}: {page[:500]}")
        return match[1], elapsed

    def load(self, name, path, headers, expected_status, expected_body, requests=2000, workers=32, rate=0, variants=None):
        """有界並列の集中取得を行い、拒否・破損・生成側CPU時間も記録する。"""
        self.phase = name
        before = counters(self.cgroup)
        started = time.monotonic()
        client_cpu = time.process_time()

        def one(index):
            try:
                chosen, want_status, want_body = variants[index % len(variants)] if variants else (headers, expected_status, expected_body)
                status, received, body, elapsed = self.request("GET", path, headers=chosen)
                coding = received.get("content-encoding")
                if coding == "zstd":
                    from codec_probe_decode import decode
                    decoded = decode(coding, body)
                else:
                    decoded = gzip.decompress(body) if coding == "gzip" else body
                correct = status == want_status and decoded == want_body
                if chosen.get("Accept-Encoding", "").endswith(",identity;q=0"):
                    correct = correct and received.get("content-encoding") == chosen["Accept-Encoding"].split(",", 1)[0]
                if want_status == 206:
                    begin = int(chosen["Range"].removeprefix("bytes=").removesuffix("-"))
                    correct = correct and not received.get("content-encoding") and received.get("content-range") == f"bytes {begin}-{begin + len(body) - 1}/{self.dat_size}"
                wire_elapsed = elapsed
                if rate:
                    elapsed = (time.monotonic() - started - index / rate) * 1000
                return status, len(body), elapsed, correct, wire_elapsed
            except Exception:
                return 0, 0, 0, False, 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            if rate:
                futures = []
                lag_ms = []
                for index in range(requests):
                    target = started + index / rate
                    time.sleep(max(0, target - time.monotonic()))
                    lag_ms.append(max(0, time.monotonic() - target) * 1000)
                    futures.append(pool.submit(one, index))
                outcomes = [future.result() for future in futures]
            else:
                outcomes = list(pool.map(one, range(requests)))
                lag_ms = []
        duration = time.monotonic() - started
        after = counters(self.cgroup)
        latencies = sorted(item[2] for item in outcomes)
        wire_latencies = sorted(item[4] for item in outcomes)
        samples = [s for s in self.samples if before["at"] <= s["at"] <= after["at"]]
        peak_cpu = max(((b["cpu_usec"] - a["cpu_usec"]) / (b["at"] - a["at"]) / 1e6
                        for a, b in zip(samples, samples[1:])), default=None)
        return {"name": name, "requests": requests, "workers": workers,
                "errors": sum(not item[3] for item in outcomes),
                "status": {str(status): sum(item[0] == status for item in outcomes)
                           for status in sorted({item[0] for item in outcomes})},
                "body_bytes": sum(item[1] for item in outcomes), "seconds": duration,
                "requests_per_second": requests / duration,
                "http_p95_ms": wire_latencies[int(len(wire_latencies) * .95)],
                "p50_ms": statistics.median(latencies), "p95_ms": latencies[int(len(latencies) * .95)],
                "cpu_cores_average": (after["cpu_usec"] - before["cpu_usec"]) / duration / 1e6,
                "cpu_cores_peak_200ms": peak_cpu,
                "memory_peak_sampled_bytes": max([before["memory_bytes"], after["memory_bytes"]] + [s["memory_bytes"] for s in samples]),
                "client_cpu_seconds": time.process_time() - client_cpu,
                "planned_requests_per_second": rate or None,
                "generator_max_lag_ms": max(lag_ms, default=0),
                **{k + "_delta": after[k] - before[k] for k in ("rbytes", "wbytes", "rios", "wios", "throttled_usec", "oom_kill")}}


def main():
    """試験用データ・秘密鍵・コンテナを作り、成否にかかわらず終了時に除去する。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="oimobbs-validation:local")
    parser.add_argument("--new-codecs", action="store_true", help="実DATと実Webスレッドの独自zstdを追加測定")
    parser.add_argument("--cpus", type=int, default=2)
    parser.add_argument("--memory", default="1g")
    parser.add_argument("--requests", type=int, default=2000)
    parser.add_argument("--egress-bps", type=int, default=80000000)
    parser.add_argument("--output", required=True)
    parser.add_argument("--optional-log-stats", action="store_true", help="正常停止後の非必須HTTPログ保存/欠測集計を追加取得")
    parser.add_argument("--live-updates", action="store_true", help="更新中の600レスから実況の差分取得バーストを追加測定")
    parser.add_argument("--peak-mix", action="store_true", help="専ブラ80%%・Web20%%の投稿併行と飽和後の回復を測定")
    parser.add_argument("--peak-polls", type=int, default=2000, help="混合ピークの予定閲覧数/秒（200〜20000、40の倍数）")
    parser.add_argument("--peak-full-every", type=int, default=10, help="専ブラのN取得ごとの全文取得。0は差分だけ")
    parser.add_argument("--peak-full-coding", choices=("identity", "gzip", "zstd"), default="identity", help="混合ピークの全文だけで許可する圧縮。差分は常にidentity")
    parser.add_argument("--peak-full-conditional", action="store_true", help="同じ全文の再取得へ保存済みETagを渡す。通常の無条件全文と別条件で比較")
    parser.add_argument("--peak-web-coding", choices=("identity", "gzip", "zstd"), default="gzip", help="混合負荷のWeb閲覧と投稿後遷移で許可する圧縮方式")
    parser.add_argument("--peak-post-workers", type=int, choices=(1, 5), default=1, help="混合負荷の投稿生成並行数（5では専ブラ4・Web1）")
    parser.add_argument("--peak-capacity-workers", type=int, choices=(5, 10, 20, 40), default=5, help="追加200投稿の容量測定並行数（専ブラ80%%・Web20%%）")
    parser.add_argument("--io-contention", action="store_true", help="混合ピーク中に専用一時ファイルを64KiB/5msで同期してI/O競合を追加")
    parser.add_argument("--save-dat", help="隔離ダミーDATだけを追加の圧縮比較用に保存する")
    args = parser.parse_args()
    if args.io_contention and not args.peak_mix:
        parser.error("io contention requires peak mix")
    if (args.peak_full_coding != "identity" or args.peak_full_conditional) and not args.peak_mix:
        parser.error("full coding/conditional comparison requires peak mix")
    if args.peak_web_coding != "gzip" and not args.peak_mix:
        parser.error("web coding comparison requires peak mix")
    if args.cpus < 1 or args.requests < 100:
        parser.error("cpus must be positive and requests must be at least 100")
    if not 200 <= args.peak_polls <= 20000 or args.peak_polls % 40 or not 0 <= args.peak_full_every <= 100:
        parser.error("invalid mixed peak request budget")
    root = pathlib.Path(__file__).resolve().parent.parent
    name = "oimobbs-resource-probe-" + uuid.uuid4().hex[:10]
    image = command("docker", "image", "inspect", args.image, "--format", "{{.Id}}")
    with tempfile.TemporaryDirectory(prefix="thread-resource-", dir=root / "var") as temporary:
        folder = pathlib.Path(temporary)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        certificate, key = folder / "cert.pem", folder / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-keyout", str(key), "-out", str(certificate), "-subj", "/CN=127.0.0.1",
                        "-addext", "subjectAltName=IP:127.0.0.1"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        config = folder / "config.json"
        config.write_text(json.dumps({"schema_version": 1, "data_dir": "/data/site",
            "public": {"listen": f"127.0.0.1:{port}", "base_url": f"https://127.0.0.1:{port}",
                       "tls_cert_file": "/tls/cert.pem", "tls_key_file": "/tls/key.pem"},
            "admin": {"listen": "127.0.0.1:19082", "transport": "loopback_tunnel", "origin": "http://127.0.0.1:19082"},
            "trusted_proxies": [], "cache_bytes": 268435456, "egress_budget_bits_per_second": args.egress_bps,
            "auto_reports": None, "maintenance": None, "edge": None}))
        # ホストの親ディレクトリは0700。直接bindしたファイルだけサービスUIDで読める。
        for file in (certificate, key, config):
            file.chmod(0o644)
        command("docker", "run", "--rm", "--network", "none", "--user", "0:0", "-v", f"{folder}:/probe",
                "--entrypoint", "/bin/sh", image, "-c", "chown 10001:10001 /probe/key.pem; chmod 600 /probe/key.pem")
        probe = None
        report_written = False
        try:
            command("docker", "run", "-d", "--name", name, "--network", "host", "--cpus", str(args.cpus),
                    "--memory", args.memory, "--memory-swap", args.memory, "--pids-limit", "128", "--read-only",
                    "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "-v", f"{name}-data:/data",
                    "--tmpfs", "/tmp:uid=10001,gid=10001,mode=0700",
                    "-v", f"{config}:/etc/oimobbs/config.json:ro", "-v", f"{certificate}:/tls/cert.pem:ro",
                    "-v", f"{key}:/tls/key.pem:ro", image,
                    "validation-serve", "--config", "/etc/oimobbs/config.json", "--init-if-missing", "--board-key", "probe")
            pid = command("docker", "inspect", name, "--format", "{{.State.Pid}}")
            if pid == "0":
                raise RuntimeError("server exited: " + command("docker", "logs", name))
            group = pathlib.Path("/sys/fs/cgroup") / pathlib.Path(f"/proc/{pid}/cgroup").read_text().split("::", 1)[1].strip().lstrip("/")
            probe = Probe(port, certificate, group)
            if args.io_contention:
                probe.io_contention_path = folder / "io-contention.bin"
            for attempt in range(100):
                try:
                    if probe.request("GET", "/")[0] == 200:
                        break
                except (OSError, http.client.HTTPException):
                    probe.local = threading.local()
                time.sleep(.1)
            else:
                raise RuntimeError("isolated server did not start")
            probe.phase = "posting_1000"
            before = counters(group)
            post_times = []
            key = ""
            for number in range(1, 1000):
                probe.actor(number % 40)
                time.sleep(max(0, before["at"] + (number - 1) / 40 - time.monotonic()))
                key, elapsed = probe.post(number, key)
                post_times.append(elapsed)
            probe.local = threading.local()
            path = f"/probe/dat/{key}.dat"
            _, _, previous, _ = probe.request("GET", path, headers={"Accept-Encoding": "identity"})
            key, elapsed = probe.post(1000, key)
            post_times.append(elapsed)
            after = counters(group)
            status, headers, raw, _ = probe.request("GET", path, headers={"Accept-Encoding": "identity"})
            # 既定設定では1000利用者レスの後に終了systemレスが一行付く。
            if status != 200 or raw.count(b"\n") != 1001 or not raw.startswith(previous):
                raise RuntimeError(f"1000-post DAT or stable prefix mismatch: HTTP {status}, lines={raw.count(bytes([10]))}")
            probe.dat_size = len(raw)
            if args.peak_mix:
                from probe_peak_mix import peak_mix
                from codec_probe_decode import decode
                full_representation_bytes = {"identity": len(raw)}
                for coding in ("gzip", "zstd"):
                    code, received, body, _ = probe.request("GET", path, headers={"Accept-Encoding": coding + ",identity;q=0"})
                    if code != 200 or received.get("content-encoding") != coding or decode(coding, body) != raw:
                        raise RuntimeError("full DAT representation mismatch")
                    full_representation_bytes[coding] = len(body)
                public_assets = {}
                for asset in ("ui.js", "ui.css"):
                    original = None
                    public_assets[asset] = {}
                    for coding in ("identity", "gzip", "zstd"):
                        code, received, body, _ = probe.request("GET", "/web/assets/" + asset, headers={"Accept-Encoding": coding})
                        decoded = decode(received.get("content-encoding"), body)
                        if code != 200 or original is not None and decoded != original:
                            raise RuntimeError("public asset representation mismatch")
                        original = decoded
                        public_assets[asset][coding] = len(body)
                result = {"image": image, "cpu_max": (group / "cpu.max").read_text().strip(),
                          "memory_max": (group / "memory.max").read_text().strip(),
                          "egress_budget_bits_per_second": args.egress_bps,
                          "dat_bytes": len(raw),
                          "fixture_sha256": hashlib.sha256(raw).hexdigest(),
                          "full_representation_bytes": full_representation_bytes,
                          "public_assets": public_assets,
                          **peak_mix(probe, key, raw, headers, args.peak_polls, args.peak_full_every, args.peak_post_workers, args.peak_capacity_workers, args.peak_full_coding, args.peak_full_conditional, args.peak_web_coding), "samples": probe.samples,
                          "memory_peak_bytes": int((group / "memory.peak").read_text()),
                          "memory_events": (group / "memory.events").read_text()}
                output = pathlib.Path(args.output)
                with output.open("x") as file:
                    json.dump(result, file, indent=2)
                output.chmod(0o600)
                report_written = True
                print(json.dumps({k: v for k, v in result.items() if k not in {"samples", "read_events", "post_events"}}, indent=2), flush=True)
                if result["posting_success"] != result["posting_planned"] or result["posting_capacity"]["success"] != 200 or result["invalid_prefixes"] or result["final_lines"] != 661 or "oom_kill 0" not in result["memory_events"] or any(p[k]["errors"] for p in result["phases"] for k in ["legacy", "web"]):
                    raise RuntimeError("mixed peak integrity failed; inspect saved report")
                return
            if args.save_dat:
                saved = pathlib.Path(args.save_dat)
                saved.write_bytes(raw)
                saved.chmod(0o600)
            status, compressed_headers, compressed, cold_ms = probe.request("GET", path, headers={"Accept-Encoding": "gzip"})
            if status != 200 or compressed_headers.get("content-encoding") != "gzip" or gzip.decompress(compressed) != raw:
                raise RuntimeError("gzip roundtrip mismatch")
            offset = len(previous) - 1
            phases = [probe.load("full_gzip_peak", path, {"Accept-Encoding": "gzip"}, 200, raw, requests=args.requests),
                      probe.load("range_one_new_post", path, {"Range": f"bytes={offset}-", "Accept-Encoding": "gzip"}, 206, raw[offset:], requests=args.requests),
                      probe.load("unchanged_etag", path, {"If-None-Match": headers["etag"], "Accept-Encoding": "identity"}, 304, b"", requests=args.requests),
                      probe.load("unchanged_range", path, {"Range": f"bytes={len(raw)-1}-", "Accept-Encoding": "identity"}, 206, raw[-1:], requests=args.requests),
                      probe.load("full_identity_peak", path, {"Accept-Encoding": "identity"}, 200, raw, requests=args.requests // 4)]
            if args.new_codecs:
                phases.append(probe.load("full_zstd_peak", path, {"Accept-Encoding": "zstd,identity;q=0"}, 200, raw, requests=args.requests))
                html_path = f"/test/read.cgi/probe/{key}/"
                code, _, html, _ = probe.request("GET", html_path, headers={"Accept-Encoding": "identity"})
                if code != 200:
                    raise RuntimeError("public thread HTML unavailable")
                for coding in ["gzip", "zstd"]:
                    phases.append(probe.load(f"thread_html_{coding}", html_path, {"Accept-Encoding": coding+",identity;q=0"}, 200, html, requests=args.requests))
            # 1000レスの取得と別スレッドへの20投稿/秒を同時に走らせる。
            posting_peak = {"errors": [], "times_ms": []}
            def post_peak():
                secondary = ""
                started = time.monotonic()
                for number in range(1, 201):
                    time.sleep(max(0, started + (number - 1) / 20 - time.monotonic()))
                    probe.actor(number % 40)
                    try:
                        secondary, elapsed = probe.post(number, secondary, "peak-post-probe")
                        posting_peak["times_ms"].append(elapsed)
                    except Exception as error:
                        posting_peak["errors"].append(str(error))
                        break
                posting_peak["seconds"] = time.monotonic() - started
            poster = threading.Thread(target=post_peak)
            poster.start()
            mixed = probe.load("mixed_poll_1000_per_second_post_20_per_second", path, {}, 0, b"", requests=10000, rate=1000,
                               variants=[({"Range": f"bytes={len(raw)-1}-", "Accept-Encoding": "identity"}, 206, raw[-1:])] * 4 +
                                        [({"If-None-Match": headers["etag"], "Accept-Encoding": "identity"}, 304, b"")])
            poster.join()
            mixed["posting_count"] = len(posting_peak["times_ms"])
            mixed["posting_errors"] = posting_peak["errors"]
            mixed["posting_seconds"] = posting_peak["seconds"]
            mixed["posting_p95_ms"] = sorted(posting_peak["times_ms"])[int(len(posting_peak["times_ms"]) * .95)] if posting_peak["times_ms"] else None
            phases.append(mixed)
            if args.live_updates:
                from probe_live_updates import live_updates
                phases.append(live_updates(probe, counters))
            result = {"scope": "isolated actual validation server, HTTPS HTTP/1.1, host client with distinct loopback sources, 200ms cgroup samples; no remote RTT or NIC proof",
                      "image": image, "cpu_max": (group / "cpu.max").read_text().strip(),
                      "memory_max": (group / "memory.max").read_text().strip(),
                      "egress_budget_bits_per_second": args.egress_bps,
                      "user_posts": 1000, "dat_lines": raw.count(b"\n"), "dat_bytes": len(raw), "gzip_bytes": len(compressed),
                      "gzip_reduction_percent": (1 - len(compressed) / len(raw)) * 100,
                      "cold_gzip_ms": cold_ms, "one_post_range_bytes": len(raw) - offset,
                      "posting": {"seconds": after["at"] - before["at"], "p95_ms": sorted(post_times)[950],
                                  **{k + "_delta": after[k] - before[k] for k in ("cpu_usec", "rbytes", "wbytes", "rios", "wios", "oom_kill")}},
                      "phases": phases, "memory_peak_bytes": int((group / "memory.peak").read_text()),
                      "samples": probe.samples}
            output = pathlib.Path(args.output)
            output.write_text(json.dumps(result, indent=2) + "\n")
            output.chmod(0o600)
            report_written = True
            print(json.dumps({k: v for k, v in result.items() if k != "samples"}, indent=2), flush=True)
            if any(phase["errors"] or phase.get("generator_max_lag_ms", 0) > 100 for phase in phases) or posting_peak["errors"]:
                raise RuntimeError("load verification failed; inspect saved report")
        finally:
            if probe:
                probe.stop.set()
                probe.monitor.join()
            subprocess.run(["docker", "stop", "--time", "35", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                report = pathlib.Path(args.output)
                if args.optional_log_stats and report_written:
                    # 生のHTTP行を読まず、停止後の欠測集計だけを取得する。
                    snapshot_file = folder / "optional-loss.json"
                    command("docker", "cp", f"{name}:/data/site/reports/http-loss/loss.json", str(snapshot_file))
                    snapshot = json.loads(snapshot_file.read_text())["summary"]
                    saved = json.loads(report.read_text())
                    saved["optional_shutdown"] = {"clean": snapshot["clean_shutdown"], "queue": snapshot["queue"]}
                    report.write_text(json.dumps(saved, indent=2) + "\n")
                    report.chmod(0o600)
                    if not snapshot["clean_shutdown"] or snapshot["queue"]["pending"]:
                        raise RuntimeError("optional log shutdown incomplete")
            finally:
                subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["docker", "volume", "rm", f"{name}-data"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
