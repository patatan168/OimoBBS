#!/usr/bin/env python3
"""隔離TLSで圧縮なしのバーストを比較し、server cgroupと仮想NICだけを測る。"""
import argparse
import concurrent.futures
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import uuid


def command(*args):
    """標準出力を返し、失敗時は測定を中断する。"""
    return subprocess.check_output(args, text=True).strip()


def stats(group, pid):
    """サーバーのCPUと仮想eth0の送信byteを、ホスト全体と分けて読む。"""
    cpu = dict(line.split() for line in (group / "cpu.stat").read_text().splitlines())
    for line in Path(f"/proc/{pid}/net/dev").read_text().splitlines():
        if line.split(":", 1)[0].strip() == "eth0":
            return {"at": time.monotonic(), "tx_bytes": int(line.split(":", 1)[1].split()[8]),
                    "cpu_usec": int(cpu["usage_usec"]), "memory_bytes": int((group / "memory.current").read_text()),
                    "throttled_usec": int(cpu.get("throttled_usec", 0))}
    raise RuntimeError("isolated eth0 missing")


def percentile(values, fraction):
    """空集合を計測済みとせず、昇順の分位値を返す。"""
    return sorted(values)[min(len(values)-1, int(len(values)*fraction))] if values else None


def measure(binary, cpus, memory):
    """試験用の鍵とコンテナを作り、失敗時にも除去する。"""
    name = "oimo-network-burst-" + uuid.uuid4().hex[:10]
    with tempfile.TemporaryDirectory(prefix="network-burst-", dir="var") as folder_name:
        folder = Path(folder_name).resolve()
        cert, key = folder / "cert.pem", folder / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-keyout", str(key), "-out", str(cert), "-subj", "/CN=127.0.0.1",
                        "-addext", "subjectAltName=IP:127.0.0.1"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        key.chmod(0o600)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        stop, full_done = threading.Event(), threading.Event()
        samples, small, failures = [], [], []
        monitor = None
        try:
            command("docker", "run", "-d", "--name", name, "--read-only", "--cpus", str(cpus),
                    "--memory", memory, "--memory-swap", memory, "--pids-limit", "64", "--cap-drop", "ALL",
                    "--security-opt", "no-new-privileges", "--user", f"{os.getuid()}:{os.getgid()}",
                    "-p", f"127.0.0.1:{port}:8443", "-v", f"{Path(binary).resolve()}:/probe:ro",
                    "-v", f"{cert}:/cert.pem:ro", "-v", f"{key}:/key.pem:ro", "alpine:3.23",
                    "/probe", "-cert", "/cert.pem", "-key", "/key.pem")
            pid = int(command("docker", "inspect", name, "--format", "{{.State.Pid}}"))
            group = Path("/sys/fs/cgroup") / Path(f"/proc/{pid}/cgroup").read_text().split("::", 1)[1].strip().lstrip("/")
            context = ssl.create_default_context(cafile=str(cert))

            def connection():
                return http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=15)

            def fetch(conn, headers, path="/dat"):
                start = time.monotonic()
                conn.request("GET", path, headers=headers)
                response = conn.getresponse()
                data = response.read()
                return response.status, dict((k.lower(), v) for k, v in response.getheaders()), data, (time.monotonic()-start)*1000

            conn = connection()
            for attempt in range(100):
                try:
                    status, headers, body, _ = fetch(conn, {"Accept-Encoding": "identity"})
                    assert status == 200
                    break
                except (OSError, http.client.HTTPException):
                    conn.close()
                    conn = connection()
                    time.sleep(0.05)
            else:
                raise RuntimeError("server startup failed")
            tag, date = headers["etag"], headers["last-modified"]
            status, range_headers, range_body, _ = fetch(conn, {"Accept-Encoding": "identity", "Range": f"bytes={len(body)-100}-", "If-Range": date})
            assert (status == 206 and range_body == body[-100:]) or (status == 200 and range_body == body)
            resume = {"status": status, "bytes": len(range_body)}
            conn.close()
            # 双方のbucketを満たした同じidle状態から集中取得を開始する。
            time.sleep(0.2)

            def watch():
                while not stop.is_set():
                    samples.append(stats(group, pid))
                    stop.wait(0.01)

            monitor = threading.Thread(target=watch, daemon=True)
            monitor.start()
            started, before = time.monotonic(), stats(group, pid)
            barrier = threading.Barrier(28)

            def full_worker(index):
                client = connection()
                barrier.wait()
                try:
                    for _ in range(3):
                        status, _, data, _ = fetch(client, {"Accept-Encoding": "identity"})
                        if status != 200 or data != body:
                            failures.append("full response mismatch")
                except Exception as error:
                    failures.append(type(error).__name__)
                finally:
                    client.close()

            def small_worker(index):
                client = connection()
                barrier.wait()
                finished_at, count = None, 0
                try:
                    while True:
                        if full_done.is_set():
                            finished_at = finished_at or time.monotonic()
                            if time.monotonic()-finished_at >= 1:
                                break
                        target = started + count*0.05
                        time.sleep(max(0, target-time.monotonic()))
                        chosen = {"Accept-Encoding": "identity"}
                        if count % 2:
                            chosen["Range"] = f"bytes={len(body)-100}-"
                        else:
                            chosen["If-None-Match"] = tag
                        recovery = full_done.is_set()
                        status, h, data, ms = fetch(client, chosen)
                        want = body[-100:] if count % 2 else b""
                        if status != (206 if count % 2 else 304) or data != want:
                            failures.append("small response mismatch")
                        header_bytes = sum(len(k)+len(v)+4 for k, v in h.items())
                        small.append({"latency_ms": ms, "recovery": recovery, "header_bytes": header_bytes, "status": status})
                        count += 1
                except Exception as error:
                    failures.append(type(error).__name__)
                finally:
                    client.close()

            with concurrent.futures.ThreadPoolExecutor(max_workers=28) as pool:
                large = [pool.submit(full_worker, i) for i in range(24)]
                tiny = [pool.submit(small_worker, i) for i in range(4)]
                for future in large:
                    future.result()
                full_seconds = time.monotonic()-started
                full_done.set()
                for future in tiny:
                    future.result()
            after = stats(group, pid)
            stop.set()
            monitor.join()
            client = connection()
            status, _, data, _ = fetch(client, {}, "/status")
            client.close()
            state = json.loads(data)
            assert status == 200 and state["queued_chunks"] == 0 and state["active_write_count"] == 0
            assert state["active_subject_count"] == 0
            windows = []
            for i, end in enumerate(samples):
                candidates = [v for v in samples[:i] if end["at"]-v["at"] >= 1]
                if candidates:
                    begin = candidates[-1]
                    windows.append((end["tx_bytes"]-begin["tx_bytes"])*8/(end["at"]-begin["at"]))
            busy = [v["latency_ms"] for v in small if not v["recovery"]]
            recovery = [v["latency_ms"] for v in small if v["recovery"]]
            events = (group/"memory.events").read_text()
            assert "oom_kill 0" in events and not failures, failures
            return {"scope": "component TLS HTTP/1.1, identity only, same NAT IP; virtual eth0 TX, not WAN NIC; server cgroup excludes host client",
                    "cpus": cpus, "memory": memory, "full_requests": 72, "full_bytes": len(body), "full_seconds": full_seconds,
                    "input_sha256": hashlib.sha256(body).hexdigest(), "date_resume": resume, "small_requests": len(small),
                    "small_busy_p95_ms": percentile(busy, .95), "small_recovery_p95_ms": percentile(recovery, .95),
                    "304_header_bytes_mean": sum(v["header_bytes"] for v in small if v["status"] == 304)/sum(v["status"] == 304 for v in small),
                    "server_cpu_cores": (after["cpu_usec"]-before["cpu_usec"])/1e6/(after["at"]-before["at"]),
                    "virtual_tx_bytes": after["tx_bytes"]-before["tx_bytes"], "virtual_tx_1s_peak_bps": max(windows),
                    "sample_max_gap_ms": max((b["at"]-a["at"])*1000 for a, b in zip(samples, samples[1:])),
                    "memory_peak_bytes": int((group/"memory.peak").read_text()), "errors": len(failures), "memory_events": events,
                    "final_status": state, "samples": samples}
        finally:
            stop.set()
            if monitor is not None:
                monitor.join()
            subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    """変更前後を同じ条件で順に測り、秘密を含まない集計だけを保存する。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", required=True)
    parser.add_argument("--after", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    rows = []
    for cpus, memory in [(1, "256m"), (2, "1g")]:
        for label in ["before", "after"]:
            row = measure(getattr(args, label), cpus, memory)
            row["version"] = label
            rows.append(row)
            print(label, cpus, "busy p95", round(row["small_busy_p95_ms"], 3), "recovery p95", round(row["small_recovery_p95_ms"], 3), "resume", row["date_resume"], flush=True)
    with os.fdopen(os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
        json.dump(rows, output, indent=2)


if __name__ == "__main__":
    main()
