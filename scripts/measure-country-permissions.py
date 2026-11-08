#!/usr/bin/env python3
"""保存した前後の試験binaryを交互に実行し、隔離HTTP/2の全結果とCPU/socket量を保持する。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess
from datetime import datetime, timezone, timedelta


def measure(binary, case, repetition, folder, requests, server_cpus, client_cpus):
    """server/clientを別CPUへ固定し、失敗した測定の出力も残す。"""
    environment = os.environ.copy()
    environment.pop("OIMO_COUNTRY_PROFILE", None)
    environment.update(OIMO_COUNTRY_LOAD="1", OIMO_COUNTRY_LOAD_CASE=case,
                       OIMO_COUNTRY_REQUESTS=str(requests),
                       OIMO_COUNTRY_SERVER_CPUS=server_cpus, GOMAXPROCS="2")
    command = ["taskset", "-c", client_cpus, str(binary),
               "-test.run=^TestCountryPermissionLoad$", "-test.v", "-test.timeout=3m"]
    log = folder / f"{case}-{binary.stem}-{repetition}.log"
    try:
        completed = subprocess.run(command, env=environment, text=True, capture_output=True, timeout=200)
    except subprocess.TimeoutExpired as error:
        stdout, stderr = error.stdout or b"", error.stderr or b""
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        log.write_text(stdout + stderr)
        raise RuntimeError(f"Timed-out measurement retained: {log}") from error
    log.write_text(completed.stdout + completed.stderr)
    prefix = "COUNTRY_LOAD_RESULT="
    records = [json.loads(line[len(prefix):]) for line in completed.stdout.splitlines() if line.startswith(prefix)]
    if len(records) != 1:
        raise RuntimeError(f"No complete result: {log}")
    record = records[0]
    record.update(binary=binary.stem, repetition=repetition, exit_code=completed.returncode, log=log.name)
    return record


def main():
    """同じ要求数・接続数・応答byteを照合してから前後の中央値と不利な実行も集計する。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--requests", type=int, default=50000)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()
    cpus = sorted(os.sched_getaffinity(0))
    if len(cpus) < 4 or not 1 <= args.repeat <= 20 or not 1 <= args.requests <= 1000000:
        raise SystemExit("Need at least four available CPUs and bounded requests/repetitions")
    baseline, candidate = args.baseline.resolve(), args.candidate.resolve()
    if baseline.stem == candidate.stem:
        raise SystemExit("Baseline and candidate binary names must differ")
    folder = args.output.resolve()
    folder.mkdir(parents=True, exist_ok=True)
    server_cpus, client_cpus = ",".join(map(str, cpus[:2])), ",".join(map(str, cpus[2:4]))
    report = {"measured_at_jst": datetime.now(timezone(timedelta(hours=9))).isoformat(),
              "scope": "isolated loopback TLS HTTP/2 SiteWebHandler SETTING.TXT; no WAN or live-host claim",
              "server_cpus": server_cpus, "client_cpus": client_cpus,
              "network_prefixes": 40000, "country_prefixes": 40000,
              "requests_per_run": args.requests, "repetitions": args.repeat,
              "warmup_requests_per_run": 101,
              "socket_boundary": "TLS TCP socket byte deltas include one stats response and the following stats request; excludes TCP/IP framing",
              "sha256": {p.stem: hashlib.sha256(p.read_bytes()).hexdigest() for p in (baseline, candidate)},
              "samples": [], "summary": {}}
    for case in ("automatic", "board"):
        for repetition in range(args.repeat):
            order = (baseline, candidate) if repetition % 2 == 0 else (candidate, baseline)
            for binary in order:
                record = measure(binary, case, repetition, folder, args.requests, server_cpus, client_cpus)
                report["samples"].append(record)
                (folder / "comparison.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
                print(f"{case} {binary.stem} #{repetition}: {record['rps']:.1f} req/s, "
                      f"CPU {record['server_cpu_seconds']:.3f}s, errors {record['errors']}", flush=True)
                if record["exit_code"] or record["errors"] or record["success"] != args.requests:
                    raise RuntimeError("Load failure retained in comparison.json")
        samples = [s for s in report["samples"] if s["case"] == case]
        if len({(s["body_sha256"], s["body_bytes"]) for s in samples}) != 1:
            raise RuntimeError("Baseline and candidate response bytes differ")
        summary = {}
        for binary in (baseline, candidate):
            rows = [s for s in samples if s["binary"] == binary.stem]
            summary[binary.stem] = {key: statistics.median(s[key] for s in rows)
                                    for key in ("rps", "p50_ms", "p95_ms", "server_cpu_seconds",
                                                "client_cpu_seconds", "socket_rx_bytes", "socket_tx_bytes")}
            summary[binary.stem].update(min_rps=min(s["rps"] for s in rows), max_rps=max(s["rps"] for s in rows),
                                        requests=sum(s["requests"] for s in rows), errors=sum(s["errors"] for s in rows))
        summary["rps_change_percent"] = (summary[candidate.stem]["rps"] / summary[baseline.stem]["rps"] - 1) * 100
        summary["server_cpu_change_percent"] = (summary[candidate.stem]["server_cpu_seconds"] / summary[baseline.stem]["server_cpu_seconds"] - 1) * 100
        report["summary"][case] = summary
        (folder / "comparison.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")


if __name__ == "__main__":
    main()
