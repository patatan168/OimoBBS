"""PythonのGILによる発行上限を避け、同じ隔離HTTPSをGoから検証付きで取得する。"""
import hashlib
import json
import pathlib
import subprocess
import tempfile

from codec_probe_decode import decode


def load_go(probe, name, path, headers, expected_status, expected_body, requests):
    """全応答のSHA-256・検証子・RangeをGoで照合し、サーバーcgroup差分を記録する。"""
    counters = probe.read_counters
    status, received, encoded, _ = probe.request("GET", path, headers=headers)
    if status != expected_status or decode(received.get("content-encoding"), encoded) != expected_body:
        raise RuntimeError("Go load fixture mismatch")
    if expected_status == 206:
        begin = int(headers["Range"].removeprefix("bytes=").removesuffix("-"))
        if received.get("content-range") != f"bytes {begin}-{begin+len(encoded)-1}/{probe.dat_size}":
            raise RuntimeError("Go range fixture mismatch")
    config = {"url": f"https://127.0.0.1:{probe.port}{path}", "certificate": probe.certificate,
              "headers": headers, "response_headers": {key: received.get(key, "") for key in ("etag", "content-range", "content-encoding")},
              "status": status, "body_sha256": hashlib.sha256(encoded).hexdigest(), "body_bytes": len(encoded),
              "requests": requests, "workers": 64, "rate": getattr(probe, "read_rate", 0)}
    probe.phase = name
    with tempfile.TemporaryDirectory(prefix="oimo-read-load-") as folder:
        config_path = pathlib.Path(folder) / "request.json"
        config_path.write_text(json.dumps(config))
        before = counters(probe.cgroup)
        completed = subprocess.run([probe.go_read_client, "--config", str(config_path)], text=True, capture_output=True)
        after = counters(probe.cgroup)
    if not completed.stdout:
        raise RuntimeError(f"Go load failed: {completed.stderr}")
    result = json.loads(completed.stdout)
    if completed.returncode and not result["errors"]:
        result["errors"] = 1
    samples = [s for s in probe.samples if before["at"] <= s["at"] <= after["at"]]
    duration = after["at"] - before["at"]
    return {**result, "name": name, "workers": config["workers"], "go_exit_code": completed.returncode,
            "generator": "Go HTTP/1.1, 64 independent loopback sources, no retries",
            "http_p95_ms": result["p95_ms"], "server_observation_seconds": duration,
            "server_cpu_us_per_request": (after["cpu_usec"]-before["cpu_usec"])/requests,
            "cpu_cores_average": (after["cpu_usec"]-before["cpu_usec"])/duration/1e6,
            "memory_peak_sampled_bytes": max([before["memory_bytes"], after["memory_bytes"]]+[s["memory_bytes"] for s in samples]),
            **{k+"_delta":after[k]-before[k] for k in ("rbytes", "wbytes", "rios", "wios", "throttled_usec", "oom_kill")}}
