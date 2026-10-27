"""隔離負荷コンテナだけをSIGKILLし、応答済み1000投稿の実HTTP復旧を測る。"""
import http.client
import pathlib
import subprocess
import threading
import time


def command(*args):
    """引数をshellへ渡さず実行し、失敗時は復旧測定を中断する。"""
    return subprocess.check_output(args, text=True).strip()


def restart(probe, name, certificate, path, raw, etag, waf):
    """監視を切り替えて再起動し、同一DAT・ETag・WAF拒否を確認した新Probeを返す。"""
    if not name.startswith("oimobbs-resource-probe-"):
        raise ValueError("crash recovery requires an isolated resource probe")
    probe.stop.set()
    probe.monitor.join()
    old_events = (probe.cgroup / "memory.events").read_text()
    if int(dict(line.split() for line in old_events.splitlines())["oom_kill"]) != 0:
        raise RuntimeError("probe had OOM before requested SIGKILL")
    started = time.monotonic()
    command("docker", "kill", "--signal", "KILL", name)
    state = command("docker", "inspect", name, "--format", "{{.State.ExitCode}} {{.State.OOMKilled}}")
    if state != "137 false":
        raise RuntimeError("probe did not exit from requested SIGKILL: " + state)
    start_requested = time.monotonic()
    command("docker", "start", name)
    pid = command("docker", "inspect", name, "--format", "{{.State.Pid}}")
    if pid == "0":
        raise RuntimeError("probe exited during recovery")
    group = pathlib.Path("/sys/fs/cgroup") / pathlib.Path(f"/proc/{pid}/cgroup").read_text().split("::", 1)[1].strip().lstrip("/")
    recovered = type(probe)(probe.port, certificate, group)
    if hasattr(probe, "io_contention_path"):
        recovered.io_contention_path = probe.io_contention_path
    try:
        received = wait_dat(recovered, path, raw, etag)
        ready = time.monotonic()
        recovery_cpu = dict(line.split() for line in (group / "cpu.stat").read_text().splitlines())
        if waf and recovered.request("GET", "/.git/config")[0] != 403:
            raise RuntimeError("WAF did not persist through SIGKILL")
        report = {"scope": "SIGKILL of isolated container after 1000 acknowledged posts; no power-loss/media-failure proof",
                  "signal_exit": state, "acknowledged_posts": 1000, "dat_lines": raw.count(b"\n"),
                  "dat_bytes_equal": True, "etag_equal": received.get("etag") == etag,
                  "crash_to_verified_dat_ms": (ready - started) * 1000,
                  "start_to_verified_dat_ms": (ready - start_requested) * 1000,
                  "start_to_verified_dat_cpu_ms": int(recovery_cpu["usage_usec"]) / 1000,
                  "start_to_verified_dat_throttled_ms": int(recovery_cpu.get("throttled_usec", 0)) / 1000,
                  "waf_block_persisted": True if waf else None, "memory_events_before_crash": old_events,
                  "optional_log_stats_scope": "last process only; queued optional records may be lost at SIGKILL"}
        return recovered, report
    except BaseException:
        recovered.stop.set()
        recovered.monitor.join()
        raise


def wait_dat(probe, path, raw, etag):
    """60秒以内に起動を待ち、公開された最初のDATが完全一致しなければ失敗する。"""
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            code, headers, body, _ = probe.request("GET", path, headers={"Accept-Encoding": "identity"})
        except (OSError, http.client.HTTPException):
            state = probe.local
            if hasattr(state, "connection"):
                state.connection.close()
            probe.local = threading.local()
            time.sleep(.02)
            continue
        if code != 200 or body != raw or headers.get("etag") != etag:
            raise RuntimeError("acknowledged DAT/ETag changed after SIGKILL")
        return headers
    raise RuntimeError("probe did not recover within60seconds")
