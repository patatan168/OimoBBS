#!/usr/bin/env python3
"""外部接続・ポート公開・永続volumeを使わず、Docker内で投稿packの往復を検証する。"""
import argparse
import datetime
import hashlib
import hmac
import json
from pathlib import Path
import re
import subprocess
import time
import urllib.parse
import uuid


def fixture_mac(key, *fields):
    """試験用の認証付き途中成果を、長さ付きdomain/fieldで構成する。"""
    digest = hmac.new(key, digestmod=hashlib.sha256)
    for field in fields:
        digest.update(len(field).to_bytes(4, "big"))
        digest.update(field)
    return digest.digest()


def main():
    """一時コンテナだけを作成し、成功・失敗のいずれでも除去する。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="oimobbs-pack-check:local")
    parser.add_argument("--low-capacity", action="store_true", help="128MiBの保存先で圧縮延期と公開継続を確認")
    parser.add_argument("--emergency-reserve", action="store_true", help="復旧用予約の解放・投稿停止・補充を確認")
    parser.add_argument("--backup", action="store_true", help="停止中コピー・別保管鍵・正本なしの照合・改変拒否を確認")
    args = parser.parse_args()
    if args.low_capacity and args.emergency_reserve:
        parser.error("choose one capacity scenario")
    if args.backup and (args.low_capacity or args.emergency_reserve):
        parser.error("backup requires the normal pack scenario")
    name = "oimobbs-pack-smoke-" + uuid.uuid4().hex[:12]

    def docker(*command, data=None, check=True):
        return subprocess.run(["docker", *command], input=data, capture_output=True,
                              check=check, timeout=45)

    def inside(*command, data=None, check=True):
        return docker("exec", "-i", name, *command, data=data, check=check)

    def cli(*command, data=None):
        result = inside("oimobbs", *command, "--config", "/tmp/config.json", data=data)
        return json.loads(result.stdout)

    def start():
        """コンテナ内のloopbackだけで検証サーバーを起動する。"""
        inside("sh", "-c", "oimobbs validation-serve --config /tmp/config.json "
               ">/tmp/server.log 2>&1 & echo $! >/tmp/server.pid")
        for _ in range(50):
            if inside("oimobbs", "healthcheck", "--config", "/tmp/config.json", check=False).returncode == 0:
                return
            time.sleep(0.1)
        raise RuntimeError("isolated server did not start")

    def stop():
        """正常終了を待ってから停止中CLIへ引き渡す。"""
        inside("sh", "-c", 'kill -TERM "$(cat /tmp/server.pid)"')
        for _ in range(100):
            if inside("sh", "-c", 'kill -0 "$(cat /tmp/server.pid)" 2>/dev/null', check=False).returncode != 0:
                return
            time.sleep(0.1)
        raise RuntimeError("isolated server did not stop")

    def request(path, fields=None, cookie="", extra_headers=()):
        if extra_headers:
            # 同梱wgetは手動Rangeの206をエラー扱いするため、この要求は生HTTPで照合する。
            assert fields is None
            head = ["GET " + path + " HTTP/1.1", "Host: 127.0.0.1:9080", "Connection: close", *extra_headers]
            result = inside("nc", "-w", "10", "127.0.0.1", "9080", data=("\r\n".join(head) + "\r\n\r\n").encode())
            headers, body = result.stdout.split(b"\r\n\r\n", 1)
            assert headers.startswith(b"HTTP/1.1 206 ")
            length = re.search(rb"content-length:\s*([0-9]+)", headers, re.I)
            assert length and len(body) == int(length.group(1))
            return body, headers.decode()
        command = ["wget", "-S", "-O", "-", "-T", "10"]
        if fields is not None:
            command += ["--header", "Content-Type: application/x-www-form-urlencoded; charset=UTF-8",
                        "--post-data", urllib.parse.urlencode(fields)]
        if cookie:
            command += ["--header", "Cookie: oimo_confirm=" + cookie]
        for header in extra_headers:
            command += ["--header", header]
        result = inside(*command, "http://127.0.0.1:9080" + path, check=False)
        if result.returncode:
            raise RuntimeError(result.stderr.decode(errors="replace"))
        return result.stdout, result.stderr.decode(errors="replace")

    def post(fields):
        """専ブラ形式の確認Cookieを保持し、二往復で投稿する。"""
        body, headers = request("/test/bbs.cgi", fields)
        found = re.search(r"set-cookie:\s*oimo_confirm=([^;\s]+)", headers, re.I)
        if found:
            body, _ = request("/test/bbs.cgi", fields, found.group(1))
        if "書きこみが終わりました。" not in body.decode("shift_jis"):
            raise RuntimeError("posting did not return success")

    def etag(headers):
        found = re.search(r"etag:\s*([^\r\n]+)", headers, re.I)
        if not found:
            raise RuntimeError("DAT ETag missing")
        return found.group(1).strip()

    def reserve_pressure():
        """272MiBの隔離tmpfsだけを満杯にし、予約解放で小さな復旧用書込みが可能になることを確認する。"""
        inside("cp", "-a", "/data/site", "/pressure/site")
        pressure_config = dict(config, data_dir="/pressure/site")
        inside("sh", "-c", "cat >/tmp/pressure.json", data=json.dumps(pressure_config).encode())
        inside("touch", "/pressure/probe")
        filled = inside("dd", "if=/dev/zero", "of=/pressure/filler", "bs=1M", "count=272", check=False)
        assert filled.returncode != 0 and b"No space left on device" in filled.stderr
        blocked = inside("dd", "if=/dev/zero", "of=/pressure/probe", "bs=1M", "count=1", check=False)
        assert blocked.returncode != 0 and b"No space left on device" in blocked.stderr
        released = inside("oimobbs", "reserve", "release", "--config", "/tmp/pressure.json",
                          "--remaining-mib", "240", "--apply")
        assert json.loads(released.stdout)["bytes"] == 240 << 20
        inside("dd", "if=/dev/zero", "of=/pressure/probe", "bs=1M", "count=1", "conv=fsync")

    created = False
    try:
        docker("run", "-d", "--name", name, "--init", "--network", "none", "--read-only",
               "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--pids-limit", "128",
               "--tmpfs", "/data:uid=10001,gid=10001,mode=0700" + (",size=128m" if args.low_capacity else ""), "--tmpfs", "/tmp:uid=10001,gid=10001,mode=0700",
               *(["--tmpfs", "/pressure:uid=10001,gid=10001,mode=0700,size=272m"] if args.emergency_reserve else []),
               *(["--tmpfs", "/replay-pressure:uid=10001,gid=10001,mode=0700,size=128m"] if args.backup else []),
               "--entrypoint", "/bin/sh", args.image, "-c", "exec sleep 3600")
        created = True
        config = json.loads((Path(__file__).resolve().parents[1] / "config.example.json").read_text())
        config["data_dir"] = "/tmp/site" if args.low_capacity else "/data/site"
        config.update(edge=None, auto_reports=None, maintenance=config.get('maintenance'))
        inside("sh", "-c", "cat >/tmp/config.json", data=json.dumps(config).encode())
        cli("init")
        if args.emergency_reserve:
            reserved = cli("reserve", "prepare", "--apply")
            assert reserved["ready"] and reserved["allocated_bytes"] >= 256 << 20
            reserve_pressure()
        cli("admin", "init", "--login", "owner", "--password-stdin", data=(uuid.uuid4().hex + "\n").encode())
        board = cli("board", "create", "--key", "pack", "--name", "Pack smoke")
        owner = board["id"]
        start()
        fields = {"bbs": "pack", "subject": "isolated pack smoke", "MESSAGE": "first body",
                  "oimo_request_id": uuid.uuid4().hex}
        post(fields)
        subject, _ = request("/pack/subject.txt")
        found = re.match(rb"([0-9]+)\.dat<>", subject)
        if not found:
            raise RuntimeError("created thread absent from subject")
        key = found.group(1).decode()
        path = "/pack/dat/" + key + ".dat"
        before, headers = request(path)
        original_etag = etag(headers)
        assert len(before.splitlines()) == 1
        stop()
        if args.low_capacity:
            inside("cp", "-a", "/tmp/site", "/data/site")
            config["data_dir"] = "/data/site"
            inside("sh", "-c", "cat >/tmp/config.json", data=json.dumps(config).encode())
        target = ("--board", owner, "--thread", key)
        preview = cli("pack", "compact", *target)
        assert preview["applied"] is False
        assert cli("pack", "enable")["minimum_reader_version"] == 68
        if args.emergency_reserve:
            released = cli("reserve", "release", "--remaining-mib", "240", "--apply")
            assert not released["ready"] and released["bytes"] == 240 << 20
        if args.low_capacity:
            rejected = inside("oimobbs", "reserve", "prepare", "--apply", "--config", "/tmp/config.json", check=False)
            assert rejected.returncode != 0 and b"insufficient capacity" in rejected.stderr
            assert not cli("reserve", "status")["enabled"]
            rejected = inside("oimobbs", "backup", "capture", "--output", "/data/rejected-backup", "--config", "/tmp/config.json", check=False)
            assert rejected.returncode != 0 and b"insufficient capacity for backup" in rejected.stderr
            assert inside("test", "-e", "/data/rejected-backup", check=False).returncode != 0
        if args.low_capacity or args.emergency_reserve:
            rejected = inside("oimobbs", "pack", "compact", *target, "--apply", "--config", "/tmp/config.json", check=False)
            assert rejected.returncode != 0 and b"insufficient free capacity" in rejected.stderr
            current = cli("pack", "compact", *target)
            assert current["storage_generation"] == 2 and not current["applied"]
            start()
            after, headers = request(path)
            assert after == before and etag(headers) == original_etag
            post(fields)  # 受理済み再送だけは容量不足でも元の成功結果を返す。
            new_reply = {"bbs": "pack", "key": key, "MESSAGE": "blocked by capacity", "oimo_request_id": uuid.uuid4().hex}
            _, challenge = request("/test/bbs.cgi", new_reply)
            cookie = re.search(r"set-cookie:\s*oimo_confirm=([^;\s]+)", challenge, re.I).group(1)
            encoded = urllib.parse.urlencode(new_reply).encode()
            request_headers = ["POST /test/bbs.cgi HTTP/1.1", "User-Agent: Wget", "Host: 127.0.0.1:9080", "Connection: close",
                               "Content-Type: application/x-www-form-urlencoded; charset=UTF-8",
                               "Cookie: oimo_confirm=" + cookie, "Content-Length: " + str(len(encoded))]
            # stdin EOFでPOSTの処理前に切断しないよう、応答を待つ間は入力側を保持する。
            rejected = inside("sh", "-c", "(cat; sleep 1) | nc -w 10 127.0.0.1 9080", data=("\r\n".join(request_headers) + "\r\n\r\n").encode() + encoded).stdout
            rejected_headers, rejected_body = rejected.split(b"\r\n\r\n", 1)
            assert rejected_headers.startswith(b"HTTP/1.1 503 "), rejected_headers
            assert re.search(rb"retry-after:\s*30", rejected_headers, re.I), (rejected_headers, rejected_body.decode("shift_jis"))
            assert "新しい投稿を一時停止" in rejected_body.decode("shift_jis")
            assert request(path)[0] == before
            stop()
            checks = ["no pack switch", "DAT", "ETag", "accepted retry", "new reply 503", "Retry-After"]
            if args.emergency_reserve:
                assert cli("reserve", "prepare", "--apply")["ready"]
                start()
                post(new_reply)
                assert len(request(path)[0].splitlines()) == 2
                stop()
                checks += ["physical reserve", "partial release", "refill", "posting resumed", "real ENOSPC", "write after reserve release"]
            else:
                checks += ["low capacity", "reserve preparation rejected without mutation", "backup rejected without output"]
            print(json.dumps({"status": "PASS", "image": args.image, "checks": checks}))
            return
        assert cli("pack", "compact", *target, "--apply")["applied"] is True
        maintenance = cli("pack", "maintain", "--limit", "1")
        assert not maintenance["applied"] and maintenance["entries"][0]["reclaim"]["files"] == 1
        reclaimed = cli("pack", "maintain", "--limit", "1", "--apply")
        assert reclaimed["entries"][0]["reclaim"]["applied"] is True
        assert reclaimed["entries"][0]["reclaim"]["files"] == 1
        start()
        after, headers = request(path)
        assert after == before and etag(headers) == original_etag
        post(fields)
        assert request(path)[0] == before
        post({"bbs": "pack", "key": key, "MESSAGE": "reply after compaction", "oimo_request_id": uuid.uuid4().hex})
        final, headers = request(path)
        final_etag = etag(headers)
        assert len(final.splitlines()) == 2
        delta, _ = request(path, extra_headers=("Range: bytes=" + str(len(before)) + "-",))
        assert before + delta == final
        stop()
        assert cli("pack", "compact", *target, "--level", "9", "--apply")["storage_generation"] == 3
        config["maintenance"] = {"enabled": True, "interval_seconds": 60, "max_threads": 1}
        inside("sh", "-c", "cat >/tmp/config.json", data=json.dumps(config).encode())
        start()
        after, headers = request(path)
        assert after == final and etag(headers) == final_etag
        # 起動直後の自動巡回が旧世代2個を回収することを実ファイルで確認する。
        old_file = "/data/site/boards/" + owner + "/threads/" + key + "/base-000002.pack"
        for _ in range(50):
            if inside("test", "-e", old_file, check=False).returncode != 0:
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("automatic maintenance did not reclaim old pack")
        stop()
        remaining = cli("pack", "maintain", "--apply")
        assert remaining["entries"][0]["reclaim"]["files"] == 0
        assert not remaining["entries"][0]["decision"]["compact"]
        backup_checks = []
        if args.backup:
            prepare_work = "/tmp/preparation-work"
            inside("mkdir", "-m", "700", prepare_work)
            def start_partial_watch(kind, watch_args, apply=False):
                """独立watchを起動し、初回JSONを待つ。"""
                prefix = "/tmp/partial-watch-" + kind
                inside("sh", "-c", "umask 077; : >" + prefix + ".jsonl; test ! -e " + prefix + ".exit || rm " + prefix + ".exit")
                command = "oimobbs " + " ".join(watch_args) + (" --apply" if apply else "")
                inside("sh", "-c", "umask 077; (" + command + " >" + prefix + ".jsonl 2>" + prefix + ".err & "
                       'partial_watch_pid=$!; echo "$partial_watch_pid" >' + prefix + '.pid; wait "$partial_watch_pid"; '
                       'echo "$?" >' + prefix + ".exit) >" + prefix + ".wrapper 2>&1 &")
                for _ in range(100):
                    report = inside("cat", prefix + ".jsonl", check=False).stdout
                    if b"\n" in report:
                        return json.loads(report.splitlines()[0])
                    time.sleep(0.1)
                raise RuntimeError("partial watch did not report")
            def stop_partial_watch(kind):
                """待機中SIGTERMの正常終了と親排他の解放を確認する。"""
                prefix = "/tmp/partial-watch-" + kind
                inside("sh", "-c", 'kill -TERM "$(cat ' + prefix + '.pid)"')
                for _ in range(100):
                    exited = inside("cat", prefix + ".exit", check=False)
                    if exited.returncode == 0:
                        assert exited.stdout.strip() == b"0"
                        return
                    time.sleep(0.1)
                raise RuntimeError("partial watch did not stop")
            prepared = cli("backup", "prepare", "--output", "/tmp/prepared-copy", "--keys-output", "/tmp/prepared-keys", "--work-parent", prepare_work)
            assert prepared["complete"] and prepared["phase"] == "complete" and not prepared["restore_ready"]
            assert prepared["replay"]["replayed"] and prepared["capture"]["backup_id"] == prepared["keys"]["backup_id"] == prepared["replay"]["backup_id"]
            assert not inside("find", prepare_work, "-mindepth", "1").stdout.strip()
            rejected_prepare = inside("oimobbs", "backup", "prepare", "--config", "/tmp/config.json", "--output", "/tmp/new-prepare-copy", "--keys-output", "/tmp/prepared-keys", "--work-parent", prepare_work, check=False)
            assert rejected_prepare.returncode != 0 and json.loads(rejected_prepare.stdout)["phase"] == "preflight"
            assert inside("test", "-e", "/tmp/new-prepare-copy", check=False).returncode != 0
            inside("mkdir", "-m", "700", "/tmp/paired-copies", "/tmp/paired-keys")
            inside("mv", "/tmp/prepared-copy", "/tmp/paired-copies/pair")
            inside("mv", "/tmp/prepared-keys", "/tmp/paired-keys/pair")
            sweep_args = ["backup", "sweep-expired", "--copy-parent", "/tmp/paired-copies", "--keys-parent", "/tmp/paired-keys"]
            for extra in ([], ["--apply"]):
                swept = json.loads(inside("oimobbs", *sweep_args, *extra).stdout)
                assert len(swept["items"]) == 1 and swept["items"][0]["status"] == "retained"
                assert not swept["restore_ready"] and not swept["items"][0]["reclaim"]["applied"]
            inside("mv", "/tmp/paired-keys/pair", "/tmp/paired-keys/other")
            missing_pair = inside("oimobbs", *sweep_args, "--apply", check=False)
            assert missing_pair.returncode != 0 and json.loads(missing_pair.stdout)["rejected_count"] == 1
            assert inside("test", "-f", "/tmp/paired-copies/pair/manifest.json").returncode == 0
            inside("mv", "/tmp/paired-keys/other", "/tmp/paired-keys/pair")
            assert json.loads(inside("oimobbs", *sweep_args, "--after", "pair").stdout)["items"] == []
            assert inside("test", "-f", "/tmp/paired-keys/pair/bundle.json").returncode == 0
            trust_instance = "/tmp/backup-trust.json"
            keys_plan = "/tmp/paired-keys-plan.json"
            trust_export = cli("backup", "export-trust", "--output", trust_instance)
            assert trust_export["exported"] and trust_export["signing_key_id"] == 10 and not trust_export["restore_ready"]
            pair_prepared = cli("backup", "prepare", "--output", "/tmp/ordered-body", "--keys-output", "/tmp/ordered-keys", "--work-parent", prepare_work, "--trust-instance", trust_instance, "--pair-plan", "/tmp/prepared-ordered-plan.json")
            assert pair_prepared["complete"] and pair_prepared["replay"]["replayed"] and pair_prepared["pair_planned"] and pair_prepared["pair_plan"]["planned"]
            assert pair_prepared["pair_plan"]["body"]["backup_id"] == pair_prepared["pair_plan"]["keys"]["backup_id"] == pair_prepared["capture"]["backup_id"]
            assert "partial_planned" not in pair_prepared and "keys_planned" not in pair_prepared
            prepared_pair_duplicate = inside("oimobbs", "backup", "prepare", "--config", "/tmp/config.json", "--output", "/tmp/rejected-pair-copy", "--keys-output", "/tmp/rejected-pair-keys", "--work-parent", prepare_work, "--trust-instance", trust_instance, "--pair-plan", "/tmp/prepared-ordered-plan.json", check=False)
            assert prepared_pair_duplicate.returncode != 0 and not json.loads(prepared_pair_duplicate.stdout)["pair_planned"]
            assert inside("test", "-e", "/tmp/rejected-pair-copy", check=False).returncode != 0
            pair_flags = ["--input", "/tmp/ordered-body", "--keys", "/tmp/ordered-keys", "--trust-instance", trust_instance, "--plan", "/tmp/ordered-plan.json"]
            pair_plan = cli("backup", "plan-pair", *pair_flags)
            assert pair_plan["planned"] and pair_plan["body"]["backup_id"] == pair_plan["keys"]["backup_id"] == pair_prepared["capture"]["backup_id"]
            pair_duplicate = inside("oimobbs", "backup", "plan-pair", *pair_flags, "--config", "/tmp/config.json", check=False)
            assert pair_duplicate.returncode != 0 and not json.loads(pair_duplicate.stdout)["planned"]
            assert "pair_planned" not in prepared and "pair_plan" not in prepared
            assert "keys_planned" not in prepared and "keys_plan" not in prepared
            complete_prepared = cli("backup", "prepare", "--output", "/tmp/complete-prepared-copy", "--keys-output", "/tmp/complete-prepared-keys", "--work-parent", prepare_work, "--trust-instance", trust_instance, "--keys-plan", "/tmp/complete-prepared-plan.json")
            assert complete_prepared["complete"] and complete_prepared["keys_planned"] and complete_prepared["keys_plan"]["planned"] and complete_prepared["replay"]["replayed"]
            assert "partial_planned" not in complete_prepared and "keys_partial_planned" not in complete_prepared
            assert complete_prepared["keys_plan"]["backup"]["backup_id"] == complete_prepared["capture"]["backup_id"] == complete_prepared["keys"]["backup_id"] == complete_prepared["replay"]["backup_id"]
            complete_plan_duplicate = inside("oimobbs", "backup", "prepare", "--config", "/tmp/config.json", "--output", "/tmp/duplicate-complete-copy", "--keys-output", "/tmp/duplicate-complete-keys", "--work-parent", prepare_work, "--trust-instance", trust_instance, "--keys-plan", "/tmp/complete-prepared-plan.json", check=False)
            assert complete_plan_duplicate.returncode != 0 and not json.loads(complete_plan_duplicate.stdout)["keys_planned"]
            assert inside("test", "-e", "/tmp/duplicate-complete-copy", check=False).returncode != 0
            assert "partial_planned" not in prepared
            planned_prepared = cli("backup", "prepare", "--output", "/tmp/planned-prepared-copy", "--keys-output", "/tmp/planned-prepared-keys", "--work-parent", prepare_work, "--trust-instance", trust_instance, "--partial-plan", "/tmp/prepared-partial-plan.json")
            assert planned_prepared["complete"] and planned_prepared["partial_planned"] and planned_prepared["replay"]["replayed"] and not planned_prepared["restore_ready"]
            assert planned_prepared["capture"]["backup_id"] == planned_prepared["keys"]["backup_id"] == planned_prepared["replay"]["backup_id"]
            assert not inside("find", prepare_work, "-mindepth", "1").stdout.strip()
            rejected_planned_prepare = inside("oimobbs", "backup", "prepare", "--config", "/tmp/config.json", "--output", "/tmp/rejected-planned-prepare", "--keys-output", "/tmp/rejected-planned-keys", "--work-parent", prepare_work, "--trust-instance", trust_instance, "--partial-plan", "/tmp/prepared-partial-plan.json", check=False)
            assert rejected_planned_prepare.returncode != 0 and not json.loads(rejected_planned_prepare.stdout)["partial_planned"]
            assert inside("test", "-e", "/tmp/rejected-planned-prepare", check=False).returncode != 0
            assert "keys_partial_planned" not in prepared and "keys_partial_planned" not in planned_prepared
            both_prepared = cli("backup", "prepare", "--output", "/tmp/both-prepared-copy", "--keys-output", "/tmp/both-prepared-keys", "--work-parent", prepare_work, "--trust-instance", trust_instance, "--partial-plan", "/tmp/both-body-plan.json", "--partial-keys-plan", "/tmp/both-keys-plan.json")
            assert both_prepared["complete"] and both_prepared["partial_planned"] and both_prepared["keys_partial_planned"] and both_prepared["replay"]["replayed"] and not both_prepared["restore_ready"]
            assert both_prepared["capture"]["backup_id"] == both_prepared["keys"]["backup_id"] == both_prepared["replay"]["backup_id"]
            assert not inside("find", prepare_work, "-mindepth", "1").stdout.strip()
            all_plans_prepared = cli("backup", "prepare", "--output", "/tmp/all-plans-copy", "--keys-output", "/tmp/all-plans-keys", "--work-parent", prepare_work, "--trust-instance", trust_instance, "--partial-plan", "/tmp/all-plans-body.json", "--partial-keys-plan", "/tmp/all-plans-partial-keys.json", "--keys-plan", "/tmp/all-plans-complete-keys.json", "--pair-plan", "/tmp/all-plans-pair.json")
            assert all_plans_prepared["complete"] and all_plans_prepared["partial_planned"] and all_plans_prepared["keys_partial_planned"] and all_plans_prepared["keys_planned"] and all_plans_prepared["replay"]["replayed"]
            assert all_plans_prepared["pair_plan"]["related_plan_count"] == 3 and all_plans_prepared["pair_plan"]["related_retired_count"] == 0
            all_related_flags = ["--input", "/tmp/all-plans-copy", "--keys", "/tmp/all-plans-keys", "--trust-instance", trust_instance, "--plan", "/tmp/all-plans-pair.json"]
            related_paths = ["/tmp/all-plans-body.json", "/tmp/all-plans-partial-keys.json", "/tmp/all-plans-complete-keys.json"]
            related_pair_payload = json.loads(inside("cat", "/tmp/all-plans-pair.json").stdout)["plan"]
            assert related_pair_payload["schema"] == 2 and len(related_pair_payload["related_plans"]) == 3
            registered_manual = cli("backup", "plan-pair", "--input", "/tmp/all-plans-copy", "--keys", "/tmp/all-plans-keys", "--trust-instance", trust_instance, "--plan", "/tmp/all-plans-pair-manual.json", "--partial-plan", related_paths[0], "--partial-keys-plan", related_paths[1], "--keys-plan", related_paths[2])
            assert registered_manual["planned"] and registered_manual["related_plan_count"] == 3
            scheduled_flags = []
            for flag in ("copy-parent", "keys-parent", "partial-plan-parent", "partial-keys-plan-parent", "keys-plan-parent", "pair-plan-parent", "work-parent", "control-parent"):
                scheduled_parent = "/tmp/scheduled-" + flag
                inside("mkdir", "-m", "700", scheduled_parent)
                scheduled_flags += ["--" + flag, scheduled_parent]
            scheduled_args = ["backup", "prepare-next", "--config", "/tmp/config.json", "--trust-instance", trust_instance] + scheduled_flags
            scheduled_watch_args = ["backup", "watch-prepare"] + scheduled_args[2:]
            preview_scheduled = json.loads(inside("oimobbs", *scheduled_args).stdout)
            assert preview_scheduled["status"] == "preview" and "name" not in preview_scheduled and "preparation" not in preview_scheduled
            scheduled_names = []
            for _ in range(2):
                prepared_scheduled = json.loads(inside("oimobbs", *scheduled_args, "--apply").stdout)
                assert prepared_scheduled["status"] == "completed" and prepared_scheduled["preparation"]["complete"] and prepared_scheduled["preparation"]["pair_plan"]["related_plan_count"] == 3
                scheduled_names.append(prepared_scheduled["name"])
            assert scheduled_names[0] != scheduled_names[1]
            watched_scheduled = start_partial_watch("preparation", scheduled_watch_args)
            assert watched_scheduled["status"] == "preview" and not watched_scheduled["apply"]
            assert inside("oimobbs", *scheduled_watch_args, check=False).returncode != 0
            assert inside("oimobbs", *scheduled_args, check=False).returncode != 0
            stop_partial_watch("preparation")
            watched_scheduled = start_partial_watch("preparation", scheduled_watch_args, apply=True)
            assert watched_scheduled["status"] == "completed" and watched_scheduled["preparation"]["replay"]["replayed"]
            scheduled_names.append(watched_scheduled["name"])
            assert len(set(scheduled_names)) == 3
            stop_partial_watch("preparation")
            pair_roots, pair_keys, pair_plans = "/tmp/pair-sweep-bodies", "/tmp/pair-sweep-keys", "/tmp/pair-sweep-plans"
            inside("mkdir", "-m", "700", pair_roots, pair_keys, pair_plans)
            swept_prepared = cli("backup", "prepare", "--output", pair_roots + "/one", "--keys-output", pair_keys + "/one", "--work-parent", prepare_work, "--trust-instance", trust_instance, "--pair-plan", pair_plans + "/one.json", "--partial-plan", "/tmp/sweep-pair-body.json", "--partial-keys-plan", "/tmp/sweep-pair-partial-keys.json", "--keys-plan", "/tmp/sweep-pair-keys.json")
            assert swept_prepared["complete"] and swept_prepared["pair_plan"]["related_plan_count"] == 3
            exported_keys_partial = cli("backup", "export-keys-planned", "--input", "/tmp/paired-copies/pair", "--output", "/tmp/export-planned-keys", "--trust-instance", trust_instance, "--plan", "/tmp/export-partial-keys-plan.json")
            assert exported_keys_partial["complete"] and exported_keys_partial["planned"] and exported_keys_partial["keys"]["verified"] and not exported_keys_partial["restore_ready"]
            duplicate_keys_partial = inside("oimobbs", "backup", "export-keys-planned", "--config", "/tmp/config.json", "--input", "/tmp/paired-copies/pair", "--output", "/tmp/export-planned-keys", "--trust-instance", trust_instance, "--plan", "/tmp/export-partial-keys-plan.json", check=False)
            assert duplicate_keys_partial.returncode != 0 and not json.loads(duplicate_keys_partial.stdout)["planned"]
            rejected_both = inside("oimobbs", "backup", "prepare", "--config", "/tmp/config.json", "--output", "/tmp/rejected-both-copy", "--keys-output", "/tmp/rejected-both-keys", "--work-parent", prepare_work, "--trust-instance", trust_instance, "--partial-plan", "/tmp/rejected-both-body-plan.json", "--partial-keys-plan", "/tmp/both-keys-plan.json", check=False)
            assert rejected_both.returncode != 0 and not json.loads(rejected_both.stdout)["keys_partial_planned"]
            assert inside("test", "-e", "/tmp/rejected-both-copy", check=False).returncode != 0
            partial_body_roots, partial_key_roots = "/tmp/partial-bodies", "/tmp/partial-keys"
            partial_body_plans, partial_key_plans = "/tmp/partial-body-plans", "/tmp/partial-key-plans"
            inside("mkdir", "-m", "700", partial_body_roots, partial_key_roots, partial_body_plans, partial_key_plans)
            cli("backup", "capture-planned", "--output", partial_body_roots + "/one", "--trust-instance", trust_instance, "--plan", partial_body_plans + "/one.json")
            cli("backup", "export-keys-planned", "--input", "/tmp/paired-copies/pair", "--output", partial_key_roots + "/one", "--trust-instance", trust_instance, "--plan", partial_key_plans + "/one.json")
            keys_planned = cli("backup", "plan-keys", "--input", "/tmp/paired-keys/pair", "--trust-instance", trust_instance, "--output", keys_plan)
            assert keys_planned["planned"] and not keys_planned["restore_ready"] and keys_planned["backup"]["backup_id"] == prepared["keys"]["backup_id"]
            key_plan_parent = "/tmp/paired-key-plans"
            inside("mkdir", "-m", "700", key_plan_parent)
            cli("backup", "plan-keys", "--input", "/tmp/paired-keys/pair", "--trust-instance", trust_instance, "--output", key_plan_parent + "/pair.json")
            planned_copy, partial_plan = "/tmp/planned-copy", "/tmp/partial-copy-plan.json"
            planned_capture = cli("backup", "capture-planned", "--output", planned_copy, "--trust-instance", trust_instance, "--plan", partial_plan)
            assert planned_capture["planned"] and planned_capture["complete"] and planned_capture["capture"]["verified"] and not planned_capture["restore_ready"]
            assert cli("backup", "verify", "--input", planned_copy)["verified"]
            duplicated_capture = inside("oimobbs", "backup", "capture-planned", "--config", "/tmp/config.json", "--output", planned_copy, "--trust-instance", trust_instance, "--plan", partial_plan, check=False)
            assert duplicated_capture.returncode != 0 and json.loads(duplicated_capture.stdout)["phase"] == "preflight"
            output = "/tmp/backup-copy"
            captured = cli("backup", "capture", "--output", output)
            assert captured["verified"] and not captured["restore_ready"]
            verified = cli("backup", "verify", "--input", output)
            assert verified["backup_id"] == captured["backup_id"] and verified["bytes"] == captured["bytes"]
            listing = inside("find", output, "-type", "f").stdout.decode().splitlines()
            assert not any(p.endswith((".key", ".seed", "emergency.reserve", "delta-000001.wal")) for p in listing)
            live = cli("backup", "reclaim", "--input", output, "--apply")
            assert not live["expired"] and not live["applied"]
            start()
            busy_scheduled = json.loads(inside("oimobbs", *scheduled_args, "--apply").stdout)
            assert busy_scheduled["status"] == "deferred_busy" and "capture" not in busy_scheduled["preparation"]
            assert inside("test", "-e", "/tmp/scheduled-copy-parent/" + busy_scheduled["name"], check=False).returncode != 0
            watched_scheduled = start_partial_watch("preparation", scheduled_watch_args, apply=True)
            assert watched_scheduled["status"] == "deferred_busy"
            stop_partial_watch("preparation")
            busy_prepare = inside("oimobbs", "backup", "prepare", "--config", "/tmp/config.json", "--output", "/tmp/busy-prepare-copy", "--keys-output", "/tmp/busy-prepare-keys", "--work-parent", prepare_work, check=False)
            assert busy_prepare.returncode != 0 and json.loads(busy_prepare.stdout)["phase"] == "source_open"
            assert inside("test", "-e", "/tmp/busy-prepare-copy", check=False).returncode != 0
            busy_keys_partial = inside("oimobbs", "backup", "export-keys-planned", "--config", "/tmp/config.json", "--input", "/tmp/paired-copies/pair", "--output", "/tmp/busy-partial-keys", "--trust-instance", trust_instance, "--plan", "/tmp/busy-partial-keys-plan.json", check=False)
            assert busy_keys_partial.returncode != 0 and json.loads(busy_keys_partial.stdout)["phase"] == "source_open" and not json.loads(busy_keys_partial.stdout)["planned"]
            assert inside("test", "-e", "/tmp/busy-partial-keys", check=False).returncode != 0
            busy_key_plan = inside("oimobbs", "backup", "plan-keys", "--config", "/tmp/config.json", "--input", "/tmp/paired-keys/pair", "--trust-instance", trust_instance, "--output", "/tmp/busy-key-plan.json", check=False)
            assert busy_key_plan.returncode != 0
            assert busy_key_plan.stdout.strip(), busy_key_plan.stderr.decode(errors="replace")
            assert not json.loads(busy_key_plan.stdout)["planned"]
            assert inside("test", "-e", "/tmp/busy-key-plan.json", check=False).returncode != 0
            busy_partial = inside("oimobbs", "backup", "capture-planned", "--config", "/tmp/config.json", "--output", "/tmp/busy-partial-copy", "--trust-instance", trust_instance, "--plan", "/tmp/busy-partial-plan.json", check=False)
            assert busy_partial.returncode != 0 and json.loads(busy_partial.stdout)["phase"] == "source_open"
            assert not json.loads(busy_partial.stdout)["planned"] and "capture" not in json.loads(busy_partial.stdout)
            assert inside("test", "-e", "/tmp/busy-partial-copy", check=False).returncode != 0
            post({"bbs": "pack", "key": key, "MESSAGE": "after backup", "oimo_request_id": uuid.uuid4().hex})
            assert len(request(path)[0].splitlines()) == 3
            stop()
            assert cli("backup", "verify", "--input", output)["verified"]
            keys = "/tmp/separate-keys"
            exported = cli("backup", "export-keys", "--input", output, "--output", keys)
            assert exported["verified"] and exported["expires_at_ns"] == captured["expires_at_ns"]
            preserved_keys = cli("backup", "reclaim-keys", "--input", keys, "--apply")
            assert not preserved_keys["expired"] and not preserved_keys["applied"]
            def verify_keys(check=True):
                return inside("oimobbs", "backup", "verify-with-keys", "--input", output, "--keys", keys, check=check)
            inside("mv", "/data/site", "/data/source-unavailable")
            for extra in ([], ["--apply"]):
                pair_retained = json.loads(inside("oimobbs", "backup", "reclaim-pair", *pair_flags, *extra).stdout)
                assert pair_retained["phase"] == "retained" and not pair_retained["expired"] and not pair_retained["applied"] and not pair_retained["restore_ready"]
            assert inside("test", "-f", "/tmp/ordered-body/manifest.json").returncode == 0
            assert inside("test", "-f", "/tmp/ordered-keys/bundle.json").returncode == 0
            unbound_pair = inside("oimobbs", "backup", "reclaim-pair", *pair_flags, "--input", "/tmp/absent-ordered-body", "--apply", check=False)
            assert unbound_pair.returncode != 0 and not json.loads(unbound_pair.stdout)["applied"]
            prepared_pair_retained = json.loads(inside("oimobbs", "backup", "reclaim-pair", "--input", "/tmp/ordered-body", "--keys", "/tmp/ordered-keys", "--trust-instance", trust_instance, "--plan", "/tmp/prepared-ordered-plan.json", "--apply").stdout)
            assert not prepared_pair_retained["expired"] and not prepared_pair_retained["applied"]
            all_pair_retained = json.loads(inside("oimobbs", "backup", "reclaim-pair", "--input", "/tmp/all-plans-copy", "--keys", "/tmp/all-plans-keys", "--trust-instance", trust_instance, "--plan", "/tmp/all-plans-pair.json", "--apply").stdout)
            assert all_plans_prepared["pair_planned"] and all_plans_prepared["pair_plan"]["planned"] and not all_pair_retained["applied"]
            assert all_pair_retained["related_plan_count"] == 3 and all_pair_retained["related_retired_count"] == 0
            for related_path in related_paths:
                assert not json.loads(inside("cat", related_path).stdout)["retired"]
            related_snapshot = inside("cat", related_paths[2]).stdout
            related_forged = json.loads(related_snapshot)
            related_forged["signature"] = "AAAAAAAA"
            inside("sh", "-c", "cat > " + related_paths[2], data=json.dumps(related_forged).encode())
            rejected_related = inside("oimobbs", "backup", "reclaim-pair", *all_related_flags, "--apply", check=False)
            assert rejected_related.returncode != 0 and not json.loads(rejected_related.stdout)["applied"]
            assert inside("test", "-f", "/tmp/all-plans-copy/manifest.json").returncode == 0
            assert inside("test", "-f", "/tmp/all-plans-keys/bundle.json").returncode == 0
            inside("sh", "-c", "cat > " + related_paths[2], data=related_snapshot)
            inside("mv", related_paths[2], "/tmp/saved-related-plan.json")
            missing_related = inside("oimobbs", "backup", "reclaim-pair", *all_related_flags, "--apply", check=False)
            assert missing_related.returncode != 0 and not json.loads(missing_related.stdout)["applied"]
            inside("mv", "/tmp/saved-related-plan.json", related_paths[2])
            assert not json.loads(inside("cat", related_paths[0]).stdout)["retired"]
            pair_snapshot = inside("cat", "/tmp/ordered-plan.json").stdout
            pair_forged = json.loads(pair_snapshot)
            pair_forged["signature"] = "AAAAAAAA"
            inside("sh", "-c", "cat > /tmp/ordered-plan.json", data=json.dumps(pair_forged).encode())
            bad_pair = inside("oimobbs", "backup", "reclaim-pair", *pair_flags, "--apply", check=False)
            assert bad_pair.returncode != 0 and "body" not in json.loads(bad_pair.stdout) and not json.loads(bad_pair.stdout)["applied"]
            inside("sh", "-c", "cat > /tmp/ordered-plan.json", data=pair_snapshot)
            complete_plan_retained = json.loads(inside("oimobbs", "backup", "reclaim-keys-planned", "--input", "/tmp/complete-prepared-keys", "--trust-instance", trust_instance, "--plan", "/tmp/complete-prepared-plan.json", "--apply").stdout)
            assert not complete_plan_retained["expired"] and not complete_plan_retained["applied"] and inside("test", "-f", "/tmp/complete-prepared-keys/bundle.json").returncode == 0
            completed_prepared_reclaim = inside("oimobbs", "backup", "reclaim-partial", "--input", "/tmp/planned-prepared-copy", "--trust-instance", trust_instance, "--plan", "/tmp/prepared-partial-plan.json", "--apply", check=False)
            assert completed_prepared_reclaim.returncode != 0 and not json.loads(completed_prepared_reclaim.stdout)["applied"]
            assert inside("test", "-f", "/tmp/planned-prepared-copy/manifest.json").returncode == 0
            scheduled_pairs = json.loads(inside("oimobbs", "backup", "sweep-pairs", "--copy-parent", "/tmp/scheduled-copy-parent", "--keys-parent", "/tmp/scheduled-keys-parent", "--plan-parent", "/tmp/scheduled-pair-plan-parent", "--trust-instance", trust_instance, "--apply").stdout)
            assert len(scheduled_pairs["items"]) == 3 and all(item["status"] == "retained" for item in scheduled_pairs["items"])
            pair_sweep_args = ["backup", "sweep-pairs", "--copy-parent", pair_roots, "--keys-parent", pair_keys, "--plan-parent", pair_plans, "--trust-instance", trust_instance]
            pair_watch_args = ["backup", "watch-pairs"] + pair_sweep_args[2:]
            for extra in ([], ["--apply"]):
                swept_pair = json.loads(inside("oimobbs", *pair_sweep_args, *extra).stdout)
                assert swept_pair["items"][0]["status"] == "retained" and swept_pair["items"][0]["pair"]["related_plan_count"] == 3
                assert not swept_pair["items"][0]["pair"]["applied"]
            assert json.loads(inside("oimobbs", *pair_sweep_args, "--after", "one").stdout)["items"] == []
            watched_pair = start_partial_watch("pairs", pair_watch_args)
            assert watched_pair["status"] == "completed" and not watched_pair["apply"]
            assert inside("oimobbs", *pair_watch_args, check=False).returncode != 0
            assert inside("oimobbs", *pair_sweep_args, check=False).returncode != 0
            stop_partial_watch("pairs")
            watched_pair = start_partial_watch("pairs", pair_watch_args, apply=True)
            assert watched_pair["apply"] and watched_pair["sweep"]["items"][0]["status"] == "retained"
            stop_partial_watch("pairs")
            inside("mkdir", "-m", "700", pair_keys + "/orphan")
            rejected_pair_sweep = inside("oimobbs", *pair_sweep_args, "--apply", check=False)
            assert rejected_pair_sweep.returncode != 0 and json.loads(rejected_pair_sweep.stdout)["rejected_count"] == 1
            assert inside("test", "-d", pair_keys + "/orphan").returncode == 0
            watched_pair = start_partial_watch("pairs", pair_watch_args, apply=True)
            assert watched_pair["status"] == "needs_attention"
            stop_partial_watch("pairs")
            assert inside("test", "-f", pair_roots + "/one/manifest.json").returncode == 0
            assert inside("test", "-f", pair_keys + "/one/bundle.json").returncode == 0
            for kind, roots, plans, completion in (("body", partial_body_roots, partial_body_plans, "manifest.json"), ("keys", partial_key_roots, partial_key_plans, "bundle.json")):
                partial_sweep_args = ["backup", "sweep-partial", "--kind", kind, "--root-parent", roots, "--plan-parent", plans, "--trust-instance", trust_instance]
                partial_watch_args = ["backup", "watch-partial"] + partial_sweep_args[2:]
                protected = inside("oimobbs", *partial_sweep_args, "--apply", check=False)
                assert protected.returncode != 0 and json.loads(protected.stdout)["rejected_count"] == 1 and json.loads(protected.stdout)["kind"] == kind
                assert inside("test", "-f", roots + "/one/" + completion).returncode == 0
                inside("mv", roots + "/one/" + completion, "/tmp/saved-sweep-" + kind + ".json")
                for extra in ([], ["--apply"]):
                    swept_partial = json.loads(inside("oimobbs", *partial_sweep_args, *extra).stdout)
                    assert swept_partial["kind"] == kind and swept_partial["items"][0]["status"] == "retained" and not swept_partial["items"][0]["reclaim"]["verified"]
                assert json.loads(inside("oimobbs", *partial_sweep_args, "--after", "one").stdout)["items"] == []
                watched_partial = start_partial_watch(kind, partial_watch_args)
                assert watched_partial["kind"] == kind and watched_partial["status"] == "completed" and not watched_partial["apply"]
                assert inside("oimobbs", *partial_watch_args, check=False).returncode != 0
                concurrent_partial = inside("oimobbs", *partial_sweep_args, "--apply", check=False)
                assert concurrent_partial.returncode != 0 and json.loads(concurrent_partial.stdout)["items"] == []
                stop_partial_watch(kind)
                inside("mv", plans + "/one.json", "/tmp/saved-sweep-plan-" + kind + ".json")
                missing_partial_plan = inside("oimobbs", *partial_sweep_args, "--apply", check=False)
                assert missing_partial_plan.returncode != 0 and json.loads(missing_partial_plan.stdout)["rejected_count"] == 1
                watched_partial = start_partial_watch(kind, partial_watch_args, apply=True)
                assert watched_partial["status"] == "needs_attention" and watched_partial["sweep"]["rejected_count"] == 1
                stop_partial_watch(kind)
                inside("mv", "/tmp/saved-sweep-plan-" + kind + ".json", plans + "/one.json")
                watched_partial = start_partial_watch(kind, partial_watch_args, apply=True)
                assert watched_partial["apply"] and watched_partial["sweep"]["items"][0]["status"] == "retained"
                stop_partial_watch(kind)
                assert inside("test", "-d", roots + "/one").returncode == 0
            keys_partial_args = ["backup", "reclaim-keys-partial", "--input", "/tmp/export-planned-keys", "--trust-instance", trust_instance, "--plan", "/tmp/export-partial-keys-plan.json"]
            completed_partial_keys = inside("oimobbs", *keys_partial_args, "--apply", check=False)
            assert completed_partial_keys.returncode != 0 and not json.loads(completed_partial_keys.stdout)["applied"]
            inside("mv", "/tmp/export-planned-keys/bundle.json", "/tmp/saved-export-bundle.json")
            partial_keys_preview = json.loads(inside("oimobbs", *keys_partial_args).stdout)
            assert not partial_keys_preview["expired"] and not partial_keys_preview["applied"] and not partial_keys_preview["verified"]
            partial_keys_apply = json.loads(inside("oimobbs", *keys_partial_args, "--apply").stdout)
            assert not partial_keys_apply["applied"] and inside("test", "-f", "/tmp/export-planned-keys/keys/master-000001.key").returncode == 0
            partial_args = ["backup", "reclaim-partial", "--input", planned_copy, "--trust-instance", trust_instance, "--plan", partial_plan]
            complete_refused = inside("oimobbs", *partial_args, "--apply", check=False)
            assert complete_refused.returncode != 0 and not json.loads(complete_refused.stdout)["applied"]
            assert inside("test", "-f", planned_copy + "/manifest.json").returncode == 0
            # 完成印欠落を模擬する。実コピー途中の取消と期限切れ適用はGoの境界/時計注入で検証する。
            inside("mv", planned_copy + "/manifest.json", "/tmp/saved-planned-manifest.json")
            for extra in ([], ["--apply"]):
                partial_retained = json.loads(inside("oimobbs", *partial_args, *extra).stdout)
                assert not partial_retained["expired"] and not partial_retained["applied"] and not partial_retained["verified"]
            original_partial_plan = inside("cat", partial_plan).stdout
            forged_partial = json.loads(original_partial_plan)
            forged_partial["plan"]["root"] = "/"
            forged_partial["plan_sha256"] = hashlib.sha256(json.dumps(forged_partial["plan"], separators=(",", ":")).encode()).hexdigest()
            inside("sh", "-c", "cat >" + partial_plan, data=json.dumps(forged_partial, separators=(",", ":")).encode())
            rejected_partial = inside("oimobbs", *partial_args, "--apply", check=False)
            assert rejected_partial.returncode != 0 and json.loads(rejected_partial.stdout)["applied"] is False
            assert inside("test", "-d", planned_copy).returncode == 0
            inside("sh", "-c", "cat >" + partial_plan, data=original_partial_plan)
            planned_reclaim_args = ["backup", "reclaim-keys-planned", "--input", "/tmp/paired-keys/pair", "--trust-instance", trust_instance, "--plan", keys_plan]
            for extra in ([], ["--apply"]):
                key_retained = json.loads(inside("oimobbs", *planned_reclaim_args, *extra).stdout)
                assert not key_retained["expired"] and not key_retained["applied"] and not key_retained["verified"]
            original_key_plan = inside("cat", keys_plan).stdout
            forged_key_plan = json.loads(original_key_plan)
            forged_key_plan["plan"]["root"] = "/"
            forged_payload = json.dumps(forged_key_plan["plan"], separators=(",", ":")).encode()
            forged_key_plan["plan_sha256"] = hashlib.sha256(forged_payload).hexdigest()
            inside("sh", "-c", "cat >" + keys_plan, data=json.dumps(forged_key_plan, separators=(",", ":")).encode())
            assert inside("oimobbs", *planned_reclaim_args, "--apply", check=False).returncode != 0
            assert inside("test", "-f", "/tmp/paired-keys/pair/keys/master-000001.key").returncode == 0
            inside("sh", "-c", "cat >" + keys_plan, data=original_key_plan)
            assert not json.loads(inside("oimobbs", *planned_reclaim_args, "--apply").stdout)["applied"]
            key_sweep_args = ["backup", "sweep-keys-planned", "--keys-parent", "/tmp/paired-keys", "--plan-parent", key_plan_parent, "--trust-instance", trust_instance]
            key_watch_args = ["backup", "watch-keys-planned"] + key_sweep_args[2:]
            for extra in ([], ["--apply"]):
                key_sweep = json.loads(inside("oimobbs", *key_sweep_args, *extra).stdout)
                assert len(key_sweep["items"]) == 1 and key_sweep["items"][0]["status"] == "retained"
                assert not key_sweep["items"][0]["reclaim"]["applied"] and not key_sweep["restore_ready"]
            assert json.loads(inside("oimobbs", *key_sweep_args, "--after", "pair").stdout)["items"] == []
            def start_key_watch(apply=False):
                """署名計画watchの独立プロセスを起動し、初回JSONを待つ。"""
                inside("sh", "-c", "umask 077; : >/tmp/key-watch.jsonl; test ! -e /tmp/key-watch.exit || rm /tmp/key-watch.exit")
                command = "oimobbs " + " ".join(key_watch_args) + (" --apply" if apply else "")
                inside("sh", "-c", "umask 077; (" + command + " >/tmp/key-watch.jsonl 2>/tmp/key-watch.err & "
                       'key_watch_pid=$!; echo "$key_watch_pid" >/tmp/key-watch.pid; wait "$key_watch_pid"; '
                       'echo "$?" >/tmp/key-watch.exit) >/tmp/key-watch-wrapper.log 2>&1 &')
                for _ in range(100):
                    report = inside("cat", "/tmp/key-watch.jsonl", check=False).stdout
                    if b"\n" in report:
                        return json.loads(report.splitlines()[0])
                    time.sleep(0.1)
                raise RuntimeError("key watch did not report")
            def stop_key_watch():
                """SIGTERMのexit 0を確認し、鍵親の排他を解放する。"""
                inside("sh", "-c", 'kill -TERM "$(cat /tmp/key-watch.pid)"')
                for _ in range(100):
                    exited = inside("cat", "/tmp/key-watch.exit", check=False)
                    if exited.returncode == 0:
                        assert exited.stdout.strip() == b"0"
                        return
                    time.sleep(0.1)
                raise RuntimeError("key watch did not stop")
            key_watch = start_key_watch()
            assert key_watch["status"] == "completed" and not key_watch["apply"]
            assert key_watch["sweep"]["items"][0]["status"] == "retained"
            assert inside("oimobbs", *key_watch_args, check=False).returncode != 0
            locked_sweep = inside("oimobbs", *key_sweep_args, "--apply", check=False)
            assert locked_sweep.returncode != 0 and json.loads(locked_sweep.stdout)["items"] == []
            stop_key_watch()
            inside("mv", key_plan_parent + "/pair.json", key_plan_parent + "/missing.json")
            missing_plan_sweep = inside("oimobbs", *key_sweep_args, "--apply", check=False)
            assert missing_plan_sweep.returncode != 0 and json.loads(missing_plan_sweep.stdout)["rejected_count"] == 1
            key_watch = start_key_watch(apply=True)
            assert key_watch["status"] == "needs_attention" and key_watch["sweep"]["rejected_count"] == 1
            stop_key_watch()
            inside("mv", key_plan_parent + "/missing.json", key_plan_parent + "/pair.json")
            key_watch = start_key_watch(apply=True)
            assert key_watch["apply"] and key_watch["sweep"]["items"][0]["status"] == "retained"
            stop_key_watch()
            assert inside("test", "-f", "/tmp/paired-keys/pair/keys/master-000001.key").returncode == 0
            def start_expired_watch(apply=False):
                """正本退避中に本文期限watchを起動し、初回JSONを待つ。"""
                inside("sh", "-c", "umask 077; : >/tmp/expired-watch.jsonl; test ! -e /tmp/expired-watch.exit || rm /tmp/expired-watch.exit")
                command = "oimobbs backup watch-expired --copy-parent /tmp/paired-copies --keys-parent /tmp/paired-keys"
                if apply:
                    command += " --apply"
                inside("sh", "-c", "umask 077; (" + command + " >/tmp/expired-watch.jsonl 2>/tmp/expired-watch.err & "
                       'expired_watch_pid=$!; echo "$expired_watch_pid" >/tmp/expired-watch.pid; wait "$expired_watch_pid"; '
                       'echo "$?" >/tmp/expired-watch.exit) >/tmp/expired-watch-wrapper.log 2>&1 &')
                for _ in range(100):
                    report = inside("cat", "/tmp/expired-watch.jsonl", check=False).stdout
                    if b"\n" in report:
                        return json.loads(report.splitlines()[0])
                    time.sleep(0.1)
                raise RuntimeError("expired watch did not report")
            def stop_expired_watch():
                """待機中SIGTERMで正常終了し、同じ親を再利用できることを確認する。"""
                inside("sh", "-c", 'kill -TERM "$(cat /tmp/expired-watch.pid)"')
                for _ in range(100):
                    exited = inside("cat", "/tmp/expired-watch.exit", check=False)
                    if exited.returncode == 0:
                        assert exited.stdout.strip() == b"0"
                        return
                    time.sleep(0.1)
                raise RuntimeError("expired watch did not stop")
            expired_watch = start_expired_watch()
            assert expired_watch["status"] == "completed" and not expired_watch["apply"]
            assert expired_watch["sweep"]["items"][0]["status"] == "retained"
            duplicate_expired = inside("oimobbs", "backup", "watch-expired", "--copy-parent", "/tmp/paired-copies", "--keys-parent", "/tmp/paired-keys", check=False)
            assert duplicate_expired.returncode != 0
            stop_expired_watch()
            inside("mv", "/tmp/paired-keys/pair", "/tmp/paired-keys/other")
            expired_watch = start_expired_watch(apply=True)
            assert expired_watch["status"] == "needs_attention" and expired_watch["sweep"]["rejected_count"] == 1
            assert inside("test", "-f", "/tmp/paired-copies/pair/manifest.json").returncode == 0
            stop_expired_watch()
            inside("mv", "/tmp/paired-keys/other", "/tmp/paired-keys/pair")
            expired_watch = start_expired_watch(apply=True)
            assert expired_watch["apply"] and expired_watch["sweep"]["items"][0]["status"] == "retained"
            stop_expired_watch()
            assert inside("test", "-f", "/tmp/paired-keys/pair/bundle.json").returncode == 0
            independent = json.loads(verify_keys().stdout)
            assert independent["verified"] and not independent["restore_ready"] and independent["backup_id"] == captured["backup_id"]
            rejected_replay = inside("oimobbs", "backup", "verify-replay", "--input", output, "--keys", keys, "--work-parent", "/replay-pressure", check=False)
            assert rejected_replay.returncode != 0 and b"insufficient capacity" in rejected_replay.stderr
            assert not inside("find", "/replay-pressure", "-mindepth", "1").stdout.strip()
            work = "/tmp/replay-work"
            inside("mkdir", "-m", "700", work)
            replayed = json.loads(inside("oimobbs", "backup", "verify-replay", "--input", output, "--keys", keys, "--work-parent", work).stdout)
            assert replayed["verified"] and replayed["replayed"] and not replayed["restore_ready"]
            assert not inside("find", work, "-mindepth", "1").stdout.strip()
            stale = work + "/.backup-replay-fixture"
            inside("mkdir", "-m", "700", stale, stale + "/keys")
            inside("sh", "-c", "umask 077; : >" + stale + "/.lock")
            inside("cp", keys + "/keys/master-000001.key", stale + "/keys/master-000001.key")
            device, inode = inside("stat", "-c", "%d %i", stale).stdout.decode().split()
            original_manifest = inside("cat", output + "/manifest.json").stdout
            now = datetime.datetime.now(datetime.timezone.utc)
            plan = {"schema": 1, "mode": "verification_only", "root": stale, "device": device, "inode": inode,
                    "created_at_ns": str(time.time_ns()), "backup_manifest_sha256": hashlib.sha256(original_manifest).hexdigest(),
                    "backup": json.loads(original_manifest)["manifest"],
                    "journal_days": [now.strftime("%Y%m%d"), (now + datetime.timedelta(days=1)).strftime("%Y%m%d")]}
            plan_raw = json.dumps(plan, separators=(",", ":")).encode()
            master = bytearray(inside("cat", keys + "/keys/master-000001.key").stdout)
            cleanup_key = bytearray(fixture_mac(master, b"oimo/key/v1", b"backup_replay_cleanup", b"1"))
            try:
                plan_mac = fixture_mac(cleanup_key, b"oimo/backup-replay-cleanup/v1", plan_raw).hex()
            finally:
                master[:] = bytes(len(master))
                cleanup_key[:] = bytes(len(cleanup_key))
            plan_envelope = {"manifest": plan, "manifest_sha256": hashlib.sha256(plan_raw).hexdigest(), "manifest_mac": plan_mac}
            plan_bytes = json.dumps(plan_envelope, separators=(",", ":")).encode()
            gate = stale + "/backup-replay.json"
            inside("sh", "-c", "umask 077; cat >" + gate, data=plan_bytes)
            def reclaim_work(apply=False, check=True):
                return inside("oimobbs", "backup", "reclaim-replay", "--input", stale, "--keys", keys,
                              *(["--apply"] if apply else []), check=check)
            preview = json.loads(reclaim_work().stdout)
            assert not preview["applied"] and preview["planned_file_count"] > 3
            def sweep_work(apply=False, check=True):
                return inside("oimobbs", "backup", "sweep-replay", "--work-parent", work, "--keys", keys,
                              "--limit", "1", *(["--apply"] if apply else []), check=check)
            sweep = json.loads(sweep_work().stdout)
            assert len(sweep["items"]) == 1 and sweep["items"][0]["status"] == "verified"
            assert not sweep["more"] and not sweep["restore_ready"]
            def start_watch(apply=False):
                """独立watchの初回報告を待つ。終了コードは所有shellが保存する。"""
                inside("rm", "-f", "/tmp/watch.jsonl", "/tmp/watch.exit")
                command = "oimobbs backup watch-replay --work-parent " + work + " --keys " + keys + " --limit 1"
                if apply:
                    command += " --apply"
                inside("sh", "-c", "umask 077; (" + command + " >/tmp/watch.jsonl 2>/tmp/watch.err & "
                       'watch_pid=$!; echo "$watch_pid" >/tmp/watch.pid; wait "$watch_pid"; '
                       'echo "$?" >/tmp/watch.exit) >/tmp/watch-wrapper.log 2>&1 &')
                for _ in range(100):
                    output = inside("cat", "/tmp/watch.jsonl", check=False).stdout
                    if b"\n" in output:
                        return json.loads(output.splitlines()[0])
                    time.sleep(0.1)
                raise RuntimeError("replay watch did not report")
            def stop_watch():
                """SIGTERMで待機を解除し、正常終了と排他解放を確認する。"""
                inside("sh", "-c", 'kill -TERM "$(cat /tmp/watch.pid)"')
                for _ in range(100):
                    exit_code = inside("cat", "/tmp/watch.exit", check=False)
                    if exit_code.returncode == 0:
                        assert exit_code.stdout.strip() == b"0"
                        return
                    time.sleep(0.1)
                raise RuntimeError("replay watch did not stop")
            watched = start_watch()
            assert watched["status"] == "completed" and not watched["apply"]
            assert watched["sweep"]["items"][0]["status"] == "verified"
            duplicate = inside("oimobbs", "backup", "watch-replay", "--work-parent", work, "--keys", keys, check=False)
            assert duplicate.returncode != 0
            stop_watch()
            inside("sh", "-c", "umask 077; : >" + stale + "/unlisted")
            assert reclaim_work(apply=True, check=False).returncode != 0
            rejected = sweep_work(apply=True, check=False)
            assert rejected.returncode != 0 and json.loads(rejected.stdout)["rejected_count"] == 1
            inside("test", "-f", stale + "/keys/master-000001.key")
            inside("rm", stale + "/unlisted")
            plan["root"] = "/"
            bad_raw = json.dumps(plan, separators=(",", ":")).encode()
            plan_envelope["manifest_sha256"] = hashlib.sha256(bad_raw).hexdigest()
            inside("sh", "-c", "cat >" + gate, data=json.dumps(plan_envelope, separators=(",", ":")).encode())
            assert reclaim_work(apply=True, check=False).returncode != 0
            inside("test", "-f", stale + "/keys/master-000001.key")
            inside("sh", "-c", "cat >" + gate, data=plan_bytes)
            inside("rm", stale + "/keys/master-000001.key")
            watched = start_watch(apply=True)
            cleaned = watched["sweep"]
            assert cleaned["items"][0]["status"] == "reclaimed" and not cleaned["restore_ready"]
            stop_watch()
            assert not json.loads(sweep_work().stdout)["items"]
            assert inside("test", "-e", stale, check=False).returncode != 0
            assert json.loads(verify_keys().stdout)["verified"]
            retained = json.loads(inside("oimobbs", "backup", "reclaim-with-keys", "--input", output,
                                        "--keys", keys, "--apply").stdout)
            assert not retained["expired"] and not retained["applied"] and not retained["restore_ready"]
            inside("mv", "/data/source-unavailable", "/data/site")
            seed_path = keys + "/keys/evidence-000010.seed"
            inside("sh", "-c", "cp " + seed_path + " /tmp/original-seed; printf 'bad' >" + seed_path)
            assert verify_keys(check=False).returncode != 0
            inside("sh", "-c", "cat /tmp/original-seed >" + seed_path + "; rm /tmp/original-seed")
            assert json.loads(verify_keys().stdout)["verified"]
            manifest_path = output + "/manifest.json"
            envelope = json.loads(inside("cat", manifest_path).stdout)
            envelope["manifest"]["id"] = uuid.uuid4().hex
            payload = json.dumps(envelope["manifest"], separators=(",", ":")).encode()
            checksum = hashlib.sha256(payload).hexdigest()
            modified = b'{"manifest":' + payload + b',"manifest_sha256":"' + checksum.encode() + b'","manifest_mac":"' + envelope["manifest_mac"].encode() + b'"}'
            inside("sh", "-c", "cat >" + manifest_path, data=modified)
            rejected = inside("oimobbs", "backup", "verify", "--input", output, "--config", "/tmp/config.json", check=False)
            assert rejected.returncode != 0 and b"authentication failed" in rejected.stderr
            assert verify_keys(check=False).returncode != 0
            backup_checks = ["scheduled preparation preview default and unique outputs", "scheduled preparation four plans and isolated replay", "scheduled preparation duplicate watch and concurrent next refusal", "scheduled preparation SIGTERM and apply restart", "scheduled preparation busy source deferred and outputs retained", "pair sweep source-free v2 preview/apply retention and cursor", "pair watch duplicate/concurrent sweep refusal", "pair watch SIGTERM and apply restart", "pair keys-only orphan rejection and needs attention", "related plan v2 automatic and manual registration", "related plan preview/apply retains fresh registered plans", "related plan missing/tamper rejected without output deletion", "pair plan saved during prepare and isolated replay", "all four plans during prepare", "pair plan duplicate rejected before body", "prepared pair plan retained without source", "ordered pair signed plan", "ordered pair duplicate plan failure JSON", "ordered pair preview/apply retains fresh outputs without source", "ordered pair unbound missing body refused", "ordered pair signature tamper refused", "complete key plan saved during prepare", "all three plans during prepare and isolated replay", "complete key plan duplicate refused before body", "prepared complete key plan verified without source", "partial body and key sweep preserve completed outputs", "partial body and key preview/apply without source", "partial sweep cursors and rejection JSON", "partial watches duplicate/concurrent sweep refused", "partial watches SIGTERM exit zero and restart", "partial watches missing plans need attention", "body and key plans in one preparation", "planned key export and duplicate/busy JSON", "completed keys protected from partial reclaim", "fresh partial keys retained without source", "key plan preflight precedes body capture", "planned prepare and isolated replay", "planned prepare duplicate plan refused before copy", "planned prepare completed body protected without source", "planned capture and legacy verification", "planned capture duplicate/busy failure JSON", "completed copy partial reclaim refused", "partial copy preserved without source", "partial plan rehash forgery refused", "planned key sweep preview/apply without source", "planned key sweep cursor and rejection JSON", "planned key watch preview/apply preserves fresh keys", "duplicate key watch and concurrent sweep refused", "key watch SIGTERM exit zero and restart", "missing plan watch needs attention", "public trust export", "signed key plan creation", "busy source key plan refused", "planned key preview/apply preserves fresh bundle without source", "key plan rehash forgery refused", "expired watch preview without source", "duplicate expired watch refused", "expired watch SIGTERM exit zero", "expired watch restart and key refusal", "expired watch apply preserves fresh body and keys", "paired expiry sweep preview/apply preserves fresh body", "missing paired keys refused without deletion", "paired sweep cursor", "prepare full pipeline", "prepare preflight failure JSON", "prepare busy source refused", "key bundle export", "unexpired keys preserved", "verification without source", "isolated WAL/pack/signature replay", "replay work removed", "replay capacity rejection without output", "replay cleanup preview", "replay sweep preview", "watch preview", "duplicate watch refused", "watch SIGTERM exit zero", "watch restart and apply", "sweep rejection JSON", "unlisted work refused", "cleanup plan rehash tamper refused", "partial work reclaimed without source", "unexpired backup preserved without source", "key tamper rejected", "backup binding enforced", "backup capture", "backup verification", "keys and old generations excluded", "unexpired backup preserved", "source advanced", "manifest rehash tamper rejected"]
        print(json.dumps({"status": "PASS", "image": args.image,
                          "checks": ["post", "preview", "reader migration", "compact", "reclaim", "restart", "dedup", "reply", "Range", "ETag", "recompact", "maintenance preview", "maintenance apply", "automatic maintenance"] + backup_checks,
                          "dat_sha256": hashlib.sha256(final).hexdigest()}))
    finally:
        if created:
            docker("rm", "-f", name)


if __name__ == "__main__":
    main()
