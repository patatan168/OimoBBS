#!/usr/bin/env python3
"""bootstrapの全試験を一つのraceバイナリから分割実行し、網羅と結果を保存する。"""
import argparse
import concurrent.futures
import hashlib
import json
import pathlib
import re
import subprocess
import tempfile


def run_shard(binary, output, index, names):
    """割り当てた親試験と全子試験を実行し、失敗時も出力を残す。"""
    pattern = "^(" + "|".join(re.escape(name) for name in names) + ")$"
    log = output / f"shard-{index:02d}.log"
    with log.open("w") as stream:
        result = subprocess.run(
            [str(binary), "-test.run", pattern, "-test.count=1", "-test.timeout=60m"],
            cwd=pathlib.Path(__file__).resolve().parents[1] / "internal/bootstrap",
            stdout=stream, stderr=subprocess.STDOUT, check=False,
        )
    return {"index": index, "tests": names, "exit_code": result.returncode, "log": log.name}


def main():
    """全親試験を一度ずつ割り当て、同じraceバイナリで全件検査する。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    output = args.output or pathlib.Path(tempfile.mkdtemp(prefix="oimobbs-bootstrap-race-"))
    output.mkdir(parents=True, exist_ok=True)
    output = output.resolve()
    if any(output.iterdir()):
        raise RuntimeError("結果の保存先には空のディレクトリを指定してください")
    with tempfile.TemporaryDirectory(prefix="oimobbs-race-binary-") as root:
        binary = pathlib.Path(root) / "bootstrap.test"
        subprocess.run(["go", "test", "-race", "-c", "-o", str(binary), "./internal/bootstrap"], check=True)
        names = subprocess.check_output(
            [str(binary), "-test.list", "^(Test|Example|Fuzz)"], text=True,
        ).splitlines()
        if not names or len(names) != len(set(names)):
            raise RuntimeError("試験一覧が空または重複しています")
        shards = [names[index::16] for index in range(16)]
        assigned = [name for shard in shards for name in shard]
        if sorted(assigned) != sorted(names):
            raise RuntimeError("分割後の試験一覧が元の全件と一致しません")
        report = {"package": "oimobbs/internal/bootstrap", "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "tests": names, "shards": shards, "results": []}
        manifest = output / "results.json"
        manifest.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        print(f"全{len(names)}試験、16分割、同時4実行。結果: {output}", flush=True)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            tasks = [pool.submit(run_shard, binary, output, index, shard) for index, shard in enumerate(shards)]
            for task in concurrent.futures.as_completed(tasks):
                result = task.result()
                report["results"].append(result)
                manifest.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
                print(f"分割{result['index']:02d}: {len(result['tests'])}試験、終了{result['exit_code']}", flush=True)
        return int(any(result["exit_code"] != 0 for result in report["results"]))


if __name__ == "__main__":
    raise SystemExit(main())
