"""Go依存をレビュー済みの固定一覧と照合し、改変・置換・未登録依存を拒否する。"""
from pathlib import Path
import json
import subprocess

module = json.loads(subprocess.check_output(["go", "mod", "edit", "-json"]))
allowed_modules = json.loads(Path(__file__).with_name("go-dependencies.json").read_text())
actual = {item["Path"]: item["Version"] for item in module.get("Require", [])}
if actual != allowed_modules or module.get("Replace") or module.get("Exclude"):
    raise SystemExit("go.mod differs from reviewed dependency pins; replacements/exclusions are forbidden")

subprocess.run(["go", "mod", "verify"], check=True)
stream = subprocess.check_output(["go", "list", "-deps", "-test", "-json", "./cmd/...", "./internal/...", "./tools/..."], text=True)
decoder = json.JSONDecoder()
count = 0
while stream.strip():
    obj, end = decoder.raw_decode(stream.lstrip())
    stream = stream.lstrip()[end:]
    info = obj.get("Module", {})
    if not obj.get("Standard") and not info.get("Main") and (allowed_modules.get(info.get("Path")) != info.get("Version")):
        raise SystemExit(f"unexpected external dependency: {obj['ImportPath']}")
    count += 1
print(f"PASS: {count} packages, standard library/own module/reviewed pinned dependencies only")
