"""Go依存を標準・自モジュール・固定Argon2内部依存に限定する。"""
import json
import subprocess

module = json.loads(subprocess.check_output(["go", "mod", "edit", "-json"]))
allowed_modules = {"golang.org/x/crypto": "v0.58.0", "golang.org/x/sys": "v0.49.0"}
actual = {item["Path"]: item["Version"] for item in module.get("Require", [])}
if actual != allowed_modules or module.get("Replace") or module.get("Exclude"):
    raise SystemExit("only pinned Argon2 modules are allowed; replacements/exclusions are forbidden")
allowed_packages = {"golang.org/x/crypto/argon2", "golang.org/x/crypto/blake2b", "golang.org/x/sys/cpu"}
subprocess.run(["go", "mod", "verify"], check=True)
stream = subprocess.check_output(["go", "list", "-deps", "-test", "-json", "./cmd/...", "./internal/...", "./tools/..."], text=True)
decoder = json.JSONDecoder()
count = 0
while stream.strip():
    obj, end = decoder.raw_decode(stream.lstrip())
    stream = stream.lstrip()[end:]
    info = obj.get("Module", {})
    if not obj.get("Standard") and not info.get("Main") and (obj["ImportPath"] not in allowed_packages or allowed_modules.get(info.get("Path")) != info.get("Version")):
        raise SystemExit(f"unexpected external dependency: {obj['ImportPath']}")
    count += 1
print(f"PASS: {count} packages, standard library/own module/pinned Argon2 dependencies only")
