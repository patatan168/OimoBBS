#!/usr/bin/env bash
# Goと依存関係の隔離更新・検証をPythonの更新器へ渡す。
set -euo pipefail
cd "$(dirname "$0")/.."
exec python3 scripts/update-dependencies.py "$@"
