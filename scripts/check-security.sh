#!/usr/bin/env bash
# Go公式DBで製品・検証ツールと任意の配布バイナリを検査する。ネットワーク接続が必要。
set -euo pipefail
cd "$(dirname "$0")/.."
if [ "$#" -gt 1 ]; then
  printf '%s\n' 'usage: bash scripts/check-security.sh [binary]' >&2
  exit 2
fi
# 検査ツールはバージョンを固定し、製品のgo.modへ外部依存を追加しない。
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./cmd/... ./internal/... ./tools/...
if [ "$#" -eq 1 ]; then
  go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 -mode=binary "$1"
fi
