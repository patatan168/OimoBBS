#!/usr/bin/env bash
# 静的資産を事前生成してから製品をビルドする。引数はgo buildへそのまま渡す。
set -euo pipefail
cd "$(dirname "$0")/.."
go generate ./internal/webui
if [ "$#" -eq 0 ]; then
  mkdir -p bin
  set -- -o bin/oimobbs ./cmd/oimobbs
fi
CGO_ENABLED=0 go build -trimpath "$@"
