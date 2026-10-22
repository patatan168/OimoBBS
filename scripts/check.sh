#!/usr/bin/env bash
# 固定toolchainで静的検査・競合検査・許可済み依存・CGO無効buildを確認する。
set -euo pipefail
cd "$(dirname "$0")/.."
test "$(go version | cut -d' ' -f3)" = go1.27.3
unformatted=$(gofmt -l internal cmd tools/gentables)
if [ -n "$unformatted" ]; then
  printf '%s\n' "$unformatted"
  exit 1
fi
# var内の使い捨て測定コードを含めず、全製品・検証ツールを対象にする。
package_patterns=(./cmd/... ./internal/... ./tools/...)
go test -timeout=60m "${package_patterns[@]}"
# bootstrapは全件の累積時間で上限に達するため、同じraceバイナリから全親試験を分割する。
race_package_list=$(go list "${package_patterns[@]}")
mapfile -t race_packages < <(printf '%s\n' "$race_package_list" | sed '/^oimobbs\/internal\/bootstrap$/d')
go test -race -timeout=60m "${race_packages[@]}"
python3 scripts/check-bootstrap-race.py
go vet "${package_patterns[@]}"
python3 -B scripts/test_update_dependencies.py
python3 -B scripts/test_setup_certificates.py
python3 scripts/check-deps.py
CGO_ENABLED=0 go build "${package_patterns[@]}"
python3 -B -m unittest discover -s tools/designcheck -p 'test_doclinks.py'
python3 -B tools/designcheck/check.py
bash scripts/check-security.sh
bash scripts/check-security-continuous.sh --fuzz-only
