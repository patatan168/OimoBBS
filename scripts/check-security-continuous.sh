#!/usr/bin/env bash
# 認証・公開境界・保存parserを固定Goで定期検査し、fuzzと公式脆弱性検査を実行する。
set -euo pipefail
cd "$(dirname "$0")/.."
test "$(go version | cut -d' ' -f3)" = go1.27.2
case "${1:-}" in ''|--fuzz-only) ;; *) exit 2 ;; esac
if [ "${1:-}" != --fuzz-only ]; then
go test -race ./internal/adminauth ./internal/securityaudit ./internal/publicedge ./internal/sealedbackup ./internal/delivery
go test -race ./internal/bootstrap -run 'TestSecurityTransportHeaders|TestHTTPPathSecurityBoundary|TestAdminBrowserBoundaryBeforeLoginNonce|TestAdministratorBrowserFormOriginPolicy|TestProxy|TestNetworkFetch|TestSnapshotAssignedBoardCategory' -timeout=10m
go vet ./cmd/... ./internal/... ./tools/...
python3 scripts/check-deps.py
python3 tools/designcheck/check.py
fi
for target in \
  './internal/publicedge FuzzCanonicalPublicPath' \
  './internal/sealedbackup FuzzArchiveOpen' \
  './internal/strictjson FuzzValidate' \
  './internal/compat FuzzForm' \
  './internal/compat FuzzRange' \
  './internal/store FuzzFrame' \
  './internal/store FuzzDecodePackChunk' \
  './internal/zstddecode FuzzDecode'; do
  read -r package fuzz <<< "$target"
  go test "$package" -run '^$' -fuzz "^${fuzz}$" -fuzztime="${OIMO_FUZZ_SECONDS:-20}s" -parallel=2
done
if [ "${1:-}" != --fuzz-only ]; then
  bash scripts/check-security.sh
fi
