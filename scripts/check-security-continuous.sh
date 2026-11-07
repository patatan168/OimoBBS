#!/usr/bin/env bash
# 認証・公開境界・保存parserを固定Goで定期検査し、fuzzと公式脆弱性検査を実行する。
set -euo pipefail
cd "$(dirname "$0")/.."
test "$(go version | cut -d' ' -f3)" = go1.27.3
case "${1:-}" in ''|--fuzz-only) ;; *) exit 2 ;; esac
if [ "${1:-}" != --fuzz-only ]; then
go test -race ./internal/waf ./internal/adminauth ./internal/securityaudit ./internal/publicedge ./internal/sealedbackup ./internal/delivery
go test -race ./cmd/oimobbs -run 'TestPublicListener|TestAdminListener|TestEdgeListener'
go test -race ./internal/quicv1 ./internal/http3native ./internal/httptransport
go test -race ./internal/bootstrap -run 'TestSecurityTransportHeaders|TestHTTPPathSecurityBoundary|TestAdminBrowserBoundaryBeforeLoginNonce|TestAdministratorBrowserFormOriginPolicy|TestAdminHTTPPrivilegeBoundaries|TestPrivateReportsRequireExplicitPermission|TestPublicReportResponseReleasesSiteMutex|TestEvidenceAPIResponse|TestAdminSecretResponse|TestAdminOTPSecretResponse|TestAdminQueuedSessionLogout|TestAdminPasskeyLoginCredentialOwnership|TestUnauthenticatedAdminRouteMatrix|TestWAFTransportRouteCoverage|TestWAFAdminAssetSourceInspection|TestWSTG|TestDomainRule|TestProxy|TestNetworkFetch|TestNetworkFeedRowBoundaries|TestNetworkOversizedFeedPreservesPublishedState|TestSnapshotAssignedBoardCategory|TestWAFIngress|TestWAFTraffic|TestMemoryRejectsUnreceivedBody' -timeout=10m
go vet ./cmd/... ./internal/... ./tools/...
python3 scripts/check-deps.py
python3 -m unittest discover -s scripts -p 'test_probe*.py'
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
  './internal/zstddecode FuzzDecode' \
  './internal/quicv1 FuzzPacketHeader' \
  './internal/quicv1 FuzzReassembly' \
  './internal/quicv1 FuzzReassemblySequence' \
  './internal/quicv1 FuzzQUICFrames' \
  './internal/quicv1 FuzzDestinationControl' \
  './internal/quicv1 FuzzKeyUpdateSequence' \
  './internal/quicv1 FuzzSendStateSequence' \
  './internal/quicv1 FuzzVarint' \
  './internal/http3native FuzzQPACKDecode' \
  './internal/http3native FuzzQPACKInstructions'; do
  read -r package fuzz <<< "$target"
  go test "$package" -run '^$' -fuzz "^${fuzz}$" -fuzztime="${OIMO_FUZZ_SECONDS:-20}s" -parallel=2
done
if [ "${1:-}" != --fuzz-only ]; then
  bash scripts/check-security.sh
fi
