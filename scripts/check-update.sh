#!/usr/bin/env bash
# 依存更新の日常確認として、認証の重点試験・静的検査・製品ビルド・脆弱性検査を行う。
set -euo pipefail
cd "$(dirname "$0")/.."
printf '%s\n' '更新検証: 依存の整合性'
python3 scripts/check-deps.py
printf '%s\n' '更新検証: 認証の重点試験'
go test -timeout=2m ./internal/adminauth ./internal/securityaudit ./internal/publicedge
go test -timeout=2m ./internal/bootstrap -run '^Test(AdminPasskey(CeremonyBoundaries|HTTPBoundaries|PersistenceAndRecovery|Input|OnlinePasswordReset|LoginRequiresNonce|LoginDoesNotRevealAccount|BeginDoesNotConsumePasswordAttempts|RemovalRevokesSessionsAndPendingLogin)|AdminOTP.*|AdminLoginForms.*|AdminPasswordFailures.*|AdminTemporaryPasswordRecovery|AdminPasswordTemporaryExpiryAndReissue|AdminSiteAdministratorRecoveryIsOfflineOnly|ReauthRequestValidation)$'
printf '%s\n' '更新検証: 静的検査と製品ビルド'
go vet ./cmd/... ./internal/... ./tools/...
CGO_ENABLED=0 go build ./cmd/...
printf '%s\n' '更新検証: 脆弱性検査'
bash scripts/check-security.sh
