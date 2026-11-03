# セキュリティの検証

Web脆弱性、WAFの入力境界、検出ログと全板規制を確認する手順です。[共通の準備と確認範囲](README.md)を先に確認し、コマンドはリポジトリのルートで実行します。

## 手順を選ぶ

- [セキュリティ](#セキュリティ)
- [Web脆弱性の回帰検査](#web脆弱性の回帰検査)
- [WAFの入力境界と管理画面](#wafの入力境界と管理画面)
- [WAF検出ログと掲示板全体の投稿規制](#waf検出ログと掲示板全体の投稿規制)

## セキュリティ

### TLS前の接続頻度と接続の再利用

```sh
mise exec -- go test -race ./internal/delivery ./cmd/oimobbs \
  -run 'TestConnectionRate|TestPublicListener|TestAdminListener|TestEdgeListener' -count=10
```

同時接続数を1本に抑えて作り直す場合の拒否、全体・回線の頻度、IPv6 /64とIPv4-mapped形式の共有、拒否時の未記録、4096件の索引上限と回復、並行受付を確認します。実TLSでは超過接続がTLSのコールバックに届かず、既存のHTTP/1・HTTP/2接続と別回線の要求を継続できることを検査します。認証済み中継とローカル管理トンネルの集約接続も確認します。

隔離Dockerで正常投稿・大量投稿・低速通信とTLS再接続を同時に測る場合は、既定WAFと以下の入口を使います。固定した毎秒400回×12秒のTLS再接続だけを追加し、任意の外部URLには接続しません。

```sh
mise exec -- python3 scripts/probe-thread-resources.py \
  --attack-mix --attack-tls-churn --attack-normal-rate 20 --waf \
  --image <ローカルイメージ> --cpus 2 --memory 512m \
  --egress-bps 80000000 --output var/connection-rate.json
```

[変更前後の比較記録](connection-rate-20261103.md)に全試行と確認範囲を記載しています。TLS前の切断をHTTP429へ数えず、攻撃の予定・実発行・未発行、正常投稿の全件成功、DAT照合、CPU・メモリ・OOMを分けて記録します。

### Web脆弱性の回帰検査

```sh
mise exec -- go test -race ./internal/bootstrap -run '^TestWSTG' -count=1
```

隔離したデータとHTTPで、秘密ファイルの推測URL、CSRF、重複ヘッダー、JSONの重複キー・未知フィールド、本文上限、不正なHTTP本文長を検査します。拒否応答に加えて、保存状態が変わらないことと、正当な要求が成功することも確認します。HTTPの検査は[継続検査](../../scripts/check-security-continuous.sh)にも含まれます。

[ブラウザー検査の準備](README.md#ブラウザー検査の準備)で示す環境変数を指定すると、`TestWSTGBrowser` がChromiumで投稿・確認画面・通報管理画面の保存型XSSと、別Originからの管理フォーム送信を検査します。環境変数を省略した場合、ブラウザ検査はスキップされます。

実施範囲・証跡・未検証項目は[2026-10-23の診断記録](security-review-2026-10-23.md)を参照してください。

### WAFの入力境界と管理画面

クエリ128／129項目、同名・空項目、percent符号化された区切り、本文の未読、クエリ件数の拒否判定で追加割当がないことを確認します。ヘッダーの禁止byte・UA合計1KiB・128項目・16KiB、設定済みHost、公開64KiB・管理256KiBの宣言本文長も検査します。

`TestWAFIngressRawHTTP` はTCPからのHTTP/1で、Go標準パーサーの400・431とWAFの403を区別します。`Expect: 100-continue` で本文を送らずに拒否できること、`TestWAFIngressHTTP2KeepsOtherStreamsUsable` で拒否後も同じ接続の別streamを使えることも確認します。既存の検知・ON/OFF・認証・CSRF・保存・再送・再起動を含め、次を実行します。

```sh
mise exec -- go test -race ./internal/waf ./internal/bootstrap \
  -run 'TestInspect|TestInspection|TestWAF' -count=1 -timeout=10m
OIMO_WAF_PAGE_OUTPUT=/tmp/oimo-waf-page.html mise exec -- go test ./internal/bootstrap \
  -run '^TestWAFManagementPageFixture$' -count=1
OIMO_WAF_PAGE_OUTPUT=/tmp/oimo-waf-page.html OIMO_CHROME=/path/to/chromium \
  node scripts/smoke-waf-ui.mjs
```

ブラウザ検査にはNode.js24以降とChromiumが必要です。320・390・700・1280・1920pxで横幅、詳細の開閉、編集値の保持、閉じた項目を含む22項目の送信データを確認します。JavaScriptなしの開閉も確認します。fixtureでの画面検査と、実HTTPでの保存・再起動を区別して記録します。

## WAF検出ログと掲示板全体の投稿規制

```sh
mise exec -- go test -race ./internal/securitylog -count=1
mise exec -- go test ./internal/securitylog ./internal/bootstrap -run 'Test(Security|RetentionRestartAndCounts|BoundedSamplesKeepCounts)' -count=1
mise exec -- go test -race ./internal/securitylog ./internal/bootstrap -run 'TestSecurity|TestRetentionRestartAndCounts|TestBoundedSamplesKeepCounts' -count=1
```

`securitylog`の全検査には、集計行の再利用と完全再読込みの件数一致、保存失敗後の破棄、ファイルの置換・削除・破損、保持上限・期限、不正UTF-8の再読込みとの一致も含みます。

[ブラウザー検査の準備](README.md#ブラウザー検査の準備)の環境変数を設定して実フォームを確認します。

```sh
mise exec -- go test ./internal/bootstrap -run '^TestSecurityEventsBrowser$' -count=1 -v
```

`OIMO_SECURITY_SCREENSHOTS`を指定すると320/390/1280pxの画像を保存します。WAFがONの状態で本文の安全な表示、検出・拒否の絞り込み、ログからNGワード入力、再認証、全板規制の保存・解除を確認します。登録済み規制一覧は板別・全板共通の状態フィルター、空結果、詳細の展開、長い条件の表示を実ブラウザで確認します。`TestRegisteredRuleListSearchAcrossPages`は65件の板規制で、表示外の規制の検索・状態別件数・検索条件を変えたカーソルの拒否を検証します。HTTP試験では既存板と新設板への適用、正常投稿、再送、再起動後の保持、snapshot、CSRFを確認します。稼働環境への反映や稼働認証後の操作は別の確認です。

[WAF検出ログ・掲示板全体の規制の検証と稼働反映](waf-log-global-rules.md)に確認範囲と切替時の観測を記録しています。
