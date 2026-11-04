# Web取得の圧縮対応必須化

2026-10-31、`a8801f1` に対する変更をローカルで検証しました。Webと管理画面のGET/HEADではgzip/zstdの受け入れ宣言を求め、専ブラ用URLのidentity取得を維持します。仕様は[閲覧時の圧縮](../features/reading.md#条件付き取得差分圧縮)を参照してください。

以下は当時の結果です。2026-11-04の[HTTP世代の受付条件](web-http-protocol.md)追加後は、専ブラと管理用SSHトンネル内部を除き、HTTP/1.1では圧縮判定より前に505を返します。

## 確認結果

| 対象 | 結果 |
| --- | --- |
| Webのトップ・板・検索・通報・規約・投稿フォーム・robots・静的資産・read.cgi | 圧縮受入なしのGET/HEADは406、空本文、no-store。専ブラUAやRangeを付けても例外にしない |
| 独立した管理入口 | 非対応要求はログインCookie・nonceを発行する前に406。gzip対応ならログイン画面を取得可能 |
| 公開パス配下の管理画面 | HTTP/1.1とHTTP/2の実TLSで、非対応のログイン・資産GET/HEADが406。gzip対応のログインは200 |
| q値・複数行・ワイルドカード | gzip/zstdの正のq値で受付。明示的なq=0は `*` より優先。全行を検査し、構文不正は400 |
| 専ブラのmenu HTML/JSON・subject・SETTING・head・DAT | identityの200、圧縮宣言なしの条件付き304を維持。DATのRangeはidentityの206 |
| `/test/bbs.cgi`、POSTなどの非取得要求 | 圧縮対応の必須判定を適用しない |
| gzip/zstdのWeb配信 | HTTP/1.1・HTTP/2の実TLSで200とContent-Encodingを確認。展開後の本文がidentity表現と一致し、条件付きGET/HEADは304 |
| identityを優先しgzipも受け入れる要求 | 受付後のidentity応答を維持。受付条件と応答形式の選択を分けて検査 |
| 公開edge | 圧縮宣言の省略・identity・gzip・複数行をそのまま転送。製品transportの `DisableCompression: true` をソース確認 |
| healthcheck | edgeの `/_edge/health` は圧縮宣言なしで200、backendへ転送しない。CLIのhealthcheckは公開originへgzip対応を宣言して取得 |

実TLS試験は製品と共通の `ValidationHTTPServer` のhandler・接続context・TLS設定を使用し、接続先証明書を検証しています。client transportの自動圧縮・展開を無効にし、実際の応答形式とHTTPプロトコルを検査しました。

## 実行した検査

次の検査は成功しました。

```sh
mise exec -- go test ./internal/bootstrap -run '^(TestWebCompressionRequired|TestAdminCompressionBeforeNonce|TestWebCompressionTLS)$' -count=1 -v
mise exec -- go test ./internal/compat ./internal/publicedge -count=1
mise exec -- go test ./cmd/oimobbs -run '^TestEdgeHealthcheckUsesPublicOrigin$' -count=1
mise exec -- go test -race ./internal/bootstrap ./internal/compat ./internal/publicedge -run '^(TestWebCompressionRequired|TestAdminCompressionBeforeNonce|TestWebCompressionTLS|TestRequireCompressedRead|TestPublicEdgePreservesAcceptEncoding)$' -count=1
mise exec -- go vet ./cmd/... ./internal/... ./tools/...
mise exec -- go build -o var/web-compression-required-20261031/oimobbs ./cmd/oimobbs
mise exec -- python3 -B tools/designcheck/check.py
python3 -B -m unittest discover -s tools/designcheck -p 'test_doclinks.py'
```

HTTPサーバー・公開handler・共通閲覧helperを使う64ファイルから210件を選んだ回帰検証では、191件成功、18件スキップ、1件失敗でした。スキップはブラウザ環境などの未指定によるものです。新しい受付条件に合わせて既存の機能テストはgzip対応も宣言し、identity優先で従来の本文・認証・閲覧制限の期待値を検査しています。専ブラのみのidentity試験と、圧縮非対応の拒否試験は別に維持しています。

失敗した `TestBoardCategoriesLargePage` はカテゴリー割当失敗時のHTMLにあるselected属性の検査で、今回の圧縮判定を通らないテンプレート単体テストです。差分対象の既存Goファイルを変更前の `a8801f1` に差し替えたGo overlayでも同じ `failed assignment hidden or lost` を再現しました。今回そのテンプレートや期待値は変更していません。全bootstrapテストの成功を示す結果ではありません。

生ログと選択したテスト名は `var/web-compression-required-20261031/` に保存しました。稼働サーバーへの反映、実ブラウザ・実専ブラ、外部監視サービスでの確認は含みません。
