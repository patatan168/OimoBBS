# Web経路のHTTP/2・HTTP/3必須化

2026-11-04、専ブラ用URLを除く公開経路と直接HTTPSの管理入口で、HTTP/1.0・HTTP/1.1を拒否する変更をローカルで検証しました。例外のURLは圧縮受け入れ必須化と同じ判定を共有します。仕様と例外一覧は[Webの取得条件](../features/reading.md#webの取得条件)を参照してください。

## 検証範囲

| 対象 | 検査内容 |
| --- | --- |
| 公開Web・公開パスの管理画面 | 実TLSのHTTP/1.1でGET・HEAD・POST・PATCH・OPTIONSを拒否。gzip対応、専ブラUA、Range、条件付き取得でも例外にしない |
| 公開Web・直接HTTPS管理 | 生のHTTP/1.0・HTTP/1.1で未送信の64KiB本文を宣言しても、受信期限を待たずに505・空本文・no-store・Cookieなしで応答し、接続を終了 |
| 専ブラ | 実TLSのHTTP/1.1でCookie確認から投稿保存まで実行。menu・subject・SETTING・head・DATのidentity取得、304、DATの206とHEADを確認 |
| 公開edge | 利用者側がHTTP/1.1、保存側が実HTTP/2の場合も、中継前に505で拒否。管理マウント配下の専ブラに似たパスにも例外を適用しない |
| HTTP/2 | 実TLSで公開ページ・管理ログイン・圧縮・条件付き取得と、mTLS中継・保存状態の監視を確認 |
| HTTP/3 | 外部QUICクライアントから製品の公開handlerとedgeへ接続し、公開ページ・資産・管理ログインを取得。既存のWAF・頻度制限試験も実行 |
| 管理用SSHトンネル内部 | `loopback_tunnel` の実HTTP/1.1でログイン画面とCookie発行を確認。圧縮受け入れ宣言など既存の検査は継続 |

拒否判定では要求本文を読みません。WAFなどが先に拒否した要求では、その403などを優先する場合があります。

関連111親試験の最終実行は109成功、2スキップ（板閉鎖のブラウザ試験と任意の性能測定）でした。既存試験のHTTP/1.1依存による8失敗は、実HTTP/2を使うよう更新した再実行ですべて解消しています。別に板追加・改名のChromium試験を実行し、投稿、旧URL、DAT保持、モバイル・デスクトップ表示とバージョン1.1.0を確認しました。race、HTTP/3相互接続、vet、CGO無効build、文書リンク検査も成功しました。

## 実行コマンド

```sh
mise exec -- go test ./internal/compat ./internal/publicedge ./cmd/oimobbs ./cmd/oimoedge
mise exec -- go test ./internal/bootstrap -run '^Test(PublicAndDirectAdminRejectHTTP1BeforeBody|LegacyHTTP1PublicContracts|WebCompressionTLS|PublicAdminHTTPS|HiddenAdminHTTPS|SharedAdminEdgeUsesAuthenticatedClientIP|HealthcheckTLSAndAuthenticatedEdge|WAFTransportRouteCoverage)$' -count=1
mise exec -- go test -race ./internal/compat ./internal/publicedge ./internal/bootstrap -run '^Test(RequireModernHTTP|LegacyClientPath|EdgeModernHTTPWithHTTP2Upstream|PublicAndDirectAdminRejectHTTP1BeforeBody|LegacyHTTP1PublicContracts|WebCompressionTLS|PublicAdminHTTPS|HealthcheckTLSAndAuthenticatedEdge|WAFTransportRouteCoverage)$' -count=1
python3 scripts/quic-reference.py test -- -race ./internal/bootstrap ./internal/publicedge -run HTTP3 -count=1
mise exec -- go vet ./cmd/... ./internal/... ./tools/...
```

生ログは `var/web-http-policy-20261104/` に保存します。既存の機能試験でHTTPのoriginを使う場合は、隔離サーバーとクライアントの両方で実際の平文HTTP/2を有効にしています。公開製品のTLS設定は変更していません。

実SSH接続、実専ブラ、外部ネットワークからの到達性、稼働サーバーへの反映は、この検証に含みません。
