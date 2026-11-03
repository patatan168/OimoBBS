# 保存停止を検知するヘルスチェック

2026-11-03。公開トップページだけの監視では、板の保存処理が停止しても正常になる問題に対応しました。稼働環境は変更していません。

## 変更した動作

公開入口へ `/.well-known/oimobbs-health` を追加しました。サイトの終了・保存停止・制御時刻の異常、各板の保存停止と終了済みworkerを検査し、正常時は200と `ok\n`、停止時は503と `unavailable\n` を返します。GETとHEADに同じ状態判定を適用し、キャッシュを禁止します。板名・板数・停止理由は返しません。

検査はサイトlockと板の既存のatomic参照を使います。板の処理列へ新しい要求を入れず、書込・同期・再起動を起こしません。通常の板閉鎖と、まだ正常に動いている処理中の板は異常と判定しません。一覧に出ない板の保存停止も検知します。

接続先・正規URL・edge認証・WAF・閲覧制限・圧縮受入の検査は通常経路を通ります。トップページのHTTP状態は変更せず、正常な別板を継続して利用できます。

CLIはトップページと監視用URLの両方を確認します。二要求で共通の5秒期限を使い、200だけでなく監視用URLの固定本文も照合します。古いサーバーの404や、入口が返す汎用200、空本文、リダイレクトは成功としません。edge構成では従来どおり公開originを使用します。edge自身の `/_edge/health` は保存状態の代わりには使いません。

既存のComposeヘルスチェックは同じCLIを呼ぶため、新しいイメージで保存停止を判定できます。今回は自動再起動の仕組みや稼働構成を追加・変更していません。

## 修正前の再現

新しい試験を使い、公開ルーターとCLI要求部だけを `bf164fb` のソースへ差し替えて確認しました。旧CLIは、トップページが200なら、監視用URLが503・404・不正な200・302でも成功しました。旧ルーターには監視用URLがなく、正常時にも404を返しました。差し替えはGoのoverlayだけで行い、作業中のソースを巻き戻していません。

## 保存障害からの検知と復旧

`TestHealthcheckStorageFailureAndRecovery` では、一時保存先に実ディレクトリの競合を作り、Repository.Postのjournal保存で結果不明を発生させました。停止フラグだけを直接設定する試験とは分けています。

| 条件 | 監視用URL | その他の確認 |
| --- | --- | --- |
| 保存障害の前 | 200 | 正常開始 |
| 一板の保存結果が不明 | 503 | トップ200、当該板subjectは503、別板subjectは200 |
| 停止中に別板へ投稿 | 503 | 別板の投稿が耐久化され、DATを200で取得 |
| 保存先競合だけを除去 | 503 | 停止状態を勝手に解除しない |
| 正常終了・再起動検証後 | 200 | 元の板へ投稿可能。別板のDAT byte・投稿数・ETagも一致 |

サイト停止・終了、worker終了、一覧に出ない板の停止、通常閉鎖、空サイト、HEADの状態と本文抑止も検査しました。板workerを明示的に待機させたまま監視要求が完了することを確認しています。

この保存障害は実ファイルの名前競合です。実ディスクの容量不足やSyncのEIOではありません。投稿はRepository.Postを呼び、HTTPは監視・トップ・subject・DAT経路を確認しています。

## 実TLSとCLI

共通の公開handler・接続context・TLS設定を使い、直結と公開edge経由をそれぞれHTTP/1.1・HTTP/2で確認しました。edgeは実ReverseProxyとmTLSで保存側へ接続し、停止時の503を公開側へ渡します。各条件で正常200、停止503、トップ200、WAFの不正UA拒否403が維持されました。

CLIのGo試験は実TLSで正常応答・停止・経路欠落・不正本文・空本文・トップ停止・リダイレクトを確認し、別途、公開originを通るedge設定の既存試験も更新しました。本番用serveを2回起動する既存試験でも、CLIからトップと監視用URLを取得できることを確認しました。

CGOなしでビルドした実バイナリも、loopback HTTPの合成サーバーへ接続して終了コードを確認しました。

| 合成サーバーの応答 | CLI終了コード |
| --- | ---: |
| トップ200・監視200と正しい本文 | 0 |
| トップ200・監視503 | 1 |
| トップ200・監視200と不正本文 | 1 |
| トップ503 | 1 |
| トップと監視を各3秒遅延 | 1。合計5.031秒で共通期限に到達 |

最後の秒数は一試行のプロセス起動込み実測です。CLI終了コードの試験では実際の保存障害を発生させず、サーバー応答を合成しています。

## 実行した検査と範囲

```sh
mise exec -- go test ./cmd/oimobbs ./internal/publicedge -count=1 -timeout=10m
mise exec -- go test ./internal/bootstrap -run '^TestHealthcheck' -count=1 -timeout=2m
mise exec -- go test -race ./cmd/oimobbs ./internal/bootstrap ./internal/publicedge \
  -run '^TestHealthcheck|^TestEdgeHealthcheck|^TestWebCompressionRequired$|^TestRepositoryPostingIsolationAndStop$|^TestBoardClosureHTTPAndRecovery$|^TestAuthenticatedEdgeTLSAndPosting$|^TestWAFTransportRouteCoverage$' \
  -count=1 -timeout=5m
mise exec -- go vet ./cmd/... ./internal/... ./tools/...
mise exec -- env CGO_ENABLED=0 go build -o var/healthcheck-resilience-20261103/oimobbs ./cmd/oimobbs
mise exec -- python3 -B tools/designcheck/check.py
python3 -B -m unittest discover -s tools/designcheck -p test_doclinks.py
```

原出力・差し替えソース・CLI合成サーバーは `var/healthcheck-resilience-20261103/` に保持しています。修正前の再現は `before-compiled.txt`、TLSの詳細は `after-tls.txt`、最終の状態・DAT確認は `after-final.txt`、raceは `race.txt` と `race-final-dat.txt`、CLIは `cli-process.json` と `cli-edge-all-final.txt` です。`var/` はGit追跡対象外です。

全bootstrap試験・全製品raceの一括実行、稼働環境への反映、WAN、長時間負荷、自動再起動、電源断・実媒体故障は今回の確認範囲に含みません。監視が正常でも、新たなディスク障害が発生していないことや、まだ実行していない保存の成功を保証するものではありません。
