# 制限判定と投稿経路の処理削減

2026-11-01。比較元は `2ffdb596f33143933895346a85677fd6efe6e333`。通常運用の制限値、拒否条件、管理設定、保存形式は維持した。制限の解除は比較用ソースと隔離コンテナの設定だけに適用した。稼働サービスへの反映は含まない。

全試行、CPU・メモリ、失敗、ソース・成果物のSHA-256、再実行用スクリプトは[機械可読記録](posting-processing.json)に収録した。生の測定結果とログはGit管理外の `var/posting-burst-corrected-20261101/` に保存した。

## 採用した変更

- `abuse.Limiter` の予約で、最大16件の一時配列をスタックへ置き、重複検査のmap生成を省いた。一般的な4課金以下の予約は一つの割当で済む。完了時は予約中のbucketを直接参照する。確定、返却、不確定、二重完了拒否と実消費量の返却条件は維持した。
- 61分窓の拒否待ち計算は、毎分の窓全体の再走査を、出入りする分の差分更新に変えた。予約中件数とRetry-Afterの条件は維持した。
- 厳密JSONのescape文字列を検査と同時に復号し、標準JSONによる二度目の復号を省いた。UTF-8、NUL、surrogate、重複キー、不正な末尾の拒否と、検証前に候補を公開しない条件を維持した。
- 投稿後に取得するスレッドHTMLのレス部分は、元の `html/template` の自動escape後の構文木から定数と既知fieldだけを取り出し、同じ値のescapeと数値変換を一回にした。外側は標準テンプレートを使う。未対応の式・文脈やURL識別子は標準描画へ戻す。HTMLの定数を別実装へ複製せず、返却byte、ETag、公開条件を維持した。

投稿間隔、投稿枠、WAF、bot・類似投稿・連投の通常ポリシー、reader version 106は変更していない。保存のSyncを省略したり、先に成功を返したりする変更もない。

## 実HTTPSの比較

同じホスト上の隔離Docker、TLS HTTP/1.1、2/4 CPUと同数のGOMAXPROCS、4GiB、送出制御80Mbps。各試行は一つの板・16スレッドへ8,000投稿を5秒の予定到着時間で発行し、完了まで待った。120 actor、専ブラ80%・Web20%。Webはフォーム取得、CSRF付きPOST、303後のgzip HTML取得を含む。別の閲覧負荷は流していない。完了件数をdrainを含む時間で割った値であり、1,600件/秒を継続処理できたという意味ではない。

最初の単一Pythonプロセスの試行では生成器側も約1 CPUを使ったため、主要比較は4プロセス・各30 actorへ分けた。同じ全体到着位置と要求を使い、TLS接続はfork後に一つの子だけが所有する。サーバー比較、ビルド、テスト、単体測定は並行実行していない。回線分類の外部更新を停止し、実際に停止した状態を確認してから測定した。

以下は各版の中央値。ABBA順に実行した。

| 条件 | 旧→新の完了件数/秒 | 旧→新のCPU ms/投稿 | 判断 |
| --- | --- | --- | --- |
| 通常ディスク・2 CPU、各2試行 | 717.2 → 759.9（+5.9%） | 2.339 → 2.170（−7.2%） | この条件で改善 |
| 通常ディスク・4 CPU、各4試行 | 752.5 → 1,022.6 | 2.864 → 2.671（−6.7%） | 完了速度差はI/O変動を含むため改善率に採用しない |
| tmpfs・4 CPU、各2試行 | 1,163.8 → 1,219.3（+4.8%） | 2.901 → 2.689（−7.3%） | 保存待ちを抑えたCPU比較 |

通常ディスク4 CPUの旧版には523.2、445.9件/秒の遅い試行があり、他の旧版は981.7、1,002.1件/秒だった。新版は1,014.2〜1,030.3件/秒。遅い旧版ではI/O pressureが大きく、これを除外したり、観測された+35.9%を実装の効果として扱ったりしない。tmpfsでもアプリのSync呼出しは残すが、永続ディスクの性能・障害耐性の証拠にはならない。

探索段階の単一プロセス版8試行も記録に残した。4 CPUの新版には425.8件/秒のI/O停止を伴う試行があり、もう一方は985.8件/秒だった。この結果を主要比較へ混ぜていない。

24試行の主負荷は合計192,000投稿すべて成功し、要求の再試行、未発行、エラーは0件。各試行の回復負荷100件も成功し、DATの行数・連番・本文照合、OOMなしを確認した。新版は2/4 CPUで通常再起動後にも全16 DATのbyteとidentity ETagを照合した。今回のHTTP比較ではSIGKILLは実施していない。再起動試行の終了ログ統計は再起動後プロセスのものであり、主負荷のログ完全性の根拠にしない。

準備段階で一度、回線設定のCAS競合によるHTTP 412が発生した。測定開始前の失敗として残し、設定用のGET/PATCHだけを新しいETagで再試行するよう修正した。投稿・閲覧の測定要求は再試行していない。

### 比較時だけ解除した条件

両版のコピーで、入口attempt RateSpecの `Disabled` を有効化し、content-rateの件数超過による拒否だけを無効化した。予約処理と履歴・メモリ上限は残した。隔離した管理API設定で投稿rate、WAF traffic、bot・類似・連投モードを無効化し、token waitを0にした。WAFの要求検査、認証、再認証、CSRF、CASは残した。製品ソースの既定値・通常経路へこれらを入れていない。

この比較は頻度制限を解除した際の内部費用を見るもの。通常の制限設定での最大成功件数を示すものではない。

## 制限と描画の単体費用

GOMAXPROCS=1、各3回の中央値。実HTTPの件数改善率とは分けて扱う。

| 処理 | 旧→新 ns/op | 旧→新 allocs/op |
| --- | --- | --- |
| 制限予約・1課金 | 304.1 → 209.1 | 3 → 1 |
| 制限予約・4課金 | 787.3 → 559.1 | 3 → 1 |
| 制限予約・16課金 | 4,012 → 2,201 | 9 → 2 |
| 61分窓の拒否待ち | 5,754 → 336.9 | 0 → 0 |
| escapeを含む投稿JSON文字列 | 2,943 → 700.4 | 4 → 1 |
| 50レスのHTML | 1,117,482 → 321,828 | 5,243 → 898 |

escapeなしJSON文字列は64.59→67.13nsで小幅に悪化した。引用符の多い文字列は2,500→956.3ns、560→512Bになった一方、バッファ拡張で3→7割当に増えた。すべての入力で割当数が減るとはしていない。

## 検証と再実行

次の確認を通した。全bootstrapの再実行結果ではない。環境変数で有効にする任意テストも強制有効化していない。

```sh
go test ./internal/strictjson ./internal/abuse ./internal/domain ./internal/postcapture ./internal/compat ./internal/app ./internal/store ./internal/evidence -timeout=6m
go test -race ./internal/abuse ./internal/strictjson ./internal/bootstrap -run 'TestLimiter|TestDisabled|TestChecked|TestGenerated|TestThreadRendering|TestThreadPage|TestThreadRequest|TestContentRate|TestAbuseGuard|TestAdmission|TestPostingBatch|TestRepositoryPostingCrash|TestWAF' -count=1
go test ./internal/bootstrap -run '^TestThreadRender' -count=1
go vet ./cmd/... ./internal/... ./tools/...
go run ./tools/jsondecodegen -check
mise exec -- bash scripts/build.sh -o var/posting-burst-corrected-20261101/oimobbs-production ./cmd/oimobbs
mise exec -- python3 -B tools/designcheck/check.py
```

窓待ちの旧実装との照合416,775件、escape文字列60,682件、生成復号31,717件、HTML byte一致41,497件、checked復号41,217件のfuzzを実施した。最初のescape用fuzzは有効な周囲空白を比較器が扱えておらず失敗した。比較器を修正し、その入力を回帰corpusとして保持した。

HTMLは不正UTF-8、制御文字、`+`、危険なURL・JavaScript文字列、mail分岐、停止状態を含めて標準描画と比較した。さらにテンプレートの本文をURL・属性・script文脈へ変えた場合と、未知の条件・pipelineでは高速描画を採用しないことを検証した。

HTTPの再実行はJSON内の `reproduction_sources` を同じ相対配置に復元し、`benchmark_only_source_changes` を比較用コピーだけへ適用してDocker imageを作る。`run-mp.py` は `label baseline|candidate 2|4`、tmpfs版は `run-mp-tmpfs.py` を使う。各試行の正確なcommandは `trials` に収録した。生データを上書きしない新しいlabelを使う。

メモリはcgroup peakであり、起動・ファイルキャッシュを含む。tmpfsでは保存データのページも含むため、プロセスRSS削減の主張には使わない。同一ホスト・短時間の隔離HTTPS比較であり、WAN、稼働ホスト、大規模履歴、長時間負荷、電源断の結果は含まない。
