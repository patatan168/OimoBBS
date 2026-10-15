# CPU・メモリ・復旧時間の検証

処理時間・割り当て量を測る単体ベンチマークと、実HTTPのCPU・メモリ・復旧時間を測る負荷試験を分けて確認します。検証は隔離データで実行します。

## 入力と処理結果の一致

厳密JSONの受理条件、投稿署名、類似度の判定、公開表現の分離を確認します。空白・Unicode・不正UTF-8・短文・長文・重複文字と、類似度の境界値を含めます。

```sh
mise exec -- go test -race ./internal/compat ./internal/bootstrap \
  -run 'Guard|Compression|Gzip|FeedCache|LiveRead|Publication'
mise exec -- go test ./internal/bootstrap -run '^$' \
  -fuzz FuzzGuardSignatureAndSimilarity -fuzztime=15s -parallel=2
mise exec -- go test ./internal/strictjson -run '^$' \
  -fuzz FuzzDecodeShapeEquivalence -fuzztime=20s -parallel=2
```

## 単体ベンチマーク

同じ入力・CPU枠・測定時間を使い、時間と割り当て量を分けて比較します。通常本文、反復長文、非反復長文、不一致の署名、公開HTMLキャッシュの命中を分けます。合成長文を測定しても製品の投稿上限は変更しません。

`GOMAXPROCS=2`、`-test.benchtime=500ms`、`-test.benchmem` を基準とし、各条件を複数回実行します。

## 実HTTPの負荷試験

[probe-thread-resources.py](../../scripts/probe-thread-resources.py) を使います。測定対象のイメージを `OIMO_PERF_IMAGE` に設定してください。

```sh
OIMO_PERF_IMAGE=oimobbs-validation:performance-check
mise exec -- python3 scripts/probe-thread-resources.py \
  --image "$OIMO_PERF_IMAGE" \
  --peak-mix --egress-bps 100000000 \
  --peak-post-workers 5 --peak-capacity-workers 20 \
  --optional-log-stats --output var/performance-check.json
```

比較対象は同じCPU・メモリ枠、読者数、投稿数、送信予算、圧縮条件で実行します。cgroupのCPU差分と短い間隔の標本を集計し、メモリは総量とanon/fileを分けます。anonにはGoヒープ以外も含まれます。

| 対象 | 確認する指標 |
| --- | --- |
| CPU | ピーク区間の平均、標本のp95、標本間隔 |
| メモリ | ピーク区間・全期間の最大、anon/file、OOMの有無 |
| 閲覧 | 完了件数、エラー、送信量、帯域待ちによる未発行 |
| 投稿 | 受理件数、連番の一意性、DATの旧版prefix、処理量 |
| 復旧 | 予定時刻から完了までのp95・最大遅延、回復区間終了時の残存投稿 |
| 非必須ログ | 欠測、待機、正常終了 |

フォームの準備・要求の発行待ち・HTTP応答時間を分けて記録します。中央値や応答時間だけで復旧時間を判断しません。

## WAFの追加費用と通常通信

WAFのOFF、URL・ヘッダー検査のみ、検査と大量アクセス制限を同一入力で比較します。

```sh
mise exec -- go test ./internal/bootstrap -run '^$' \
  -bench '^BenchmarkWAFMiddleware$' -benchtime=100000x -count=3 -cpu=1,4
OIMO_WAF_PERFORMANCE=1 OIMO_WAF_PERF_WORKERS=8 \
  mise exec -- go test ./internal/bootstrap \
  -run '^TestWAFPublicReadPerformance$' -count=1 -cpu=2 -v
OIMO_WAF_PERFORMANCE=1 OIMO_WAF_PERF_WORKERS=32 \
  mise exec -- go test ./internal/bootstrap \
  -run '^TestWAFPublicReadPerformance$' -count=1 -cpu=2 -v
```

単体測定では1024回線の小さな応答に対する処理時間と割り当てを確認します。回数指定を100000回以下にすることで、設定した瞬間枠内で追加費用を測ります。実HTTP試験は一時保存領域に合成投稿を作成し、DAT、subject.txt、Range、304、HEAD、板ページを混在させ、8または32並列・各条件8192件・3巡で比較します。条件の実行順を入れ替え、正常応答の完了件数／秒、p95、エラー、割り当て、プロセス全体のCPU使用量、応答本文の転送速度を記録します。割り当てとCPUには同一プロセスの負荷生成側も含みます。`-cpu=2`はGoの並列実行数で、物理CPUの占有やcgroupの制限ではありません。この実HTTP性能試験はLinux向けです。

測定時は通常通信の費用を比べるため頻度枠を引き上げます。初期値の毎秒300件などによる意図した制限を、検査の性能低下と混同しません。単体のns/opの逆数を掲示板全体の処理能力として扱いません。loopback・合成投稿・短い試験の結果であり、長時間のCPUやメモリの安定性、本番ピーク、WANのDDoS耐性を証明しません。

```sh
mise exec -- go test -race ./internal/waf ./internal/bootstrap \
  -run 'TestTraffic|TestWAF' -count=1
mise exec -- go test ./internal/waf -run '^$' \
  -fuzz '^FuzzInspectPathFast$' -fuzztime=15s -parallel=2
```

緩めの瞬間枠、超過後の回復、公開／管理枠の分離、IPv6の集約、4096回線のメモリ上限、処理枠の解放、設定引継ぎ、実TLSでの中継元検証を検査します。高速化した通常パスが従来の注入パターン検出を省略しないことはfuzzでも確認します。

## 結果の扱い

ソース・イメージ、資源枠、負荷条件、実行結果を測定成果物へ記録します。単体の割り当て量はサーバー全体のピークメモリとは区別します。隔離Docker・loopbackの結果から、本番・WAN・実NIC・利用者端末の性能を保証しません。

共通の検査コマンドと確認範囲は[検証方法](README.md)を参照してください。
