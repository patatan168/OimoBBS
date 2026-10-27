# 1件のJSON内の並列符号化・復号

2026-10-25。`f9bce38e78aab261a83b9008ba4d0e4716e23aa9`を基準に、大きな配列を含む1件のJSONを複数のCPUで処理するようにした。[全試行・ソース照合値](json-single-parallel.json)を保存する。稼働BBSは変更していない。

## 実装と入力契約

生成済みの保存DTO符号化では、128要素以上のsliceから先頭4要素の実出力を使って処理量を見積もる。推定128KiB以上で、CPU数・64KiBあたり1worker・32要素あたり1workerの範囲で分担する。各workerの出力を元の順番で連結し、先頭4要素も再利用する。JSONのフィールド順、要素順、HTML escape、不正UTF-8の置換、nilと空配列、IDエラーを維持する。

厳密復号では、sliceの要素数を確定する既存の走査でbyte単位の分担境界も集める。128要素・128KiB以上の配列を対象に、構文・深さ・Unicodeを確認してから、型検査・値の構築を分担する。各workerは異なる要素だけを書く。未知・重複・必須キー、null、数値範囲などの検査は維持する。

独自の`UnmarshalJSON`とmap等の標準復号は、**本文全体の検査成功後に元の順番で逐次実行する**。末尾が不正なら呼び出さず、途中失敗した復号先も公開しない。保留処理はworkerから親へ複製せずに保持する。

追加worker枠は符号化・復号の全要求で共有し、合計を`GOMAXPROCS-1`以下にする。呼出元も作業に参加し、枠不足なら待ち行列を作らず逐次処理する。worker内でさらにworkerを作らない。復号時のCPU数の問い合わせは、大きいJSONの開始時の一度にまとめる。小さいJSON、単一コア、サイズ上界の計算は逐次処理し、小さい入力ではcallbackのheap確保も避ける。保存の確定順序・fsync・入力サイズ上限は変更しない。

対象は生成済み符号化のsliceと、ゼロ値の対応型への厳密復号のsliceである。単独の長い文字列、固定長配列だけの文書、既存値へのmerge、特殊タグを使う復号などは従来の逐次経路を使う。すべてのJSONが並列になるわけではない。

## 同じ保存DTOによる比較

AMD Ryzen 5 5500U、Linux、Go1.27.3、共有ホスト。`domain.Append`に投稿を1・128・512件格納し、全件で日本語・絵文字・HTML escape・改行・ID・時刻・非公開情報・入れ子の頻度キーを含めた。JSONはそれぞれ1,796・228,933・916,677bytes。同じbyteと型を前版・変更後で使用し、SHA-256も照合した。CPU数は`GOMAXPROCS`で指定し、専有CPUやcontainer quotaの試験ではない。

各条件3回、300ms以上の測定の中央値。計測中に通常試験・race・fuzz・buildを重ねていない。小さいJSONの差や単一コアの数%の上下を、確定的な改善・劣化とは判断しない。

| 1件に含む投稿数 | CPU数 | 符号化 前→後 µs | 倍率 | 復号 前→後 µs | 倍率 |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 128 | 1 | 583.1 → 596.5 | 0.98 | 2386.7 → 2491.7 | 0.96 |
| 128 | 2 | 627.6 → 427.3 | 1.47 | 2350.6 → 1662.0 | 1.41 |
| 128 | 4 | 571.9 → 345.5 | 1.66 | 2447.8 → 1534.1 | 1.60 |
| 512 | 1 | 2620.6 → 2661.3 | 0.98 | 9879.2 → 9735.4 | 1.01 |
| 512 | 2 | 3322.4 → 1686.6 | 1.97 | 9965.4 → 6687.3 | 1.49 |
| 512 | 4 | 3004.5 → 1139.1 | 2.64 | 10024.6 → 5409.6 | 1.85 |

4CPU・512投稿の累積割当量は、符号化5,238,279→2,166,906B/件、復号2,481,413→2,419,056B/件だった。符号化は最終出力領域の一括確保により、逐次経路の段階的なbuffer拡張も減る。割当量は同時に保持するメモリやRSSを表さない。128投稿・2CPUの復号では599,132→607,443B/件と増える条件もある。

1投稿だけを格納した小さいJSONは逐次処理する。最終比較で符号化は全CPU条件で2,048B・1確保、復号は約4,240B・17確保を維持した。ここから通常の1投稿HTTPの高速化は主張しない。

## 複数要求を同時に処理した比較

`RunParallel`でCPU数に応じた複数要求を流す。下表は完了件数あたりの経過時間で、単独要求の遅延ではない。

| 1件に含む投稿数 | CPU数 | 符号化 前→後 µs/完了 | 復号 前→後 µs/完了 |
| ---: | ---: | ---: | ---: |
| 128 | 2 | 480.8 → 485.8 | 1338.0 → 1292.1 |
| 128 | 4 | 375.9 → 367.7 | 791.0 → 814.3 |

最終比較でも128投稿JSONの4CPU同時復号は遅い条件があり、同時要求の全条件の改善を示す結果ではない。初期候補の小さいJSONで観測した遅い条件を受け、CPU数の問い合わせも削減した。最終比較の1投稿JSONの2CPU同時符号化は1.981→1.874µs/完了だった。初期候補のログも保持する。大量の小さいJSONが中心なら、一件内の分担による大幅な改善は期待しない。

## 検証と再実行

次で生成一致、通常試験、競合検査、差分fuzz、同じ保存型の測定を再実行できる。

```sh
mise exec -- go run ./tools/jsonencodegen -check
mise exec -- go test ./cmd/... ./internal/... ./tools/...
mise exec -- go test -race ./internal/strictjson ./internal/jsonencode ./internal/parallel ./internal/domain ./internal/postcapture ./internal/evidence ./internal/store ./tools/jsonencodegen
GOMAXPROCS=4 mise exec -- go test ./internal/strictjson -run '^$' -fuzz '^FuzzSingleJSONParallel$' -fuzztime=20s -parallel=2
GOMAXPROCS=4 mise exec -- go test ./internal/jsonencode -run '^$' -fuzz '^FuzzParallelArray$' -fuzztime=20s -parallel=2
mise exec -- go test ./internal/domain -run '^$' -bench '^BenchmarkSingleJSONPosts(Concurrent)?$' -benchmem -benchtime=300ms -count=3 -cpu=1,2,4
```

試験では、並行要求とworker枠不足時の逐次復帰、byte一致、失敗時の復号先非公開、独自復号の順序とエラー、複数の配列を挟む独自復号、本文末尾・未知/重複キー・整数範囲・Unicodeの不正を照合する。

全Go試験とevidenceを含むrace試験は、CPU数の問い合わせを一度にまとめる直前の実装で成功した（bootstrap全体787.349秒）。その最終変更後は、関連7パッケージの通常・race試験、bootstrapの投稿・管理・回線表の代表経路のrace、大小の差分fuzz4対象、Go vet、CGO無効build、生成一致、文書検査が成功した。大きいJSONのfuzzは最終コードで復号1,728回・符号化6,488回、既存の復号・生成符号化のfuzzは40,630回・8,819回を通過した。全体試験と最終変更後の検査をJSON内でも区別する。

HTTP全体の処理量、本番負荷、512MiBのcgroup上限での回復は今回の測定対象ではない。生のログ、変更前source、初期候補は`var/json-single-parallel-20261025/`に保持する。
