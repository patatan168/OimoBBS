# 圧縮byteを維持したZstandardの速度改善

2026-11-01。比較元は`162b733`。**保存候補が重複する合成DATでは圧縮時間を約26.5%、総CPUを約27.6%削減しました。一様な50万byteの制御入力は約92.1%短縮しました。** 通常の文章・混合DATとHTTP本文に一律の高速化は確認していません。[全入力・標本・CPU・RSS・検証結果](zstd-speed-20261101.json)を保存しています。

## 採用した変更

- 保存候補は、精度・符号表の選択方針が同じで、適応prefixが全blockで固定prefixと一致する場合だけ後続の重複を省きます。blockごとに幅が変わる入力は省きません。先行候補の優先、最小出力、呼出元の候補配列、返却配列の所有権を維持します。
- 保存の17byte以上、HTTPの32KiB以上の本文では、先頭wordが一様に見えるときだけ全文を確認します。本当に同じbyteだけなら探索せず従来と同じRLE列を生成します。末尾が16byte未満のblockは従来どおりrawです。混合blockの探索とrepeat履歴は従来の経路を使います。
- 小さいHTTP本文は追加の一様性検査を行いません。符号表・一致候補・圧縮精度・worker上限・メモリ予約・decoder・reader要件は変更していません。HTTP ETagも`-zstd-v13`を維持します。

## 同じ入力での測定

Go1.27.3、AMD Ryzen 5 5500U、`GOMAXPROCS=2`、`taskset -c 10,11`。前回と同じ25本文、合成DAT3種類、未圧縮・周期・一様の対照入力を使いました。workerを再利用し、毎回の圧縮と専有出力の確保を計時します。圧縮済みキャッシュの再送、入力の読取りと復号は計時外です。

前→後→後→前の順で200ms×2回、各版4標本の中央値です。計時中に自分の他のビルド・試験は重ねていません。共有ホストでCPUは排他的に確保していません。総CPUは全threadのuser+systemです。中断された測定は`interrupted-benchmark`へ分け、最終集計に含めていません。

| 入力・処理 | 圧縮時間 µs 前→後 | 時間差 | 総CPU差 | 圧縮byte 前→後 |
| --- | ---: | ---: | ---: | ---: |
| 文章DAT・保存level 9 | 1,515.46 → 1,525.12 | +0.64% | +0.66% | 12,191 → 12,191 |
| 混合DAT・保存level 9 | 2,150.78 → 2,168.64 | +0.83% | +0.39% | 30,969 → 30,969 |
| 高エントロピーDAT・保存level 9 | 5,176.33 → 3,804.99 | -26.49% | -27.61% | 176,639 → 176,639 |
| トップHTML・HTTP | 94.43 → 93.79 | -0.68% | -0.62% | 1,930 → 1,930 |
| スレッドHTML・HTTP | 190.22 → 190.49 | +0.14% | +0.15% | 4,101 → 4,101 |
| 50万byte全ゼロ・HTTP | 91.35 → 7.17 | -92.15% | -92.14% | 25 → 25 |

高エントロピーDATは全blockで適応幅が7byteとなり、level 9の3候補のうち1候補を省ける入力です。文章・混合DATではこの条件を満たさず、ほぼ据え置きです。全ゼロはRLE経路の制御入力で、実ログ全体の短縮率を表しません。25本文のHTTP時間差は-5.06〜+3.91%でした。82byteのsubjectは強制圧縮の参考値で、通常HTTPでは圧縮しません。通信時間・全HTTPのCPU・稼働負荷の改善率ではありません。

## サイズと資源

25本文のHTTP合計は30,310→30,310byte、保存level 1は31,299→31,299byte、level 6は31,424→31,424byte、level 9は31,236→31,236byteでした。サイズだけでなく、全100組のframeがbyte同一です。3制御入力×4profileの12組も同一です。

プロセス最大RSSの中央値は配信対照が14.58→13.59MiBでした。各版2プロセスの標本です。
プロセス最大RSSの中央値は保存対照が16.15→15.99MiBでした。各版2プロセスの標本です。

RSSはGo runtime・fixture・GCを含み、稼働BBSの増分や上限の保証ではありません。新しい常駐cacheや探索表は追加していません。重複を除く場合だけ短い候補配列を作り、既存の最大2workerと8MiBの作業予約を維持します。

## 検証と不採用試行

固定108frameのhash回帰試験、任意512入力の新旧2,048frameのbyte一致と独立復号が成功しました。公開本文・制御入力の新旧224frameは独立Go decoder・製品decoder・libzstdで展開し、旧v1.0.3製品decoderでも保存168frameを確認しました。入力の変更、候補の並べ替え、worker再利用による出力変更も検査しています。

codec/store/compat/webui/生成器/CLI/公開入口の通常試験、関連race、HTTP TLS、vet、生成資産付きのCGO無効buildが成功しました。独立復号・保存往復・破損frameのfuzzは各20秒指定で合計75,268件を通過しました。文書・fixtureの検査も成功しました。全bootstrap試験、実機、WAN、稼働ピーク負荷・512MiB負荷は範囲に含めません。

短い履歴表の配置、FSE構築・正規化・Huffman木、word比較の展開と末尾処理、整数対数の表参照も比較しました。通常の本文で遅くなる、または改善が小さい試作は採用していません。途中のソース・試験バイナリ・生標本は`var/measurements/zstd-speed-20261031-233700/`に保持し、最終集計から分けています。稼働反映は別の配備記録で扱います。

再測定は前回と同じ`results.json`と本文を用意し、`OIMO_ZSTD_HTTP_CORPUS`にそのディレクトリを指定します。

```sh
OIMO_ZSTD_HTTP_CORPUS=/absolute/path/to/corpus GOMAXPROCS=2 taskset -c 10,11 \
  mise exec -- go test ./internal/zstdencode -run '^$' \
  -bench '^(BenchmarkEncode|BenchmarkHTTPCorpus)$' -benchtime=200ms -count=4
GOMAXPROCS=2 taskset -c 10,11 mise exec -- go test ./internal/store -run '^$' \
  -bench '^BenchmarkPackCompressionTarget$' -benchtime=200ms -count=4
```
