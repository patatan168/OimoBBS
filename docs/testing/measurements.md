# 性能の測定資料

過去の測定条件と全試行を保存したJSONの一覧です。失敗、遅い試行、不採用候補も含みます。現行仕様は[仕様の全体像](../specification.md)、再実行方法は[性能の検証手順](performance.md)を参照してください。

測定値を使うときは、記録内のソース版、採用・不採用、CPU・メモリ、キャッシュ、WAF、負荷条件を確認してください。試作版の結果を現行版の性能へ読み替えません。

## WAF

| 記録 | 測定対象 |
| --- | --- |
| [クエリ解析前の制限と管理画面](waf-query-ui.json) | 128項目の境界、拒否時の割当量、通常閲覧の実HTTP比較、画面幅・JavaScript無効時の検証 |

## 資源・帯域・保存

| 記録 | 測定対象 |
| --- | --- |
| [固定投稿上限の撤去とWAF回線別スイッチ](server-scaling.json) | 1/4CPUの実HTTPS、過負荷・併用・再起動照合。遅延悪化・拒否を含む |
| [CPU・メモリの自動調整](adaptive-resources.json) | 資源予算、圧迫時の受付制限・回復、実HTTPS投稿 |
| [CPU並列化・I/O方式](cpu-io-scaling.json) | 並列化と同期・領域先行確保の候補比較。同期方式の不採用も含む |
| [帯域別の構成](bandwidth-sizing.json) | 100・200・400・1000Mbpsの配信と投稿併行。旧版での構成目安 |
| [非必須HTTPログ](http-log-posting.json) | ログ滞留への追従と投稿の比較 |
| [保存圧縮](storage-compression.json) | WAL・snapshotの圧縮、混合負荷、I/O競合、不採用候補 |
| [HTTP配信codec](http-codec-current.json) | HTTP圧縮のcache missとサーバー内復号の単体比較。実HTTPは含まない |
| [Zstandard設定比較](zstd-same-settings.json) | 同じ圧縮設定での候補比較。全11候補を不採用 |

## 復号処理

| 記録 | 測定対象 |
| --- | --- |
| [Zstandard復号・第1回](zstd-decode.json) | 復号の単体測定 |
| [第2回](zstd-decode-second.json)・[第3回](zstd-decode-third.json)・[第4回](zstd-decode-fourth.json) | 各段階の復号比較、入力・設定別の時間と割当量 |
| [第5回](zstd-decode-fifth.json) | 復号表の作業領域とHuffman先読みの改善。既存の配信・保存用入力を比較 |
| [復号最適化後の投稿](throughput-after-zstd.json) | 単体の復号と、実HTTP投稿・回復の比較 |

codec単体の値には、実ディスクのWrite/Syncや通信時間を含みません。復号時間の短縮だけから投稿全体の処理量を推定しません。

## 投稿処理

| 記録 | 測定対象 |
| --- | --- |
| [投稿の限界処理件数](posting-capacity.json) | 改善前の固定予定投稿、WAF・メモリ・分散先の比較 |
| [投稿の頭打ち診断](posting-bottleneck.json) | CPU・保存待ち・要求発行待ちの診断 |
| [投稿JSONの検査](posting-tuning.json) | 重複検査の削減、実HTTPS比較、収集待ちの不採用候補 |
| [投稿準備の並列化](posting-parallel.json) | 不採用にした試作版の単体・実HTTP比較 |
| [投稿保存の安定化・初期比較](posting-stability.json) | 保存と回復の比較 |
| [投稿保存の安定化・追加比較](posting-sustain.json) | 保存・再送索引・独立WAL同期・ログの比較と失敗試行 |

過去の比較では、100投稿/秒の安定処理や強いI/O競合後の回復条件を毎回満たす結果は得られていません。詳細は各記録の判定条件と失敗試行を確認してください。共有ホスト・合成データ・短時間の結果は、本番SLO、WAN・実NICの性能、長期安定性を保証しません。
