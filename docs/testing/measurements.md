# 検証記録の一覧

性能測定・セキュリティ検証・稼働反映の記録をまとめた一覧です。失敗、遅い試行、不採用候補も含みます。現行仕様は[仕様の全体像](../specification.md)、再実行方法は[性能の検証手順](performance.md)を参照してください。

現在のアルゴリズムは[符号化・圧縮・並列処理](../encoding.md)、受付と回復の条件は[資源管理](../features/resources.md)を参照してください。

測定値を使うときは、記録内のソース版、採用・不採用、CPU・メモリ、キャッシュ、WAF、負荷条件を確認してください。試作版の結果を現行版の性能へ読み替えません。

## 資料を選ぶ

| 確認したいこと | 資料 |
| --- | --- |
| HTTP検査・一覧・ログの処理 | [WAF](#waf) |
| CPU・メモリ・帯域・閲覧・保存 | [資源・帯域・保存](#資源帯域保存) |
| バックアップ・保存障害・再起動復旧 | [保存・バックアップ・復旧](#保存バックアップ復旧) |
| Webの取得条件・HTTP圧縮 | [HTTP配信と圧縮](#http配信と圧縮) |
| 圧縮データの復号 | [復号処理](#復号処理) |
| 投稿の処理量・遅延・復旧 | [投稿処理](#投稿処理) |
| 管理操作記録の初回表示・ページ送り・照合再開 | [管理操作の記録](#管理操作の記録) |
| Web脆弱性・投稿入力・稼働設定 | [セキュリティの検証記録](#セキュリティの検証記録) |
| 更新時の退避・復元・公開確認 | [稼働反映の記録](#稼働反映の記録) |

## WAF

| 記録 | 測定対象 |
| --- | --- |
| [TLS前の新規接続頻度](connection-rate-20261103.md)・[全試行](connection-rate-20261103.json) | 2CPU・512MiB、TLS再接続毎秒400回と大量投稿・低速通信を混在。正常20投稿/秒の保存、TLS前の切断、CPU、HTTP/1・HTTP/2の既存接続継続 |
| [投稿枠の短時間待機](posting-admission-wait-20261102.md)・[全試行](posting-admission-wait-20261102.json) | 投稿の同時上限を維持した最大500msの有限待機。20投稿/秒と短い枠競合の実HTTPS比較、待機・取消・回線別切替の検査 |
| [攻撃混在と未受信本文の早期拒否](attack-mix-20261102.md)・[全試行](attack-mix-20261102.json) | 既定WAFで大量投稿・低速本文・低速ヘッダーを混在。正常10投稿/秒の全件保存、20投稿/秒の失敗、実TLS中継とHTTP/2の回帰検査 |
| [入口のヘッダー・Host・宣言本文長](waf-ingress.md)・[検査記録](waf-ingress.json) | 制御文字・UA・量の上限、実HTTP/1とHTTP/2、本文未読の早期拒否、race・fuzz・単体コスト |
| [WAF・一覧・非必須ログの並行処理](ingress-egress-optimization.md)・[全10試行](ingress-egress-optimization.json) | WAFの枠解放、一覧の要約取得、ログ計算の並行化。投稿・閲覧の同時負荷、512MiB、強制再起動、ログ欠測を含む |
| [クエリ解析前の制限と管理画面](waf-query-ui.json) | 128項目の境界、拒否時の割当量、通常閲覧の実HTTP比較、画面幅・JavaScript無効時の検証 |

## 資源・帯域・保存

| 記録 | 測定対象 |
| --- | --- |
| [起動と更新時の停止時間](restart-recovery-20261103.md)・[全試行](restart-recovery-20261103.json) | 同じ完全バックアップによる実mTLS起動、HTTPログ復旧の並列検証、停止中の退避・復元費用と同じvolumeでの通常更新 |
| [回線分類更新](network-update-optimization.md)・[全試行](network-update-optimization.json) | Zstandard・分類専用2MiB枠・取得/国別解析/行検証の並列化。固定feedの単一コア・1/2/4CPU・ヒープ目安と復旧 |
| [固定投稿上限の撤去とWAF回線別スイッチ](server-scaling.json) | 1/4CPUの実HTTPS、過負荷・併用・再起動照合。遅延悪化・拒否を含む |
| [CPU・メモリの自動調整](adaptive-resources.json) | 資源予算、圧迫時の受付制限・回復、実HTTPS投稿 |
| [CPU並列化・I/O方式](cpu-io-scaling.json) | 並列化と同期・領域先行確保の候補比較。同期方式の不採用も含む |
| [共有本文WALの試作](shared-wal-io.md)・[全試行](shared-wal-io.json) | 既定無効の共有同期、512MiBの拒否・悪化、未発行、SIGKILL復旧、syncfs不採用 |
| [帯域別の構成](bandwidth-sizing.json) | 100・200・400・1000Mbpsの配信と投稿併行。旧版での構成目安 |
| [非必須HTTPログ](http-log-posting.json) | ログ滞留への追従と投稿の比較 |
| [保存圧縮](storage-compression.json) | WAL・snapshotの圧縮、混合負荷、I/O競合、不採用候補 |
| [512MiBでの受付回復](memory512-recovery.md)・[全記録](memory512-recovery.json) | 未回収ヒープと作業予約を考慮した早期GC、WAF有効の実HTTPS3試行、実メモリ圧迫と強制再起動 |
| [閲覧処理の追加最適化](reading-optimization.md)・[全試行](reading-optimization.json) | 公開HTML・一覧のETag共有、DATヘッダ解析、単体・実HTTPS・投稿併行と復旧 |
| [CPU・Mutex・GCの追加検証](cpu-mutex-gc-optimization.md)・[全試行](cpu-mutex-gc-optimization.json)・[反映記録](cpu-mutex-gc-deployment.md) | 2→4CPUの1.6倍目標、閲覧の達成と投稿の未達、共有SSD競合・全試作・GC/Mutex/CPU診断 |
| [閲覧のCPU・メモリ比較](reading-resource-scaling.md)・[全試行](reading-resource-scaling.json) | サイト共通ロックの共有化、一覧の経路短縮、Go生成器、2/4CPU・512MiB/2GiB・作業集合・継続負荷 |
| [Zstandard設定比較](zstd-same-settings.json) | 同じ圧縮設定での候補比較。全11候補を不採用 |

## 保存・バックアップ・復旧

再実行する検査は[保存・復旧の検証手順](storage.md)を参照してください。

| 記録 | 確認範囲 |
| --- | --- |
| [共有WALの復旧とI/O障害](recovery-resilience.md) | 復旧中の連続SIGKILL、書込・同期失敗、実HTTPSのACK後停止 |
| [保存停止のヘルスチェック](storage-healthcheck.md) | 保存先異常の検知、別板の継続、再起動、実TLS・edge・CLI |
| [暗号化バックアップのGo統合](sealed-backup-go.md) | sync/pack/send/receive/sweep、実SIGKILL、隔離SSHとDockerでの復号・署名照合 |
| [完成記録と暗号文の再作成](sealed-backup-resilience.md) | 書込・同期失敗、途中停止と再開。旧Python実装時点の記録 |
| [復号・転送再試行](sealed-restore-resilience.md) | 復号途中の停止、hash不一致、元ログ消失後の再送。旧Python実装時点の記録 |
| [受信側の原子的な設置](atomic-backup-receive.md) | 実SSHの連続切断、ACK消失、再送、認証復号、期限回収の再開。旧Python実装時点の記録 |

## HTTP配信と圧縮

現在の受付条件は[Webの取得条件](../features/reading.md#webの取得条件)、実装は[Zstandardの符号化](../encoding.md#zstandardの符号化)を参照してください。以下は各変更時点の検証記録です。

| 記録 | 測定対象 |
| --- | --- |
| [Web取得の圧縮対応必須化](web-compression-required.md) | Web・管理GET/HEADの406、専ブラのidentity/304/206、HTTP/1.1・HTTP/2の実TLS取得、edge・healthcheck |
| [大きい高エントロピーDAT](zstd-entropy-20261101.md)・[全標本](zstd-entropy-20261101.json) | 保存9の4byte候補の費用・探索間隔、サイズ削減を超える時間/CPU劣化の除外、同一バイナリ展開・旧版互換性 |
| [同じ圧縮byteでの速度改善](zstd-speed-20261101.md)・[全標本](zstd-speed-20261101.json) | 重複する保存候補の除外、一様本文の直接RLE、同じ出力byte・CPU/RSS・独立復号 |
| [一致探索と保存RLEの改善](zstd-ratio-20261031.md)・[全標本](zstd-ratio-20261031.json) | 25本文の新旧比較、CPU/RSS、短い一致の直近2候補、保存RLE、独立復号と旧版readerでの保存互換性 |
| [小さいHTTP本文と候補表の追加改善](zstd-small-http-extra.md)・[全標本](zstd-small-http-extra.json) | 4byte参照とRLE、FSE構築前の下限判定、全一致repeatの再比較削減、サイズ・経過時間・総CPU |
| [HTTPの定義済みFSE表](zstd-predefined-http.md)・[全標本](zstd-predefined-http.json) | 符号表ヘッダーを省く選択、同一17本文のサイズ・経過時間・総CPU、保存88出力のbyte一致 |
| [HTTPのliteralヘッダー削減](zstd-http-literals.md)・[全標本](zstd-http-literals.json) | 前回改善版からの圧縮率と時間、短いヘッダー・単一stream、保存68出力のbyte一致。稼働反映は含まない |
| [小さいHTTP本文のZstandard圧縮](zstd-small-http.md)・[全標本](zstd-small-http.json) | 公開URLで取得した同一本文17件の圧縮サイズ・生成時間。圧縮単体の変更前後比較で、稼働反映・通信時間は含まない |
| [HTTP配信codec](http-codec-current.json) | HTTP圧縮のcache missとサーバー内復号の単体比較。実HTTPは含まない |
| [Zstandardの高圧縮化](high-compression.md)・[全測定](high-compression.json) | 列ごとの符号化精度選択、保存候補の最大2worker比較、gzipレベル9との単体比較とWAF有効の実HTTPS |

## 復号処理

| 記録 | 測定対象 |
| --- | --- |
| [1件のJSON内の並列符号化・復号](json-single-parallel.md)・[全試行](json-single-parallel.json) | 大きい配列を含む保存DTOの一件内分担、共有worker枠、1/2/4CPUと同時要求、byte・厳密検査・独自復号順序の維持 |
| [Zstandard復号の長さ計算](zstd-length-decode.md)・[全標本](zstd-length-decode.json) | literal・参照長の分離、前回版との1コア比較、保存frameの測定変動と不採用案 |
| [小さいZstandard frameの復号](zstd-small-frame-decode.md)・[全標本](zstd-small-frame-decode.json) | 32KiB以下の表構築と単一stream読取り、実本文と保存frame、1コアの経過時間・総CPU。大frameの高速化は未確認 |
| [Zstandard復号・第1回](zstd-decode.json) | 復号の単体測定 |
| [第2回](zstd-decode-second.json)・[第3回](zstd-decode-third.json)・[第4回](zstd-decode-fourth.json) | 各段階の復号比較、入力・設定別の時間と割当量 |
| [第5回](zstd-decode-fifth.json) | 復号表の作業領域とHuffman先読みの改善。既存の配信・保存用入力を比較 |
| [Zstandardの並列復号](zstd-decode-parallel.md)・[全試行](zstd-decode-parallel.json) | 独立した保存frameの最大4worker展開、1/2/4CPU、両CRC検査とpack全復元・DAT範囲読取り |
| [Zstandard復号の処理削減](zstd-decode-efficiency.md)・[全試行](zstd-decode-efficiency.json) | 単一frameのliteral作業配列削減とHuffman位置更新の削減、1コアと4コア同時展開の総CPU・割当 |
| [Zstandard復号の追加最適化](zstd-decode-tuning.md)・[全試行](zstd-decode-tuning.json) | Huffmanの深さ定数化とsequence読取りの重複検査削減、前回版との1コア・4コア比較 |
| [pack読取りの処理削減](pack-read-efficiency.md)・[全試行](pack-read-efficiency.json) | 二重の意味検証と中間配列を削減、検証専用の文字コード走査、以前の悪化の交互再測定と日本語を含むpack全体比較 |
| [文字コード変換の並列化と処理削減](textcodec-parallel.md)・[全試行](textcodec-parallel.json) | UTF-8とShift_JISの変換表・ASCII処理の最適化、最大4worker、単独と同時要求の総CPU・割当量と不正入力の照合 |
| [復号最適化後の投稿](throughput-after-zstd.json) | 単体の復号と、実HTTP投稿・回復の比較 |

codec単体の値には、実ディスクのWrite/Syncや通信時間を含みません。復号時間の短縮だけから投稿全体の処理量を推定しません。

## 投稿処理

[遅延・回復と集中投稿](#遅延回復と集中投稿) / [同期I/Oと保存待ち](#同期ioと保存待ち) / [JSONと文字コード](#jsonと文字コード) / [CPU並列化と処理量](#cpu並列化と処理量)

### 遅延・回復と集中投稿

| 記録 | 測定対象 |
| --- | --- |
| [投稿回復の再悪化と同期I/O](posting-recovery-regression-20261103.md)・[全診断・時系列](posting-recovery-regression-20261103.json) | 120秒の実投稿観測、攻撃なし対照、単独fsyncとext4・journal・SATAの同時採取。13秒の復帰・再悪化・初期失敗を含む |
| [投稿集中後の応答速度の回復](posting-burst-recovery-20261103.md)・[全比較・診断](posting-burst-recovery-20261103.json) | 検出ログを投稿優先の背景I/O枠へ接続。20投稿/秒・集中終了後30秒の比較、再悪化・未達・不採用候補を含む |
| [一括投稿の履歴検算](posting-peak-20261102.md)・[全試行](posting-peak-20261102.json) | 未公開群の履歴複製と個別WALの再解析を削減。2/4CPUの固定投稿・集中条件、保存待ちの悪化を含む全試行、閲覧併行と強制再起動 |
| [間隔の空いた返信の待ち短縮](posting-idle-latency.md)・[全30試行](posting-idle-latency.json) | 低頻度返信の収集待ち省略、専ブラ・Webの実HTTPS、集中投稿の悪化試行と回線更新停止後の比較・通常再起動 |
| [周期保守による停止連鎖の回避](posting-maintenance-stalls.md)・[全試行](posting-maintenance-stalls.json) | 共通ロックを保持した投稿列待ちの再現、混雑板の保守延期、同じWAF枠での投稿・閲覧・再起動照合 |

### 同期I/Oと保存待ち

| 記録 | 測定対象 |
| --- | --- |
| [保存同期の回数削減](posting-sync-wait.md)・[全試行](posting-sync-wait.json) | 確認操作と保存候補の枠の分離、主要Sync回数、通常版の速度・遅延、不採用案・最終版・SIGKILL復旧 |
| [投稿WALの書き込み量を減らす](posting-io-mitigation.md)・[全試行](posting-io-mitigation.json) | 必須記録WALの圧縮範囲、書込み量の軽減、速度改善の未確認、通常・混合・SIGKILL復旧 |
| [投稿の同期待ちへの適応](posting-io-adaptive.md)・[全試行](posting-io-adaptive.json) | 実Sync時間に応じた収集、隔離した同期遅延での回数・処理量、通常HTTPS・混合負荷・復旧 |
| [収集待ち拡張の再検討（不採用）](posting-io-collection.md)・[全20試行](posting-io-collection.json) | 32/64msへの拡張と少量投稿の保護を比較。再試行で遅延・未発行が再発し、製品コードは元へ復元 |
| [投稿I/Oの追加検証（不採用）](posting-io-retry.md)・[全14試行](posting-io-retry.json) | 単独WALの圧縮と非必須ログの再収集。書込み量とSyncを分けて比較し、下限改善を確認できず両案を復元 |
| [保存待ち中の本文準備（不採用）](posting-io-bodyprepare.md)・[全14試行](posting-io-bodyprepare.json) | 準備記録の実Syncに本文の検証・圧縮を重ねる試作。追加遅延下の小幅改善、通常比較、実Syncとの重複、混合負荷の再試行 |
| [SATA設定と保存待ち（不採用）](posting-io-device-policy.md)・[全16試行](posting-io-device-policy.json) | 省電力・キュー深さ・組合せの一時比較。実fsyncの長い待ちと未発行が残り、全設定を元へ復元 |
| [保存待ちとcheckpointの削減](posting-io-checkpoint.md)・[全試行](posting-io-checkpoint.json) | 本文まとめ書き、実frame数のcheckpoint予算、終了時の残作業を含む同期診断、HTTPS・SIGKILL復旧 |
| [投稿保存の安定化・初期比較](posting-stability.json) | 保存と回復の比較 |
| [投稿保存の安定化・追加比較](posting-sustain.json) | 保存・再送索引・独立WAL同期・ログの比較と失敗試行 |
| [共有WALの実用化](shared-wal-practical.md)・[全試行](shared-wal-practical.json) | CPU重複処理の削減、有界バイナリ形式、継続・混合・復旧の比較 |

### JSONと文字コード

| 記録 | 測定対象 |
| --- | --- |
| [文字コード最適化後の投稿](textcodec-posting.md)・[全試行](textcodec-posting.json) | 1/2/4CPUの実HTTPS、同期I/Oによる遅い試行の診断、160投稿/秒＋400閲覧/秒での拒否・未発行・復旧 |
| [固定スキーマJSON符号化](posting-json.md)・[全試行](posting-json.json) | journalの専用符号化、旧JSON/frameとのbyte一致、1/2/4CPUの実HTTPS・混合負荷・SIGKILL復旧 |
| [投稿JSONの符号化・検証の追加改善](posting-json-second.md)・[全試行](posting-json-second.json) | 保存DTOの生成符号化、厳密構文検査の走査削減、CPU時間と保存待ち・混合負荷の拒否を分けた比較 |
| [投稿JSONの型検査と復号の統合](posting-json-third.md)・[全試行](posting-json-third.json) | 構文・型付き復号・bool補完の重複走査削減、差分fuzz、実HTTPSのCPU時間・混合負荷・SIGKILL復旧 |
| [保存JSONの専用復号と単一スレッド投稿](posting-json-typed.md)・[全15試行](posting-json-typed.json) | 保存型の生成復号、1CPU・GOMAXPROCS=1のCPU単価と完了速度、JSON CPU診断、503・準備失敗と通常ディスクの変動を含む |
| [投稿JSONの検査](posting-tuning.json) | 重複検査の削減、実HTTPS比較、収集待ちの不採用候補 |

### CPU並列化と処理量

| 記録 | 測定対象 |
| --- | --- |
| [制限判定と投稿経路の処理削減](posting-processing.md)・[全試行](posting-processing.json) | 通常の制限を維持した予約・窓待ち・厳密JSON・HTMLの処理削減。比較時だけ頻度制限を解除した2/4CPUの実HTTPS、I/O変動とtmpfs比較 |
| [並列準備とスレッド別候補索引](posting-multicore.md)・[全56試行](posting-multicore.json) | worker待合せと候補走査の削減、2/4CPU最終比較、非同期検証の不採用、混合負荷とSIGKILL復旧 |
| [検出ログの重複復号と投稿CPU](posting-cpu-lanes.md)・[全試行](posting-cpu-lanes.json) | writer専用の単一時間帯再利用、1/2/4CPUの実HTTPS、2→4CPUの伸びと絶対速度を分けた比較、通常ディスク・混合負荷 |
| [復旧の再停止とI/O障害](recovery-resilience.md)・[検査・全HTTP試行](recovery-resilience.json) | 一致済み本文を保持する再実行、全Sync/Close後の復旧元削除、6回連続SIGKILL、容量・I/O障害注入、512MiBの実HTTPS復旧 |
| [単一コアを含む投稿処理](posting-single-core-optimization.md)・[全試行](posting-single-core-optimization.json) | 厳密JSON復号・署名記録・更新HTMLを省CPU化。2→4CPUは1.6倍未達、絶対性能・継続負荷・復旧を別に記録 |
| [投稿シーケンス変更の再挑戦](posting-pipeline-optimization.md)・[全38試行](posting-pipeline-optimization.json) | 部分待合せ・検証統合・保存中のCPU構築・PGO・収集待ち0を比較。1.6倍未達、全候補不採用・稼働版維持 |
| [投稿の限界処理件数](posting-capacity.json) | 改善前の固定予定投稿、WAF・メモリ・分散先の比較 |
| [投稿の頭打ち診断](posting-bottleneck.json) | CPU・保存待ち・要求発行待ちの診断 |
| [投稿準備の並列化](posting-parallel.json) | 不採用にした試作版の単体・実HTTP比較 |
| [投稿のCPU・メモリ増設](posting-resource-scaling.md)・[全試行](posting-resource-scaling.json) | 独立検証・署名・符号化・本文準備の並行化、1/2/4CPUと1/2/4GiB、継続・混合・復旧 |
| [投稿の継続最適化と復旧](posting-cpu-continuation.md)・[全試行](posting-cpu-continuation.json) | 所有列・WAL圧縮・起動の並列化、1.45倍の検証と継続負荷・再起動、全試作を含む |
| [投稿の追加CPU並行化](posting-cpu-parallelism.md)・[全試行](posting-cpu-parallelism.json) | 候補再利用・保存層の独立検証、2/4CPU比較と1.5倍目標の未達、試作・診断・復旧を含む |

過去の比較では、100投稿/秒の安定処理や強いI/O競合後の回復条件を毎回満たす結果は得られていません。詳細は各記録の判定条件と失敗試行を確認してください。共有ホスト・合成データ・短時間の結果は、本番SLO、WAN・実NICの性能、長期安定性を保証しません。

## 管理操作の記録

| 記録 | 確認範囲 |
| --- | --- |
| [初回復元の10秒タイムアウト](audit-first-access.md) | 同一バックアップの隔離HTTP比較、64件ずつの同期保存と起動時検証の引継ぎ、7,988件の要約・期限一致、中断・再起動・race |
| [大量記録のページ送りと照合再開](audit-pagination.md) | 条件未選択の2,002件・2MiB超を実HTTPで全ページ取得、snapshot後の予算中断からの再開、Chromium、固定一覧・権限・race |

## セキュリティの検証記録

| 記録 | 確認範囲 |
| --- | --- |
| [認可・WAF・ドメイン規制の境界修正（2026-10-26）](security-boundary-fixes-2026-10-26.md) | 4件の修正、未認証2,800要求、接続方式別WAF、Chromiumの改変認証・再認証、race・fuzz |
| [Webセキュリティ診断（2026-10-23）](security-review-2026-10-23.md)・[検証結果](security-review-2026-10-23.json) | OWASPに沿った隔離HTTP・Chromium・race・fuzz・依存検査。実施済みと未検証の項目を記録 |
| [投稿形式と稼働設定（2026-10-24）](post-boundary-settings-audit.md) | 投稿形式の早期拒否と隔離HTTPの回帰検査。稼働設定・公開経路の読取り確認と未確認範囲 |

## 稼働反映の記録

| 記録 | 確認範囲 |
| --- | --- |
| [管理画面のボタン整理・監査修正（2026-11-03）](admin-audit-deployment-20261103.md) | 起動時の走査予算超過、初回索引復元、2回の停止時間、復元照合、公開経路、定期バックアップ |
| [高圧縮化・512MiB対策の稼働反映](compression-memory512-deployment.md) | 全データ退避・復元一致、新旧起動確認、実HTTPSの圧縮・ETag更新、設定と保持データの照合 |
| [投稿準備・入口WAF](posting-waf-deployment.md)・[反映結果](posting-waf-deployment.json) | 全データ退避・隔離での新旧起動、BBSのみ置換、保存値・公開経路・UA境界・ブラウザーの確認 |
| [CPU・Mutex・GC最適化](cpu-mutex-gc-deployment.md) | 更新時の退避・復元、保存データ、公開・管理画面の確認 |
| [閲覧・投稿の資源利用改善](reading-resources-deployment.md) | 全データの退避・隔離復元、設定・鍵の照合、公開経路とブラウザーの確認 |
| [WAF・一覧・非必須ログ最適化](ingress-egress-deployment.md) | 全データの退避・隔離復元、切替後のhealthcheck、公開経路とブラウザーの確認 |

稼働反映の記録は実施日時点の結果です。認証後の管理操作や負荷試験など、実施できていない範囲は各記録に記載しています。
