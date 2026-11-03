# 保存・復旧の検証

障害からの復旧、暗号化バックアップ、提出用CSV・ZIPと容量回収を確認する手順です。[共通の準備と確認範囲](README.md)を先に確認し、コマンドはリポジトリのルートで実行します。

## 手順を選ぶ

- [保存と復旧](#保存と復旧)
- [障害・性能・提出用記録](#障害性能提出用記録)
- [容量回収の回帰検査](#容量回収の回帰検査)
- [保存圧縮](#保存圧縮)

## 保存と復旧

### 障害・性能・提出用記録

実ファイルと署名journalの照合、Syncエラー、途中停止、再起動、再送を確認します。SIGKILLは電源断でOSキャッシュを失う試験とは別です。バックアップは作成成功だけでなく隔離再生と復元先の照合も確認します。

共有本文WALの復旧中に繰り返し停止する試験と、容量不足相当・短い書込・Sync/Close失敗後の再開は次で検査します。既存の署名不一致・必須prefix破損・余分な末尾の拒否も含めます。

```sh
mise exec -- go test -race ./internal/store ./internal/app -run 'ThreadGroup|Replay|PostingMulti|PostingBatch|Posting.*Crash|Posting.*Recover' -count=1
```

[復旧の再停止とI/O障害](recovery-resilience.md)に、同じ復旧中の6回連続SIGKILL、障害注入、実HTTPSのACK後SIGKILLを分けて記録しています。

ホスト側の暗号化バックアップは、[完成記録の途中停止・同期失敗・再作成](sealed-backup-resilience.md)も確認します。実ファイルと実SIGKILLを使う範囲と、Docker・転送を差し替えた範囲を分けて記録しています。

[復号・転送再試行の強化](sealed-restore-resilience.md)では、実CLIの復号途中のSIGKILL、再実行時の一時ファイル回収、暗号文のhash不一致、Dockerログ消失・停止後の既存コピー再送を確認します。

[受信側の原子的な設置](atomic-backup-receive.md)では、実OpenSSHでの3回連続切断・再送、設置後の応答消失、受信済みコピーの認証復号、期限回収の中断再開を確認します。

現行の[Goへの統合](sealed-backup-go.md)では、Python実装を置き換えた `oimoseal sync/pack/send/receive/sweep` を確認します。Goの障害注入・実SIGKILLに加え、実SSH転送とPythonを含まないDockerイメージでの暗号化・復号・署名検証を隔離実行できます。

[保存停止のヘルスチェック](storage-healthcheck.md)では、保存先競合からの停止検知・別板の投稿継続・再起動復旧、直結TLSと認証済みedgeのHTTP/1.1・HTTP/2、CLI終了コードと共通期限を確認します。

記録には秘密カナリアを使い、公開HTML・DAT・JSON・通常ログに認証秘密が入らないことを検査します。非公開照会・保全・出力は担当板・追加権限・期限・欠測を検査し、保存されていない情報を出力で補いません。

性能試験はCPU・メモリ・ディスク・帯域・投稿/閲覧比率・クライアント数・測定期間・エラー率を明記します。専ブラ80%／Web20%の混在条件を使う場合はその配分を維持します。復旧後の5秒以内を判定する指標は予定送信時刻から完了までのp95で、サーバー内部時間だけで置き換えません。

結果にはコマンド、環境、成功・失敗、未確認範囲を記録します。

#### 提出CSVとZIPの検査

```sh
mise exec -- go test ./internal/disclosure -run 'Test(Export|Submission|SampleZIP|ContentExport|LogExplanation)' -count=1
mise exec -- go test ./internal/bootstrap -run '^Test(EvidenceExtractFromDraft|PostingReverseDNSPersistsAndExports|AdminEvidenceHTTPCompleteLifecycle|AdminUnboundHTTPObservationQueryAndRestart|AdminRejectedEvidenceHTTP)$' -count=1
```

| 対象 | 確認すること |
| --- | --- |
| 対象と本文 | 保存済みの `board_key`・`thread_key`・`post_number`、本人の `public_body`、自動投稿の除外 |
| 応答終了時刻 | 対応するHTTP原本の自動保全、同一要求の照合、記録あり・欠測が混在するCSV |
| CSVの読み方 | JST、空欄・null・空文字の区別、数式と桁落ちの防止、実列ごとの型と説明 |
| ZIPとサンプル | 実ZIPの署名・件数・ファイルハッシュ、サンプルがCSVとREADMEだけの未署名見本であること |
| 一覧・検索 | 通常投稿と未受理・閲覧の入口分離、作成日時順、検索・状態・並び順、条件付きページ送り、担当外の非表示 |
| 管理操作 | 全項目でのZIP取得、削除済み照会・受渡し経路と入力の拒否、版競合・再送・権限・期限の検査 |

画面では、案件作成からZIP取得までを確認します。ZIP内の `readme.txt` とサンプルは実際に展開して読み、表示・列名が[現在の仕様](../features/records.md#提出用ファイル)と一致することを確認します。隔離HTTPの検査と稼働環境での取得確認は分けて記録します。

[ブラウザー検査の準備](README.md#ブラウザー検査の準備)を済ませると、提出案件の一覧・検索も検査できます。

```sh
mise exec -- go test ./internal/bootstrap -run '^TestAdminEvidenceSearchBrowser$' -count=1
```

ログイン・検索・状態・並び替え・次ページでの条件保持・検索解除と、幅320・390・800・1280pxの表示を確認します。

### 容量回収の回帰検査

隔離した一時保存先で、容量の開始・終了基準、7日の境界、回収順、案件保全、途中停止と再起動、別板の投稿継続、HTTP投稿とバックアップ再生を検査します。

```sh
mise exec -- go test ./internal/app ./internal/bootstrap -run '^TestStoragePressure' -count=1
mise exec -- go test -race ./internal/app ./internal/bootstrap -run '^TestStoragePressure' -count=1
```

既存の期限満了・保全・原本回収への影響を確認する場合：

```sh
mise exec -- go test ./internal/app ./internal/bootstrap \
  -run 'TestRequiredRetirement|TestRequiredGCJob|TestRequiredOriginalRepository|TestRequiredHoldProduct|TestPostingCapacity|TestPersistentExpiry|TestReclaimedBodyBackupReplay' -count=1
```

これらはディスク空き容量を模擬する隔離試験です。実ディスクを満杯にする試験、電源断、本番負荷での遅延や、稼働環境への適用確認は含みません。

### 保存圧縮

| 確認すること | 参照先 |
| --- | --- |
| 圧縮する対象と保存形式 | [内部設計](../architecture.md#ログ関連の圧縮範囲) |
| 同じ入力の圧縮量・時間・割り当て | [保存codecの比較](../../tools/storagebench/README.md) |
| 実HTTPのCPU・メモリ・復旧 | [性能の検証手順](performance.md) |
| 過去の条件・全試行・不採用候補 | [保存圧縮の測定資料](storage-compression.json) |

合成入力の圧縮率や復号速度だけで、実HTTPの投稿性能を判断しません。実測では保存件数・DAT・ログ欠測・OOMも確認し、CPU・メモリ枠が異なる結果を混ぜずに記録します。
