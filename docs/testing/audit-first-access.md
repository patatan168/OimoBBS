# 監査画面の初回復元と公開入口のタイムアウト

2026-11-03。`/admin/audit` の初回表示が「公開サーバーへ接続できません。」になる報告を調査し、稼働反映前の完全バックアップを復元した隔離コピーで再現しました。この文書は原因・修正と同一条件の比較を記録します。同日、修正版 `e5e2ebe` を[本番へ反映](admin-audit-deployment-20261103.md)しました。本番の認証後の監査照会は未実施です。

## 原因

公開入口の `ResponseHeaderTimeout` は10秒です。監査一覧の初回取得では、snapshot後の監査証明を再照合し、未移管の監査要約を日別正本へ保存してから索引を公開します。基準版は1件ごとに同期保存するため、溜まった要約の保存が10秒を超え、公開入口が503を返しました。準備完了後は約2msで表示できるため、時間を置いて復旧する症状とも一致します。

当時の公開入口は転送エラーをログに残していません。報告された本番要求の詳細な時系列は直接確定できませんが、BBSの再起動・OOMはなく、隔離した実データで同じ文言と10秒の応答待ち超過を再現しています。破損を示す検証エラーは見つかりませんでした。

## 修正

- 起動時に検証した監査証明・要約・cursorを、初回の索引復元へ引き継ぎます。所有者・世代が変わった場合は再検証し、時計と保持境界も照合します。
- 元履歴は最大64frameずつ、保存先は所有者・日付ごとに最大64件ずつ同期保存します。
- 走査位置と証明は候補として保持し、要約のSync成功後だけ元cursor・索引へ反映します。圧縮blockの未処理frameも別のcursorへコピーし、保存失敗時に元の未処理分を失いません。
- 保存済みのIDは内容と固定期限を照合して再利用します。途中の中断後も、要約の欠落・重複・期限延長を起こさない経路です。

取得権限・絞込み・ページ送り・保存形式のreader条件は変更していません。内部の進捗を一覧へ出さない判定も維持します。

## 同一条件の比較

基準は `1156266`。同じ完全バックアップを別ディレクトリへ復元し、同じGo・同じホストで逐次実行しました。回線情報の背景取得は各コピーの起動直後に取消・終了待ちし、取得結果の追記を測定へ混ぜていません。

実HTTPで、隔離コピー専用のセッションから監査handlerを呼び、応答ヘッダー待ち10秒の中継を通します。本番のログイン操作・接続元制限・mTLS経路を再現する試験ではありません。

| 取得回 | 基準版 | 修正版 |
| --- | --- | --- |
| 初回 | 0.663秒、準備中の503 | 0.894秒、200 |
| 2回目 | 10.001秒、中継タイムアウトの503 | 2.13ms、200 |
| 3回目 | 10.008秒、中継タイムアウトの503 | 1.79ms、200 |
| 4回目 | 9.447秒、200 | 2.02ms、200 |
| 5回目 | 1.73ms、200 | 1.69ms、200 |

基準版は200の初回取得まで約30.1秒、修正版は初回0.894秒でした。各版1回の逐次比較であり、WAN・混雑時・長時間負荷の性能保証ではありません。

全監査要約7,988件の内容と固定期限は修正前後で一致しました。日別正本の全項目を比較したSHA-256は `b438f3faa6cbc5dfa94151ddaaa29861a93018970a89ddd930710fbd0238a79b` です。探索試行では背景回線更新が1件増えたため、比較結果には背景更新を止めた再試行を使っています。

修正版で監査を保存した実データコピーを閉じて再度開き、初回35.3msで200を確認しました。再オープン後も同じ7,988件の要約と期限が一致しています。

## 回帰検査と原出力

```sh
mise exec -- go test ./internal/bootstrap ./internal/store \
  -run 'Test(Audit|AdminAudit|SnapshotAudit|SnapshotRepositoryAudit|StartupSnapshotAudit|StartupAuditVerification|CommittedCursor|History|ControlExpiry)' -count=1 -timeout=5m
mise exec -- go test -race ./internal/bootstrap ./internal/store \
  -run 'Test(AuditBatch|AuditDailyArchive|AuditImportFailure|AuditStorageFailure|SnapshotAuditCatchUp|StartupSnapshotAudit|StartupAuditVerification|CommittedCursorCompressed)' -count=1 -timeout=5m
```

通常・race試験、vet、ビルド、設計検査を実施。保存後・索引公開前の中断、保存先異常、予算中断、圧縮block内のcursor分離、再起動、改変拒否、権限・ページ送りを確認します。

Git対象外の `var/testing/audit-first-access-20261103/` に `baseline-matched-route.log`、`candidate-matched-route.log`、`audit-equality-matched.json`、`comparison.json`、`investigation_audit_clone_test.go` と関連テストの原出力を保持しています。実電源断・本番の認証後操作・負荷試験は未実施です。
