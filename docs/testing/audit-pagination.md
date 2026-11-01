# 管理操作記録のページ送りと照合再開

2026-11-01。条件未選択でも管理操作記録を開けない二つの原因を修正した。稼働サービスへの反映は含まない。

## 原因と変更

1. ページ分割前の検索全体に2,000件・2MiBの上限があり、既定50件の最初のページまで503になっていた。固定一覧は不変の索引参照を共有し、API・HTMLへ返すページの要約だけを作る。件数と総量の旧制限を撤去し、条件未選択で全件をページ送りできるようにした。
2. snapshot後の監査証明の照合は、読取り予算を超えたときに一時cursorとchainを破棄していた。同じ予算で再取得しても先頭の照合を繰り返す。検査済みの境界・要約・cursor・chainを一組で保持し、照合が完了した位置を通常の差分取込へ接続した。証明・本文の検査は省略せず、途中結果は公開しない。

索引の期限回収で参照先が変わらないように、記録自体を不変の参照にした。取得時点の表示分類も固定する。取得後の追記は既存ページへ割り込まず、期限回収で元索引から外れた記録も固定一覧の有効期間中は保持する。

履歴の一回64MiB・20万frame、索引10万件・64MiB、固定一覧8件・10分、セッション束縛cursorと権限の再検査は維持する。固定一覧には共有記録を一度だけ数える128MiB予算も適用する。保存形式とreader versionは変更しない。

ページ送り用の保持枠が満杯の場合は、その理由と最大10分の待機を案内する。板・期間の絞込みでは枠が空かないため、その案内を削除した。失敗時にも検索フォームを残し、検索結果0件として表示しない。準備中は同じ検索条件へ戻れるようにした。

## 検証

- `TestAdminAuditLargeResultPaging`：実際の制御履歴から、条件未選択の2,002件・2,826,417 JSON bytesを取得。既定50件で全41ページを走査し、欠落・重複0件。途中の追記は既存一覧へ含めず、再取得時に現れる。HTMLの最初のページと「次のページ」も200応答。
- `TestSnapshotAuditCatchUpBudgetMakesProgress`：旧実装では2 frameの予算で10回試しても進まないことを再現。修正後は取消と後続追記を挟んでも5回の有界な取込で完了し、期待する全要約と実HTTPの取得結果が一致。
- `TestAuditSnapshotSurvivesIndexPruning`：期限回収・索引の詰め直し・表示分類の解放後も、固定した記録IDと分類が変わらない。
- `TestAuditSnapshotBudgetSharesRecords`：複数一覧の同じ記録は一度だけ数え、異なる記録の合計が保持予算を超える場合は拒否する。
- 既存のAPI・HTML、秘密非表示、フィルタ、固定ページ、別セッション・権限外・改変cursorの拒否、再起動、破損・欠落した証明の拒否も対象にする。

実行ログはGit管理外の `var/audit-resume-20261101/` へ保存する。次の通常・race・ブラウザ検証はこの変更の関連範囲であり、製品全体の全試験ではない。

```sh
mise exec -- go test ./internal/bootstrap ./internal/webui -run 'Test(AdminAudit|Audit|SnapshotAudit|SnapshotRepository|ControlExpiryAudit)' -count=1 -timeout=4m
mise exec -- go test -race ./internal/bootstrap -run 'Test(AdminAudit|Audit|SnapshotAudit|SnapshotRepository|ControlExpiryAudit)' -count=1 -timeout=6m
mise exec -- go vet ./internal/bootstrap ./internal/webui
mise exec -- bash scripts/build.sh -o var/audit-resume-20261101/oimobbs ./cmd/oimobbs
mise exec -- python3 -B tools/designcheck/check.py
```

`OIMO_BROWSER_NODE`、`OIMO_PLAYWRIGHT`、`OIMO_CHROMIUM` を指定すると、大量記録の同じfixtureからChromiumも実行する。条件未選択の初期表示50件、次ページの別50件、エラーなし、390px幅の横はみ出しなしを `scripts/test-admin-audit-paging-browser.mjs` で検証する。既存の `TestAdminAuditBrowser` も操作者選択・詳細・期間・操作選択・JavaScriptなし・複数画面幅を確認する。
