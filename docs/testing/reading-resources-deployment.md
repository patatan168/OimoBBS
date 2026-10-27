# 閲覧・投稿最適化の稼働反映

2026-10-23 23:11 JST。`b3853f0` までの[閲覧資源利用の改善](reading-resource-scaling.md)と[投稿・復旧処理の改善](posting-cpu-continuation.md)を、稼働中のBBSへ反映しました。

旧イメージ `oimobbs:country-conflicts-20261022` から `oimobbs:reading-resources-b3853f0-20261023` に更新しました。クリーンなソースからの再ビルド結果は負荷試験済みイメージと同一で、IDは `sha256:d032957c785d32cade5e59dd245ddf5b30fed5df207b397b6861cbed7d025497` です。

BBSを正常停止して全 `/data` を退避し、別volumeで復元・新版起動・正常終了を確認しました。隔離環境はネットワークを無効にしており、外部公開入口へ接続する通常のhealthcheckは適用できません。最終切替直前にも全データを再退避し、新volumeへ復元しています。旧volume `oimobbs-validation-country-conflicts-20261022` と旧イメージのタグ `oimobbs:rollback-before-reading-resources-20261023` は保持しました。

実行記録・復元用archive・一覧・SHA-256・旧compose/configは非公開ディレクトリ `var/backups/deployments/reading-resources-b3853f0-20261023/` に保存しています。最終archiveは409,197,568 bytes、511項目です。適用中のcomposeは従来どおり `compose.yaml`、`compose.admin.yaml`、`compose.slip.yaml` の順で、最後のファイルのBBSイメージと外部データvolumeだけを更新しました。

確認結果は次のとおりです。

- BBSだけ再作成。公開edge・証明書サービスのコンテナと起動時刻は不変。
- 最終停止からhealthyまで51.99秒。公開入口を経由するhealthcheckは正常、30秒間の追加観測でも再起動0・OOMなし。非root・読取り専用rootを維持。
- 管理認証・運用設定などサイト制御データ35行は、保存値のハッシュがすべて更新前と一致。
- 鍵・instance・証拠項目など73ファイルは内容・権限・所有者が一致。全バックアップのSHA-256も一致。
- 実公開11経路の本文とETagが一致。DATの条件要求304、HEAD、Range 206を確認。
- 実Chromiumで公開ページ、管理ログイン画面、CSS、明暗表示、未認証API・証拠への401を確認。
- ブラウザーの実フォーム送信は正しいOrigin/Refererでしたが、保存済み資格情報ではセッションを確立できず、認証済み管理APIは401。認証後の管理操作は未確認です。資格情報は変更していません。

性能の数値はリンク先の隔離試験によるもので、稼働環境への負荷試験は行っていません。CPU・メモリの稼働割当は変更していません。
