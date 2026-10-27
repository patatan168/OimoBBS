# WAF・一覧・非必須ログ最適化の稼働反映

2026-10-24。[最適化と隔離試験](ingress-egress-optimization.md)の実装コミット `ffeafb4` を稼働環境へ反映しました。

BBSを `oimobbs:reading-resources-b3853f0-20261023` から `oimobbs:ingress-egress-20261024` へ更新しました。最終コミットからの再ビルドでも負荷試験済みイメージと一致し、IDは `sha256:5c86e1104eb00ec49fcdfb7e04069eee1965d942ce6f689207c1c291d35c197d` です。公開edge・証明書サービスのコンテナと起動時刻、CPU/メモリ割当は維持しました。

正常停止時の全 `/data` を退避し、別volumeで復元・新版起動・正常終了を確認しました。隔離リハーサルはネットワークなしで実施し、外部公開入口へ接続する通常healthcheckは切替後に実施しています。最終切替直前にも完全退避し、新volume `oimobbs-ingress-egress-20261024` へ復元しました。

- 最終backupは406,285,312 bytes、518項目。archive・一覧・SHA-256・旧compose/config・検証結果は非公開の `var/backups/deployments/ingress-egress-20261024/` に保持。
- 旧volume `oimobbs-reading-resources-b3853f0-20261023` と旧イメージのタグ `oimobbs:rollback-before-ingress-egress-20261024` を保持。
- BBSだけ再作成。最終停止からhealthyまで53.58秒、30秒の追加観測でも再起動0・OOMなし。非root・読取り専用rootを維持。
- 設定・管理認証等のサイト制御データ35行は全保存値のハッシュが更新前と一致。鍵・instance・証拠等73ファイルも内容・権限・所有者が一致。
- 実公開11経路の本文とETagが更新前と一致。条件要求304、HEAD、Range 206も正常。
- 実Chromiumで公開ページ、管理ログイン、実CSS、明暗表示、未認証API/証拠の401を確認。

管理ログインの実フォーム送信は正しいOrigin/Refererでしたが、従来の保存済み資格情報ではセッションを確立できず、認証後の管理操作は未確認です。資格情報は変更していません。稼働環境への負荷試験やテスト投稿は行っていません。
