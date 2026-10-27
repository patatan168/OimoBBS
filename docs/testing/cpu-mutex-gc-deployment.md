# CPU・Mutex・GC改善版の稼働反映

2026-10-24。実装コミット`90ce8dd63d17b441fc8e30b784cef87565c239ea`の最終版E2を反映しました。[性能測定と全試行](cpu-mutex-gc-optimization.md)にあるとおり、**投稿1.6倍の目標は未達です。** 確認できた閲覧・排他待ち・2CPU継続負荷の改善を反映したもので、1.6倍達成版とは扱っていません。

| 対象 | 反映前 | 反映後 |
| --- | --- | --- |
| BBSイメージ | `oimobbs:ingress-egress-20261024` | `oimobbs:cpu-mutex-gc-20261024` |
| イメージID | `sha256:5c86e1104eb00ec49fcdfb7e04069eee1965d942ce6f689207c1c291d35c197d` | `sha256:673e0a1507ff9007bd6db75ec7bb30137e10ed65ef1d0729265b436ace90e31d` |
| データvolume | `oimobbs-ingress-egress-20261024` | `oimobbs-cpu-mutex-gc-20261024` |

`compose.yaml`・`compose.admin.yaml`・稼働用`compose.slip.yaml`を使用し、BBSだけを置換しました。public-edgeとcertificatesのコンテナID・開始時刻は同一です。CPU・メモリ・PID制限、送信予算、保存済みWAF等の設定は変更していません。稼働環境のCPU/メモリは従来どおりDockerの固定上限なしで、隔離試験の2/4CPU・4GiBとは別です。

## バックアップと復元

正常停止した`/data`全体をtarへ保存し、一覧・各ファイルのmode/UID/GID/SHA-256とarchiveのSHA-256を記録して同期しました。527項目・408,083,968bytesの最終archiveは次の場所に残しています。

`var/backups/deployments/cpu-mutex-gc-20261024-r2/before-data.tar`

SHA-256: `7f7a0e5257ede617154decebcf5a863ce3d91b9e629b6dc088aeade036806244`

別の完全バックアップを隔離volumeへ復元し、同じE2イメージをnetwork-noneで起動・正常終了する復元試験を実施しました。そのarchiveと復元結果も保持しています。最終切替は直前の新しい完全バックアップを別volumeへ復元してから行いました。旧イメージは`oimobbs:rollback-before-cpu-mutex-gc-20261024`として、旧データvolumeも変更せずに残しています。

最初の試行は補助スクリプトの制御ログ階層の想定誤りで、設定行の事前照合に失敗しました。新イメージの起動前に中断し、旧イメージ・旧volumeへ復帰しています。実際の`/data/site/site`と`/data/site/boards/<owner>/control`に合わせて修正し、保存済みarchiveから4所有者・57行を読めることを確認して再試行しました。最初のarchiveと失敗・復帰記録も`var/backups/deployments/cpu-mutex-gc-20261024/`へ保持しています。

再試行の切替開始からhealthy確認までは約51.16秒でした。公開経路の実停止時間を独立に連続測定した値ではありません。

## 切替後の確認

- BBSは意図したイメージ、healthy、再起動0回、非root `10001:10001`、read-only rootです。30秒間の追加観測でも維持しました。
- サイトと3板の制御ログを読取り専用で解析し、全57行のhashが一致しました。設定・資格記録を変更していません。
- 鍵、instance、保存資料等73ファイルのSHA-256・mode・UID/GIDが一致しました。最終archiveのチェックサムも再検証しました。
- 実際のHTTPS入口で11経路の本文・ETagが一致し、DATの304・HEAD・Rangeを確認しました。
- Chromiumで公開ページと管理ログインページを表示し、CSSの実配信一致とlight/dark表示を確認しました。未認証の管理APIと保存資料は401でした。
- 実フォームのPOSTは送信前にブラウザーで捕捉し、Origin/Refererを確認しました。サーバーへ認証要求は送っておらず、実際のログイン成功・ログイン後の管理画面は今回未検証です。既存の認証情報は変更していません。

稼働環境での投稿・負荷試験、WAN上の性能、停電・媒体故障からの復旧は検証していません。隔離試験の倍率を稼働環境の最大処理量へ読み替えません。
