# 高圧縮化・512MiB対策の稼働反映

2026-10-25。コミット`50621312569588e8c36be9aedf6c5c4d6d1e507f`の[高圧縮化](high-compression.md)と[512MiBでの受付回復](memory512-recovery.md)を稼働BBSへ反映しました。

| 対象 | 反映前 | 反映後 |
| --- | --- | --- |
| イメージ | `oimobbs:network-zstd-only-20261024` | `oimobbs:compression-memory512-20261025` |
| イメージID | `sha256:908fb28818376db22b8f2b53aadb8ace42734407d7fa7b98a6929fea48661772` | `sha256:785d57bc85aab211471b1a6e4c6ea4b0d003be38df89c19a98fb208da3d8cac4` |
| データvolume | `oimobbs-network-zstd-only-20261024` | `oimobbs-compression-memory512-20261025` |

BBSだけを置換し、public-edgeとcertificatesのコンテナID・起動時刻は一致しています。CPU・メモリ・PID制限、送信予算、WAF等の保存設定は従来どおりです。稼働環境のCPU・メモリはDockerの固定上限なしで、隔離試験の2CPU・512MiBとは別です。非root `10001:10001`とread-only rootも維持しています。

## 退避と復元

正常停止した全`/data`をtarへ退避し、一覧・各項目のSHA-256・mode・UID/GIDとarchiveのSHA-256を記録して同期しました。切替直前のarchiveは421,697,536bytes、527項目です。

`var/backups/deployments/compression-memory512-20261025/before-data.tar`

SHA-256: `3fa5f9eca4d18d65e82393de204c23b7c24c8b8d922de2f8dd7e587666097a55`

事前の完全バックアップを別volumeへ復元し、network-noneで新版の起動・正常終了を確認しました。その領域を旧版でも起動・正常終了できることを確認しています。最終切替は直前の新しい完全バックアップを別volumeへ復元し、起動前に527項目すべての内容・mode・UID/GIDがarchiveの一覧と一致することを確認しました。保存形式の移行はありません。

旧イメージは`oimobbs:rollback-before-compression-memory512-20261025`、旧データvolumeもそのまま保持しています。設定・compose、退避・復元・公開検証・ブラウザー結果は同じ非公開ディレクトリへ保存しました。

切替開始からhealthy確認までは約50.64秒です。公開経路の実停止時間を独立に連続測定した値ではありません。

## 切替後の確認

- healthy、再起動0、OOMなし。30秒の追加観測でも維持しました。
- サイトと3板の制御データ全57行のhashが一致。設定・資格情報の保存値を保持しています。
- 鍵・instance・保存資料等73ファイルの内容・mode・UID/GIDが一致。最終archiveのSHA-256も再検証しました。
- 公開11経路の本文・identity ETagが一致。DATの304・HEAD・Range 206を確認しました。
- DATとスレッドHTMLのgzip・zstdを独立した復号器でidentity本文と照合し、304とHEADを確認しました。gzipの表現は保持し、zstdのETagは`-zstd-v8`へ更新。旧zstd ETag付きの要求は200で新表現を返しました。
- Chromiumで公開トップ・管理ログイン、CSSの実配信一致、明暗表示、未認証APIと保存資料への401を確認しました。ログイン画面の実画像も確認しています。
- 管理ログインのフォームPOSTは送信前にローカル応答へ置き換え、Origin/Refererを確認しました。認証要求はサーバーへ送っておらず、ログイン成功・認証後の管理操作は未検証です。資格情報は変更していません。

切替前の圧縮検査補助スクリプトで、304応答時にcurlが本文ファイルを作らないケースを処理できず一度停止しました。空本文として扱うよう修正し、切替前後の検査を通過しています。BBSの切替失敗や切り戻しは発生していません。

稼働環境での投稿・負荷試験、実NIC・WANの性能、停電・媒体故障からの復旧は検証していません。512MiBでの試験成績はリンク先の隔離条件によるものです。
