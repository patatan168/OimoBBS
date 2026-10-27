# 投稿準備・入口WAFの稼働反映

2026-10-26。コミット`f12cf24b3f74b35d4fd32c3f9dca05dc06767fb9`の[投稿準備の改善](posting-multicore.md)と[入口WAF](waf-ingress.md)を稼働BBSへ反映しました。[反映結果](posting-waf-deployment.json)には検査結果と元資料のSHA-256を記録しています。

| 対象 | 反映前 | 反映後 |
| --- | --- | --- |
| イメージ | `oimobbs:compression-memory512-20261025` | `oimobbs:posting-waf-20261026` |
| イメージID | `sha256:785d57bc85aab211471b1a6e4c6ea4b0d003be38df89c19a98fb208da3d8cac4` | `sha256:931497975da636554c9c8664c366419662fcedbabb94b2bac9ef0a7f12050208` |
| データvolume | `oimobbs-compression-memory512-20261025` | `oimobbs-posting-waf-20261026` |

最終隔離測定の通常版イメージを識別情報で固定し、製品ソースのSHA-256が現在のソースと一致することを確認して再利用しました。BBSだけを置換し、public-edgeとcertificatesのコンテナID・起動時刻は維持しています。非root、read-only root、CPU・メモリ・PID制限も維持しています。稼働環境はDockerのCPU・メモリ固定上限なしで、隔離測定の条件とは異なります。

## データの退避と復元

正常停止した全`/data`を退避し、一覧・各項目の内容とmode・UID/GID・archiveのSHA-256を保存・同期しました。最終archiveは426,146,816bytes、540項目です。

`var/backups/deployments/posting-waf-20261026/before-data.tar`

SHA-256: `95a9ea82eff39c4ec3420047980aeadfeac6cde688b276337eb86ae4e20195b3`

事前の完全バックアップを別volumeへ復元し、network-noneで新版の起動・正常終了、その後の旧版による起動・正常終了を確認しました。切替時は直前に取り直した完全バックアップを新しい稼働volumeへ復元し、起動前に540項目すべての内容・mode・UID/GIDが一致することを確認しました。保存形式の移行はありません。

旧イメージは`oimobbs:rollback-before-posting-waf-20261026`として保持し、旧volumeと隔離復元volumeも保持しています。設定・compose・検査用スクリプト・結果は同じ非公開ディレクトリにあります。

## 稼働確認

- healthy、再起動0、OOMなし。30秒の追加観測でも維持しました。
- サイトと3板の制御データ58行が一致。WAFは既存のON設定を維持し、頻度制限・資格情報・板設定も変更していません。
- 鍵・instance・保存資料等73ファイルの内容・mode・UID/GIDが一致。archiveのSHA-256も再検証しました。
- 公開11経路の本文・identity ETagが一致。DATの304・HEAD・Range 206を確認しました。
- DAT・スレッドHTMLのgzip/zstdを独立した復号器でidentity本文と照合し、表現のETag・圧縮byte数、304・HEADも一致しました。
- 公開・管理それぞれでUser-Agent 1,024byteは200、1,025byteはno-store付き403でした。反映前の1,025byteは200であり、新しい制限の稼働を確認しています。
- Chromiumで公開トップ・管理ログイン、CSSの実配信一致、明暗表示、未認証API・保存資料の401を確認し、ログイン画面の画像も確認しました。
- 管理ログインの実フォームPOSTは送信前にローカル応答へ置き換え、OriginとRefererを確認しました。資格情報は送信・変更しておらず、ログイン成功や認証後の管理操作は未検証です。

本番への試験投稿・負荷試験は行っていません。Host・制御文字・Content-Length・HTTP/2の詳細境界は[隔離検証](waf-ingress.md)の結果と区別します。本番WAN/NICの処理量、DDoS耐性、電源断・媒体故障からの復旧も未検証です。

## 切替時の観測

切替開始からhealthyまで48.89秒でした。約0.5秒間隔の公開GET観測では503が53件、4秒timeoutが3件あり、切替開始から約46.95秒の応答で200へ復帰しました。これは逐次要求の完了時刻であり、厳密な停止時間の境界ではありません。事前バックアップ取得時にもBBSを正常停止・再開しており、そのときの公開停止時間は連続測定していません。

事前再起動直後の補助プローブが503で一度停止し、healthy待機後の再実行は通過しました。隔離コピーの設定検査でもファイルmodeの条件で一度停止し、コピーを元の秘密modeへ直して通過しました。検査失敗に伴う稼働データの修正、切替失敗、切り戻しは発生していません。
