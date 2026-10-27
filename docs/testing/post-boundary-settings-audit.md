# 投稿形式と稼働設定の確認

2026-10-24。CPU・Mutex・GC最適化後の投稿入口と稼働設定を確認しました。

## 発見と修正

掲示板の投稿は従来から`application/x-www-form-urlencoded`のみを受理します。`multipart/form-data`を投稿として保存する経路はありませんでした。ただし、結合された不正なContent-Type（例：`application/x-www-form-urlencoded; charset=UTF-8, multipart/form-data`）はHTTP観測器の検査で失敗し、503になっていました。公開CGI・Web投稿の隔離HTTPで再現しました。

共通のHTTP境界で形式・文字コードを本文読取り前に検査するよう変更し、観測器へ進めず415を返します。本文復号と同じ検査関数を使います。正しい投稿形式・文字コード、CSRF、Origin、重複ヘッダ、本文・項目数の上限は維持します。管理APIのJSON受付には変更しません。

`TestPublicPostingInputBoundaries`は実multipart、multipart表記のフォーム、JSON、text/plain、Content-Type欠落・重複・不正結合、未対応文字コード、gzip表記、重複項目・エスケープによる重複、壊れたエスケープ、無効UTF-8、32項目超過、64KiB超過を公開CGIとWeb投稿の実HTTPで確認します。Webには有効なCSRFとCookieを渡し、別の認証拒否で結果を隠さないようにしています。30拒否ケースで投稿未保存を確認し、正常入力が確認画面に進むことも確認します。別の8ケースで観測器なし・本文読取り0回の早期拒否を確認します。

## 稼働設定

Docker inspect、起動設定、サイト制御ログのコピーを読取り専用で検査しました。制御ログは製品のmutation/snapshot検証器で解析しています。

- BBSと公開入口は非root、read-only root、全capability削除、権限昇格禁止。BBSの外部ポート公開はなく、公開入口だけが443を公開します。入口からBBSはmTLS認証で、信頼するproxyは入口の単一IPです。
- WAFとアクセス制限はON。通常要求は回線60件/秒・全体300件/秒、同時回線32・全体128。未保存の追加項目は既定値を適用し、回線別制限もON、投稿専用枠は回線10件/秒・全体60件/秒、同時回線8・全体32です。
- 投稿間隔制限はON、返信1秒・burst3、スレッド作成600秒・burst1。類似投稿はobserve、集中投稿はrejectで、既存設定を変更していません。
- HTTPログとログ欠落記録はactive。コンテナ標準出力は5MiB×2にローテーションします。
- BBSのCPU・メモリ固定上限なしは既存方針です。環境変数はPATHだけで、試験用設定やGC無効化はありません。Goのメモリ目標・メモリ受付制御は残っています。公開入口は256MiB、PID制限はBBS128・入口64です。
- 公開サーバーと入口はheader5秒・本文10秒・送信30秒、header16KiB、公開本文64KiBの上限を保持します。HTTP/2のstream/windowも有界です。
- 実HTTPSの公開一覧とsubject.txtは200、管理ログインは200、未認証管理APIは401。設定・環境ファイル・Git・pprof・metricsの6経路は403/404で取得できません。HSTSとnosniffも確認しました。

この範囲で他に設定を変更すべき問題は見つかりませんでした。認証済み管理操作、WAN負荷・DDoS、実環境への不正POSTは今回の確認範囲に含めません。

## 検証

- compat・bootstrapの投稿形式、HTTP境界、CSRF、WSTG HTTP、WAF、edge信頼設定、security header、非必須ログの関連試験：成功。
- publicedge・waf・delivery・platformの全通常試験：成功。
- 投稿形式と境界・WAF早期拒否の関連race試験：成功。
- compat・bootstrapのgo vet、git diff --check：成功。

詳細な実行ログ・稼働設定の抽出は、非公開の`var/settings-audit-20261024/`と`/tmp/oimo-settings-audit-*.log`に保存しています。

## 稼働反映

修正コミット`cd1089d32223a09b0af916bf6fdd418577844723`を、BBSイメージ`oimobbs:post-boundary-20261024`（`sha256:74adc6cf6a3ecef1899cd60bc0f49572bb17108cd5169abb31b042f12ce279a0`）へビルドしました。完全バックアップを別volumeへ復元して新版の起動・正常終了をnetwork-noneで検証した後、切替直前の新しい完全バックアップを別volume `oimobbs-post-boundary-20261024`へ復元してBBSだけを置換しました。入口と証明書コンテナは変更していません。

最終バックアップは`var/backups/deployments/post-boundary-20261024/before-data.tar`、527項目・408,501,760bytes、SHA-256は`c3ee76ac62c136a3b3616580458dac21c4844f1f6dc2e5e7c77c03e24614a03b`です。旧volume `oimobbs-cpu-mutex-gc-20261024`と旧イメージのタグ`oimobbs:rollback-before-post-boundary-20261024`も保持しています。稼働用`compose.slip.yaml`は新イメージ・新volumeへ更新しました。

切替開始からhealthy確認までは53.18秒です。バックアップ用停止の時間とは別に起動待ちがあり、公開経路の停止時間を独立した連続観測で測った値ではありません。切替後の4所有者・57設定行が完全一致し、鍵・instance・保存資料等73ファイルの内容・権限・所有者も一致しました。公開11経路の本文・ETag、DATの304・HEAD・Rangeと、別の9経路の公開/未認証管理応答を再確認しました。30秒間の追加観測でもhealthy・再起動0・OOMなしでした。
