# セキュリティ運用

## 公開入口と管理接続

[compose.slip.yaml](../compose.slip.yaml) の公開入口 `public-edge` は443を受け、保存サーバーへmTLSで接続します。

| 対象 | 構成・制限 |
| --- | --- |
| 公開入口の保存領域 | 公開TLS鍵と専用client鍵のみ。掲示板データ、管理設定、投稿原本、サイト鍵、復号鍵はmountしない |
| 保存サーバー | 8443をホストへ公開せず、独立CA・client証明書SHA-256・入口の固定IPを検査 |
| 管理接続 | 公開サイトと同じ443の設定済み管理パス。ルート直下の管理API・ログインは404 |
| 接続元情報 | 実socketから生成し、利用者のForwarded・X-Forwarded-*・X-Oimo-*は転送しない |
| 要求本文 | 公開要求は最大64 KiB。設定済み管理パスは最大256 KiB、各操作の入力上限も検査 |
| 同時要求 | 全体128件、IP別8件 |
| TCP接続 | 全体256件、IPv4別／IPv6の64bitネットワーク別16件 |

管理用の別ポートとリレーは使いません。管理パスを公開入口と保存側に同じ値で設定し、実HTTPSログイン・管理画面のIP制限・クローラー拒否を確認します。管理IP制限は入口のIPではなく、mTLSで認証した入口が実socketから確定した利用者IPで判定します。

専用client証明書は `oimoedge init-client --output <新規ディレクトリ>` で生成します。期限前に新しい証明書を生成し、保存側のCA・証明書固定値・入口を一括更新します。変更前の `deploy/config.json` と `compose.slip.yaml` を退避してください。CA秘密鍵は生成後に保存しません。

HTTPSのHSTSは `max-age=31536000` です。includeSubDomains・preloadは指定せず、localhost HTTP管理には適用しません。カメラ・マイク・位置情報・決済・USBなどの不要なブラウザ機能も拒否します。

公開入口は保存領域を持たず、保存側の公開処理と管理処理は同じRepositoryを使います。

## 認証監視

ログイン・再認証・ログアウトを標準エラーへJSONで出力します。パスワード、ログイン名、Cookie、CSRF、本文は記録しません。認証済みアカウントは保存ID、接続元はプロセス専用鍵によるHMACで記録します。接続元のHMACは再起動ごとに変わります。

同じ操作・結果は毎分100件まで記録し、超過分を要約します。[security_monitor.py](../tools/security_monitor.py) はホストの0700/0600領域へ回収し、8MiBごとに3世代で回転します。失敗・制限・過負荷・内部エラーが5件以上になるとjournalへ通知します。

systemd設定例は [監視サービス](../deploy/oimobbs-security-monitor.service.example) と [timer](../deploy/oimobbs-security-monitor.timer.example) です。通知先はホストのjournalです。

## 暗号化バックアップ

オンラインバックアップの設定・作成は[運用手順](operations.md#バックアップ)を参照してください。同梱の稼働設定では12時間ごとに作成し、本文の元の保持期限と最長24時間のコピー期限を維持します。

[seal_online_backup.py](../tools/seal_online_backup.py) は作成・隔離再生の成功を確認して、コピーと鍵束を暗号化します。暗号化はX25519、HKDF-SHA256、AES-256-GCMの64KiB単位と認証済み終端を使う独自の `OIMOSEAL1` 形式です。改変・順序変更・切詰め・鍵違いを拒否します。

```sh
CGO_ENABLED=0 go build -o ./bin/oimoseal ./cmd/oimoseal
./bin/oimoseal generate --output /private/recovery-identity
./bin/oimoseal seal --key /private/recovery-identity/public.key \
  --input backup.tar --output backup.tar.seal
./bin/oimoseal open --key /private/recovery-identity/private.key \
  --input backup.tar.seal --output restored.tar
```

復号秘密鍵をアプリや暗号化処理へ渡さず、暗号文と別に保管します。ホスト喪失に備える場合は別ホストへ保管してください。暗号化後も元の期限で回収します。

`--destination SSH設定alias:/absolute/directory` でSFTP転送を指定できます。登録済みhost鍵を厳格検査し、受信側でも期限metadataに基づいて回収します。

### 復旧

新しい隔離領域にcopies・keys・workの親を用意し、稼働と同じUIDの所有、権限0700にします。復号したコピーと鍵束を展開し、検証付き再生を実行します。

```sh
./bin/oimobbs backup verify-replay \
  --input /srv/oimo-backups/copies/site-001 \
  --keys /srv/oimo-backups/keys/site-001 \
  --work-parent /srv/oimo-backups/work
```

`restore_ready` と除外項目を確認します。公開復元の手順は[復元](operations.md#復元)を参照してください。

## 継続検査とDDoS

[check-security-continuous.sh](../scripts/check-security-continuous.sh) は認証・境界のrace試験、vet、依存・文書検査、8種のfuzz、Go公式DBの脆弱性検査を実行します。[サービス](../deploy/oimobbs-security-check.service.example) と [日次timer](../deploy/oimobbs-security-check.timer.example) の例を用意しています。

接続数・処理数・サイズの制限はアプリの資源を守ります。回線を埋めるDDoSには上流側の対策が必要です。上流を導入する場合も、実利用者の接続情報を認証して渡し、保存側への直接接続を閉じてください。
