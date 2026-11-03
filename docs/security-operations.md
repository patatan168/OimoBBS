# セキュリティ運用

公開入口・認証監視・暗号化バックアップの構成と運用方法です。通常の起動は[セットアップ](setup.md)、バックアップ作成と公開復元は[運用手順](operations.md)を参照してください。

| 目的 | 参照先 |
| --- | --- |
| 公開入口と保存サーバーを分ける | [公開入口と管理接続](#公開入口と管理接続) |
| ログインの保護・復旧方針を確認する | [管理者認証の保護](#管理者認証の保護) |
| 認証失敗を確認する | [認証監視](#認証監視) |
| バックアップを暗号化・転送する | [暗号化バックアップ](#暗号化バックアップ) |
| 保存済みの暗号文から戻す | [復旧](#復旧) |
| 定期検査・大量通信への備え | [継続検査とDDoS](#継続検査とddos) |

## 公開入口と管理接続

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

## 管理者認証の保護

登録・ログイン・復旧の手順は[管理認証](features/administration.md)を参照してください。運用時に確認する要点は次のとおりです。

| 項目 | 保護する内容 |
| --- | --- |
| パスキー | 本人確認を必須にし、設定済みのホスト・Origin・アカウント・用途を検証。未ログインの応答に鍵ID一覧を含めない |
| パスワード＋OTP | OTP登録後は両方を必須にする。OTP単独・パスワード単独の認証は拒否 |
| OTPの保存 | 共有鍵は暗号化し、使用済み区間を耐久保存。保存失敗時はログインさせず受付を停止 |
| ログイン制限の変更 | パスキーまたはパスワード＋OTPでの再認証が必要 |
| 認証手段の削除・方針変更 | 本人の全セッションを失効させる。パスキー削除時は旧世代で確定待ちの操作も拒否 |
| 認証情報の記録 | 登録用キー・OTPコード・一時パスワードをURLや認証監視に記録しない |
| 最終復旧 | サイト管理者は停止中CLIのみ。他の管理者はサイト管理者がWebで一時パスワードを発行 |

OTPは偽サイトへのコード入力を防げません。通常はパスキーを使い、端末を失ったときに備えてOTPも登録できます。OTPで復旧する場合もパスワードが必要です。

### 締め出しとセッション占有を抑える仕組み

パスワード照合前の制限は接続元単位です。アカウント名を指定した失敗だけで、別の接続元の本人を締め出すアカウント共通停止は設けません。OTPコードのアカウント共通枠は、正しいパスワードを確認した後に消費します。分散した接続元によるパスワード推測には、全体の受付上限・導出処理の上限・WAF有効時の全体認証制限を併用します。

ログイン画面のトークンは署名付き・10分期限です。発行時にサーバー記録を増やさず、使用済みの記録だけを有限件数で保持します。Origin・CSRF・トークン再利用・OTPコード再利用も検査します。

セッションは1アカウント32件・全体10,000件までです。33件目のログインでは本人の最終利用が最も古いセッションを失効させ、他の管理者のセッションは追い出しません。各認証方式の試行回数と期限は[認証試行とセッションの上限](features/administration.md#認証試行とセッションの上限)にまとめています。

## 認証監視

ログイン・再認証・ログアウトを標準エラーへJSONで出力します。パスワード、ログイン名、Cookie、CSRF、本文は記録しません。認証済みアカウントは保存ID、接続元はプロセス専用鍵によるHMACで記録します。接続元のHMACは再起動ごとに変わります。

同じ操作・結果は毎分100件まで記録し、超過分を要約します。[security_monitor.py](../tools/security_monitor.py) はホストの0700/0600領域へ回収し、8MiBごとに3世代で回転します。失敗・制限・過負荷・内部エラーが5件以上になるとjournalへ通知します。

systemd設定例は [監視サービス](../deploy/oimobbs-security-monitor.service.example) と [timer](../deploy/oimobbs-security-monitor.timer.example) です。通知先はホストのjournalです。

## 暗号化バックアップ

オンラインバックアップの設定・作成は[運用手順](operations.md#バックアップ)を参照してください。稼働用の定期バックアップ構成では12時間ごとに作成し、本文の元の保持期限と最長24時間のコピー期限を維持します。一般のセットアップスクリプトは、この定期作成や暗号化を自動登録しません。

[oimoseal](../cmd/oimoseal/backup_commands.go) の `sync` は作成・隔離再生の成功記録を読み、`pack` がコピーと鍵束を再検証して暗号化します。暗号化・tar作成・送受信の管理・期限回収はGoで実装し、この経路でPythonや外部tarコマンドは使いません。暗号化はX25519、HKDF-SHA256、AES-256-GCMの64KiB単位と認証済み終端を使う独自の `OIMOSEAL1` 形式です。改変・順序変更・切詰め・鍵違いを拒否します。

暗号文を同期・設置してから、完成記録を一時ファイルへ書いて同期し、置換します。保存先ディレクトリの同期まで成功した場合だけ、完成報告・転送へ進みます。既存暗号文を再利用・転送する前には、全体のSHA-256を完成記録と照合します。不一致・欠落・壊れた完成記録は、Dockerの完成ログに残る未期限切れのコピーを再検証・再暗号化します。再作成できない不正な組は転送せずエラーにします。全体照合により、保存量に比例した読込みが増えます。秘密鍵による復号検証は暗号化ホストでは行いません。[途中停止・保存失敗](testing/sealed-backup-resilience.md)と[復号・転送再試行の追加検証](testing/sealed-restore-resilience.md)を参照してください。

```sh
CGO_ENABLED=0 go build -o ./bin/oimoseal ./cmd/oimoseal
./bin/oimoseal generate --output /private/recovery-identity
./bin/oimoseal seal --key /private/recovery-identity/public.key \
  --input backup.tar --output backup.tar.seal
./bin/oimoseal open --key /private/recovery-identity/private.key \
  --input backup.tar.seal --output restored.tar
./bin/oimoseal sync --container oimobbs-validation-bbs-1 \
  --image oimobbs-validation:local --source var/security/online-backup \
  --output var/security/encrypted-backups \
  --destination backup-host:/srv/oimo-backup-receive
```

`sync` の送信元にはDocker CLIと、転送する場合はOpenSSHクライアントが必要です。指定イメージにも `oimoseal pack` と保存形式に対応する `oimobbs` を含めます。`source/encryption/public.key` は32byteの公開鍵とし、コピー・鍵束とともにコンテナの実行UIDが所有します。ファイルは0600、ディレクトリは0700を使い、暗号文の出力先はホスト側の実行ユーザー、受信先はSSHユーザーが所有します。復号秘密鍵は元コピーの領域に置きません。定期実行は[service例](../deploy/oimobbs-sealed-backup.service.example)を使います。

復号結果は全chunkと終端の認証、ファイルの同期・Closeを終えてから最終名へ排他的に設置します。強制終了時の一時ファイルは0600で、同じ出力名の次回実行時に排他を取って回収します。同名出力の処理中は待機せずエラーを返し、別名の出力は並行できます。排他用の空の0600ファイル `.oimoseal-<hash>-lock` は保持します。既存の最終出力は上書きしません。

最終名設置後のディレクトリ同期に失敗した場合は、完全なファイルが残っていてもエラーを返します。終了コードを確認し、再検証する場合は新しい出力名を使います。出力先にはファイルの排他・hardlink・ディレクトリ同期に対応する保存先を使います。

復号秘密鍵をアプリや暗号化処理へ渡さず、暗号文と別に保管します。ホスト喪失に備える場合は別ホストへ保管してください。暗号化後も元の期限で回収します。

`sync` の `--destination SSH設定alias:/absolute/directory` で原子的な世代設置を伴うSSH転送を指定できます。受信先にはGo版 `oimoseal` を事前に `/usr/local/bin/oimoseal` へ配置し、SSHコマンド実行を許可します。異なる設置先は `--receiver /absolute/path/oimoseal` で指定します。受信先にPython・Docker・tarコマンドは不要です。SFTP専用アカウントでは利用できません。既存のOpenSSH設定を使い、任意の設定ファイルは `--ssh-config` で選べます。登録済みホスト鍵を厳格に検査し、復号秘密鍵は送りません。

既存の暗号文と完成記録だけを送る場合は `oimoseal send --input /private/backup.seal --manifest /private/backup.json --destination backup-host:/srv/oimo-backup-receive` を使います。`receive` はこの送信処理から呼び出します。

受信先の親directoryをSSHユーザー所有の0700で用意します。暗号文と完成記録は受信先の一時directoryへ保存し、長さ・全体hash・期限を照合して、両fileとdirectoryを同期します。その後 `backup-<ID>-<SHA256>/` へrenameし、親を同期してから完了を通知します。完成世代の中身は `archive.seal` と `manifest.json` です。期限内の以前の世代は上書きしません。受信中断や応答消失後の再送、設置済み世代の再検証にも対応します。

転送の再試行は、Dockerの完成ログではなく保存済みの期限内の完成記録からも行います。Dockerログ取得は30秒までとし、取得失敗時も検証済みの既存コピーの転送・期限回収へ進んだ後、ログ取得のエラーを返します。受信した暗号文のhash一致と、復号秘密鍵での認証復号は別に確認します。

送信元が停止しても期限を守るため、受信先にも[独立した回収timer](../deploy/oimobbs-backup-receive-gc.timer.example)を設定し、`/usr/local/bin/oimoseal sweep --root /srv/oimo-backup-receive` を実行します。暗号文・完成記録・世代の保存配置は従来と同じです。Python版からは送信元・受信先の実行バイナリとserviceを一緒に更新します。旧scpの平置き `.seal/.json` は回収対象外なので、既存手順で期限管理してください。Go版の実SSH・Docker検証範囲は[Goへの統合](testing/sealed-backup-go.md)を参照してください。

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
