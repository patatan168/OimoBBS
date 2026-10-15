# 運用手順

初回起動は[セットアップ](setup.md)、機能は[確定仕様](specification.md)を参照してください。以下はリポジトリのルートで、データを所有するOSユーザーから実行します。systemdの場合も管理CLIはサービスと同じユーザーで実行します。

## 停止・再開

手動起動はCtrl+Cで停止し、公開運用は次で再開します。

```sh
./bin/oimobbs serve --config config.json
```

ローカル検証は `validation-serve --config config.json --admin` を使います。systemdは `sudo systemctl stop oimobbs` / `sudo systemctl start oimobbs`、Dockerは[配備手順](../deploy/README.md)を使います。

停止中CLIを使う前に、同じ保存先のサービスを停止してください。保存先のファイルは管理CLIで操作します。

## 管理画面

設定の `admin.origin` へ直接接続します。通常は掲示板と同じHTTPS Origin・ポートの管理パスです。[同じポートでの管理公開](setup.md#管理画面を同じポートで公開する)を参照してください。ログイン後の `/manual` に操作方法があります。ロール・追加権限・担当板の選び方は[管理者の権限](admin-permissions.md)を参照してください。

| 操作 | 画面 |
| --- | --- |
| サイト名、板追加、板設定、カテゴリー | サイト設定・板設定 |
| 入力上限、ID、ローカルルール、CAP専用、転載禁止、専ブラ専用 | 対象板の設定 |
| 管理者・担当板・追加権限 | 管理者 |
| CAP発行、期限、停止、鍵リセット | 対象板のCAP管理 |
| IP/CIDR・本文・URL等の規制 | 投稿規制 |
| 全体・板別の閲覧と投稿許可 | 閲覧制限・対象板の閲覧制限 |
| ログイン前を含む管理用の接続条件 | 管理画面のアクセス |
| 類似文・埋め立て、共通投稿枠 | 掲示板全体の荒らし対策 |
| 通報条件、帯域、キャッシュ、整理 | 運用設定 |
| 空き容量、復旧予約、投稿時間、圧縮 | 保存の整理 |
| 案件、原本照会、保全、署名提出、受け渡し | 提出用ログ |
| 操作者・時刻・種類による確認 | 管理操作の記録 |

再認証が求められたら現在の管理者パスワードを入力します。権限不足は再認証で解除されません。古い画面との競合は最新内容を確認して入力し直します。保存結果が不明な場合は内容と要求IDを変えず、同じ要求で結果を確認します。

## 閲覧制限を設定する

「閲覧制限」で掲示板全体の条件を指定します。板ごとは「板設定 → 対象板 → 板の閲覧制限」、管理用は別の「管理画面のアクセス」で設定します。まずOFFのまま条件を入力し、確認後にONで保存できます。

IP/CIDRは1行に1件です。IP単独入力も受け付けます。許可IPが空ならIPで限定せず、指定した場合はその範囲内だけ許可します。拒否IP・国・回線・VPN条件の方が優先されます。国の拒否は `US`・`CN` などを1行に1件、UAは大文字小文字を区別しない部分一致の文字列を指定します。

管理用の許可リストには、画面に表示される現在のIPを含めます。公開入口構成でも認証済みの利用者IPを使います。Docker等の中継ではlocalhost接続がgatewayのIPに見える場合があります。条件の優先順位は[確定仕様](specification.md#閲覧と投稿の許可)を参照してください。

## 管理画面のアクセス制限を解除する

回線変更や分類の更新後にログイン画面へ入れなくなった場合は、サーバーを停止して管理用の制限だけをOFFにします。管理パスワードと掲示板の閲覧設定は維持します。

systemdの場合：

```sh
sudo systemctl stop oimobbs
./bin/oimobbs admin reset-reading-access --config config.json
sudo systemctl start oimobbs
```

手動起動の場合はCtrl+Cで停止し、解除後に通常の起動コマンドを実行します。

Dockerでは普段のComposeファイルと保存先指定を使います。

```sh
docker compose stop bbs
docker compose run --rm --no-deps bbs admin reset-reading-access --config /etc/oimobbs/config.json
docker compose start bbs
```

解除は監査へ記録します。

## 管理パスワードの再設定

サーバーを停止し、登録済みのログイン名を指定します。初回作成の `admin init` ではなく `reset-password` を使います。

```bash
read -r -s -p '新しい管理者パスワード: ' oimo_admin_secret
printf '\n'
printf '%s\n' "$oimo_admin_secret" | ./bin/oimobbs admin reset-password \
  --config config.json --login owner --password-stdin
unset oimo_admin_secret
```

再開後は新しいパスワードでログインします。

## 停止中の板管理・検査

稼働中の板追加は管理画面を使えます。停止中CLIは以下です。

```sh
./bin/oimobbs board create --validation --config config.json --key news --name 'ニュース'
./bin/oimobbs board list --validation --config config.json
```

同じキー・名前の再作成は同じ板を返し、名前が違えば拒否します。`--validation` は投稿と署名記録も照合する指定です。投稿済みサイトにも付けます。

板作成途中の停止から再開する場合は、保存済み要求を使います。

```sh
./bin/oimobbs board recover --validation --config config.json
```

`check` は初期サイト管理データ用です。投稿済みサイトは `board list --validation` で検査します。

## 復旧用ディスク予約

容量不足からの復旧に備え、停止中に256MiBを確保します。

```sh
./bin/oimobbs reserve prepare --config config.json --apply
./bin/oimobbs reserve status --config config.json
```

容量不足時は停止後、必要な量だけ予約を解放して検証付き回収を行います。例えば16MiBを空ける指定は次です。

```sh
./bin/oimobbs reserve release --config config.json --remaining-mib 240 --apply
```

予約ファイルを手で削除しません。容量回復後に `prepare --apply` を再実行して `ready: true` を確認します。補充と容量回復が完了するまで新規投稿が止まる場合があります。

## バックアップ

通常の停止中コピーは本文、検証情報、別保管の鍵束、隔離再生を一緒に確認します。以下は絶対パスの例です。保存先の外に、所有者限定の親を用意し、出力先は毎回未作成の名前にします。

```sh
mkdir -p /srv/oimo-backups/copies /srv/oimo-backups/keys /srv/oimo-backups/work
chmod 700 /srv/oimo-backups /srv/oimo-backups/copies /srv/oimo-backups/keys /srv/oimo-backups/work
./bin/oimobbs backup prepare --config config.json \
  --output /srv/oimo-backups/copies/site-001 \
  --keys-output /srv/oimo-backups/keys/site-001 \
  --work-parent /srv/oimo-backups/work
```

本文コピーと鍵束は別の保管領域で管理します。終了コードと `prepare` のJSONで、全工程の成功を確認してください。

稼働中の定期バックアップは `serve --online-backup-config <path>` で指定します。専用設定は所有者限定JSONで、コピー・鍵・計画・作業・信頼根の配置と資源上限を指定します。形式は [OnlineBackupConfig](../internal/bootstrap/backup_online_config.go) に定義しています。作成の `apply` と期限回収の `reclaim` は独立した明示設定です。

定期オンラインバックアップの容量予約が不足した場合は `deferred_capacity` を記録し、サーバーを継続したまま次の設定周期で再試行します。保存・解放などの別エラーが併記された場合は従来どおり停止します。投稿の空き容量制限も維持します。

通常バックアップは各本文の元の保持期限を超えて保存する仕組みではありません。長期の案件保全は管理画面の保全機能を使います。コピー・鍵束・途中出力・作業領域の回収は署名計画とCLIで行い、手作業でファイルを混ぜません。

## 復元

復元は停止した最新の完全保存先から、まだ存在しない別の保存先へ行います。`restored.json` は完全な起動設定をコピーし、`data_dir` を未作成の復元先に変更したものです。その親ディレクトリは事前に用意します。

```sh
./bin/oimobbs restore --source-config config.json --config restored.json
./bin/oimobbs board list --validation --config restored.json
```

欠けた本文を古いバックアップから補う場合は `restore` に `--backup <絶対パス>` を追加できます。最新台帳の削除・期限・規制を維持し、古い制御情報へ戻しません。通常の本文・鍵バックアップをそのまま `data_dir` に置く操作ではありません。

復元した保存先を確認してから、その設定で公開起動します。元の保存先は切替確認まで保持します。

## バイナリ更新

1. 新バイナリを別の名前でビルドし、必要な検証を行います。
2. サービスを停止し、旧バイナリ・設定・データの復旧用コピーを保持します。
3. 新バイナリを配置し、同じOSユーザー・設定・保存先で再開します。
4. 起動ログ、公開ページ、管理接続、投稿・再起動後の保存を確認します。

最低reader版を進めたデータへ古いバイナリを接続しません。戻す場合は旧バイナリと対応する復旧データの組を確認し、更新後の投稿を失う範囲を把握してから切り替えます。
