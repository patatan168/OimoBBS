# 運用手順

作成済みサイトの日常管理、更新、バックアップ、復旧の手順です。初回起動は[セットアップ](setup.md)を参照してください。コマンドはリポジトリのルートで、データを所有するOSユーザーから実行します。systemdの場合も管理CLIはサービスと同じユーザーで実行します。

## 目的から探す

| 目的 | 手順 |
| --- | --- |
| サーバーを止める・再開する | [停止・再開](#停止再開) |
| 操作する管理画面を探す | [管理画面の使い方](admin-guide.md) |
| 管理画面の応答が遅い | [応答待ちの切り分け](#管理画面の応答待ちを調べる) |
| 閲覧できる接続元を限定する | [閲覧制限](#閲覧制限を設定する) |
| 管理画面に入れなくなった | [アクセス制限の解除](#管理画面のアクセス制限を解除する)・[パスワードの再設定](#管理パスワードの再設定) |
| 保存先を退避する・別の保存先へ復旧する | [バックアップ](#バックアップ)・[復元](#復元) |
| 保存容量と自動回収を確認する | [容量の確認](#保存容量を確認する) |
| 容量不足から復旧する | [復旧用ディスク予約](#復旧用ディスク予約) |
| バイナリを入れ替える | [バイナリ更新](#バイナリ更新) |

## 停止・再開

### systemdサービス

必要な操作を選んで実行します。

| 操作 | コマンド |
| --- | --- |
| 状態を確認 | `systemctl status oimobbs.service --no-pager` |
| 直近50行のログを確認 | `sudo journalctl -u oimobbs.service -n 50 --no-pager` |
| 停止 | `sudo systemctl stop oimobbs.service` |
| 再開 | `sudo systemctl start oimobbs.service` |
| 再起動 | `sudo systemctl restart oimobbs.service` |

起動後は公開ページと管理ログインも確認します。

自動起動を解除する場合は `sudo systemctl disable --now oimobbs.service` を実行します。登録自体を削除する場合は、停止後に `/etc/systemd/system/oimobbs.service` をsudoで削除し、`sudo systemctl daemon-reload` を実行します。設定・データは保持されます。

### 手動起動・Docker

手動起動はCtrl+Cで停止し、HTTPS公開は次で再開します。

```sh
./bin/oimobbs serve --config config.json
```

ローカル検証は `./bin/oimobbs validation-serve --config config.json --admin`、Dockerは[停止・再開の手順](../deploy/README.md#再開停止)を使います。

### 停止中CLIを使う前に

停止中CLIを使う前に、同じ保存先のサービスを停止してください。保存先のファイルは管理CLIで操作します。

### 起動後の監査処理

起動直後と、その後1分ごとに監査記録を引き渡します。一度に調べる履歴量が上限に達した場合は、公開受付を続け、確定済みの位置から次の周期に処理を再開します。データ破損や保存失敗も起きている場合は停止します。

## 管理画面

設定の `admin.origin` へ直接接続します。通常は掲示板と同じHTTPS Origin・ポートの管理パスです。ログイン後の画面内マニュアルも使えます。

| 調べたいこと | 参照先 |
| --- | --- |
| どの画面を開くか・設定を保存する流れ | [管理画面の使い方](admin-guide.md) |
| 操作者・操作・対象板から記録を探す | [管理操作の記録](admin-guide.md#管理操作の記録を調べる) |
| レス削除・投稿者規制・スレッド停止 | [レスとスレッドの管理](admin-guide.md#レスとスレッドを管理する) |
| 再認証の期限が切れたとき | [ログインと再認証](admin-guide.md#ログインと再認証) |
| パスキー・OTPの登録、ログインできる方法 | [管理認証](features/administration.md#ログイン方法) |
| ロール・追加権限・担当板 | [管理者の権限](admin-permissions.md) |
| 公開する管理URL・ポート | [管理画面の公開設定](setup.md#管理画面を同じポートで公開する) |

セッションが切れた場合は、説明付きのログイン画面を表示します。HTMLの受信後にCSS/JSの認証が失効した場合もログイン画面へ戻ります。管理用資産の認証・権限確認と `no-store` は維持します。

### 管理画面の応答待ちを調べる

ブラウザの開発者ツールで、Networkから対象のHTML要求を選び、Response Headersの `Server-Timing` を確認します。単位はミリ秒です。例えば `dur=2.5` は2.5秒ではなく、2.5ミリ秒を表します。

| 計測名 | 含む処理 |
| --- | --- |
| `admin` | 要求枠に入ってから応答ヘッダを作るまでのアプリ処理 |
| `admin_reading` | 接続元の判定。必要なDNS確認を含む |
| `admin_session` | セッション・アカウントの確認。排他待ちを含む |
| `admin_audit_query` | 監査の履歴照合・検索・排他待ち |
| `admin_audit_view` | 監査の選択肢・操作者名の準備とHTML描画 |

`admin_reading` 以降の4項目は `admin` の内訳です。足し合わせて全体時間を求める値ではありません。監査専用の2項目は監査の要求で返します。

| 観測した状態 | 次に確認すること |
| --- | --- |
| 再起動後、操作記録を初めて開くときに遅い | 初回の履歴照合。`admin_audit_query` と、2回目以降の値を比較 |
| `admin_reading` が大きい | 接続元の分類・DNS確認 |
| `admin_session` や `admin_audit_query` が大きい | 認証・検索処理と、他の管理操作等による排他待ち |
| `admin` は小さいのにブラウザの待機が長い | 要求枠・送信帯域の待機、edge、通信経路、ブラウザ側の処理 |

要求枠に入る前の待機、送信帯域の待機、edgeの処理、通信往復、本文転送、ブラウザ描画は `admin` に含みません。特定のブラウザ拡張やセキュリティ製品の影響も、この値だけでは断定できません。

## 閲覧制限を設定する

「閲覧制限」で掲示板全体の条件を指定します。板ごとは「板設定 → 対象板 → 板の閲覧制限」、管理用は別の「管理画面のアクセス」で設定します。まずOFFのまま条件を入力し、確認後にONで保存できます。

IP/CIDRは1行に1件です。IP単独入力も受け付けます。許可IPが空ならIPで限定せず、指定した場合はその範囲内だけ許可します。拒否IP・国・回線・VPN条件の方が優先されます。国の拒否は `US`・`CN` などを1行に1件、UAは大文字小文字を区別しない部分一致の文字列を指定します。

管理用の許可リストには、画面に表示される現在のIPを含めます。公開入口構成でも認証済みの利用者IPを使います。Docker等の中継ではlocalhost接続がgatewayのIPに見える場合があります。条件の優先順位は[閲覧と投稿の許可](features/reading.md#閲覧と投稿の許可)を参照してください。

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

認証手段を失った場合は、対象者のロールによって復旧方法が異なります。

| 対象者 | 復旧方法 |
| --- | --- |
| サイト管理者 | サーバーを停止し、以下のコマンドで再設定 |
| サイト管理者以外 | サイト管理者がWebで一時パスワードを発行。[復旧の手順](features/administration.md#ログインできない管理者の復旧)を参照 |

### サイト管理者をコマンドで復旧する

1. [停止手順](#停止再開)に従って、同じ保存先を使うサーバーを停止します。
2. 登録済みのサイト管理者のログイン名を指定し、次を実行します。例の `owner` と設定ファイルのパスは実環境に合わせます。初回作成の `admin init` は使いません。

```bash
read -r -s -p '新しい管理者パスワード: ' oimo_admin_secret
printf '\n'
printf '%s\n' "$oimo_admin_secret" | ./bin/oimobbs admin reset-password \
  --config config.json --login owner --password-stdin
unset oimo_admin_secret
```

3. サーバーを再開し、新しいパスワードでログインします。
4. パスキー・OTP・ログイン制限を設定し直します。

再設定は対象のサイト管理者を有効に戻し、全セッション・パスキー・OTPと「パスキーまたはパスワード＋OTPだけを受け付ける」の設定を解除します。

### 一時パスワードで復旧するときの注意

Webの一時パスワードは1時間有効で、表示は発行時の一度だけです。対象者はログイン後、パスワード変更が完了するまで管理操作を使えません。期限切れ・応答紛失時は新しく発行し直してください。サイト管理者へのWebリセットと、下位管理者へのコマンドリセットは拒否します。

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

## 保存容量を確認する

1. 管理画面の「保存の自動整理」で、実空き容量と投稿受付の状態を確認します。
2. 容量回収の状態と起動後の件数を確認します。公開起動の `serve` は、最終投稿から7日以上の未満杯スレッド、満杯スレッドの順に古いものから回収します。
3. 回収が進まない場合は、表示された理由、保存先の権限、サーバーログを確認します。保全中・固定・システム報告スレッドは回収対象外です。
4. 回収できる古いスレッドがなければ、手動バックアップなどの使用量を確認するか、保存容量を追加します。WAL・pack・鍵を直接削除しないでください。

[回収対象・容量基準・状態表示](features/records.md#容量不足時の自動回収)に詳細をまとめています。`maintenance.enabled` はpackの自動整理の設定であり、容量回収の有効／無効を切り替えるものではありません。

スレッドを手動で一覧から外したい場合は「アーカイブ」を使います。返信を止め、通常の保持期限は変えません。容量不足時の回収条件を満たすと、アーカイブ済みのスレッドも回収される場合があります。[公開停止と物理回収の違い](features/records.md#公開停止と保存データの回収)を確認して操作してください。

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

### 停止中に作成する

サーバーを停止し、本文コピー・検証情報・別保管の鍵束を作成して隔離再生を確認します。以下は絶対パスの例です。保存先の外に、所有者限定の親を用意し、出力先は毎回未作成の名前にします。

```sh
mkdir -p /srv/oimo-backups/copies /srv/oimo-backups/keys /srv/oimo-backups/work
chmod 700 /srv/oimo-backups /srv/oimo-backups/copies /srv/oimo-backups/keys /srv/oimo-backups/work
./bin/oimobbs backup prepare --config config.json \
  --output /srv/oimo-backups/copies/site-001 \
  --keys-output /srv/oimo-backups/keys/site-001 \
  --work-parent /srv/oimo-backups/work
```

本文コピーと鍵束は別の保管領域で管理します。終了コードと `prepare` のJSONで、全工程の成功を確認してください。

### 稼働中に定期作成する

`serve --online-backup-config <path>` で専用設定を指定します。所有者限定JSONで、コピー・鍵・計画・作業・信頼根の配置と資源上限を指定します。形式は [OnlineBackupConfig](../internal/bootstrap/backup_online_config.go) に定義しています。作成の `apply` と期限回収の `reclaim` は独立した明示設定です。

定期オンラインバックアップの容量予約が不足した場合は `deferred_capacity` を記録し、サーバーを継続したまま次の設定周期で再試行します。保存・解放などの別エラーが併記された場合は従来どおり停止します。投稿の空き容量制限も維持します。

### 保管と回収

通常バックアップは各本文の元の保持期限に従います。長期の案件保全は管理画面の保全機能を使います。コピー・鍵束・途中出力・作業領域の回収は署名計画とCLIで行い、手作業でファイルを混ぜません。暗号化と別ホストへの転送は[セキュリティ運用](security-operations.md#暗号化バックアップ)を参照してください。

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

国が重複する回線分類表を保存すると最低reader101を宣言します。同じ範囲の国が異なる場合は不明、日本を含む場合は日本優先として保存・復元します。reader100以前へ戻す際は、更新前のデータと旧イメージの組を使います。

最低reader版を進めたデータへ古いバイナリを接続しません。戻す場合は旧バイナリと対応する復旧データの組を確認し、更新後の投稿を失う範囲を把握してから切り替えます。

### 保存形式の互換性

保存形式のreader版は、そのデータを読み込むために必要な実装の対応版です。起動JSONの `schema_version` や、WALのversionとは別に検査します。

現在のサイトは初期化完了印 `instance.json` のschema 5を使います。投稿原本の重複する文字コード情報と固定・算出可能な時計情報を削除したため、旧schema 1・2・3・4のサイトと旧投稿記録は読み込まず、自動変換もしません。旧データをそのまま新バイナリへ接続せず、旧バイナリと対応する退避データを保持してください。

現在の `serve` は、公開受付前に容量回収に対応する最低reader99を保存します。一度更新したデータはreader98以前のバイナリでは開けません。検証起動の `validation-serve` は、この容量回収の更新を自動では行いません。

切り戻す場合は、旧バイナリに対応する変更前のデータが必要です。停止中の退避データと旧バイナリ・設定を組にして保管してください。

## WAL・snapshotの形式更新

WAL・control snapshotはversion 2の保存形式を使います。既存形式を通常バイナリで読む互換経路はありません。稼働領域の更新では、BBSを正常停止し、全データの退避・一覧・SHA-256と旧imageを確保してから、退避データを別volumeへ復元して変換します。署名対象の正規バイト、DAT、設定、鍵を照合し、新バイナリで投稿データを含む起動検査を終えてからBBSだけを切り替えます。変換用の一時スクリプト・実行物は確認後に削除し、旧データと退避archiveは保持します。

旧形式の退避データには、その形式を読める旧imageを対応させて保管します。新しい稼働領域を読むbackup検証・暗号化helperにも、新形式対応imageを指定してください。公開用のHTTP圧縮や提出用ZIPの形式は保存WALと独立しています。圧縮範囲は[内部設計](architecture.md#ログ関連の圧縮範囲)を参照してください。

## Goと依存関係の更新

`mise`、Python3、Gitとネットワーク接続を用意します。`scripts/update.sh` は隔離したソースのコピーで更新し、既定では差分表示だけを行います。稼働データやサービスには触れません。

| 目的 | コマンド |
| --- | --- |
| 更新候補を通常検証し、差分を確認 | `bash scripts/update.sh` |
| 通常検証した変更をソースへ反映 | `bash scripts/update.sh --apply` |
| 全件試験・race・fuzzも行って反映 | `bash scripts/update.sh --full-checks --apply` |
| Goを指定し、依存はパッチ更新に限定して反映 | `bash scripts/update.sh --go 1.27.3 --modules patch --apply` |
| Goを維持し、外部依存だけを更新して反映 | `bash scripts/update.sh --go current --apply` |
| 検証せずに候補と差分だけを確認 | `bash scripts/update.sh --skip-checks` |

通常検証は、認証の重点試験・静的検査・ビルド・脆弱性検査を行います。全件試験・race・fuzzまで必要な場合は `--full-checks` を選びます。`--skip-checks` と `--apply` は併用できません。

対象Goはmiseが導入します。Goの版はgo.mod、mise、Dockerfile、セットアップ・検査スクリプトと現行の手順書で揃えます。過去の計測fixtureは書き換えません。依存の固定一覧と配布用の著作権表示も更新します。新しいメジャーバージョンへの移行と、Alpine・検査ツール自体の更新は対象外です。

通常は `scripts/check-update.sh` で依存照合、認証・パスキーの重点試験、vet、CGO無効の製品ビルド、脆弱性検査が成功してから反映します。全件試験・race・fuzzは省略します。更新差分がなければ検証も省略します。Goや依存の大きな更新を広く確認する場合は `--full-checks` を指定すると、従来どおり `scripts/check.sh` の全検証を実行します（差分がない場合も実行）。失敗時や、処理中に元の設定が変更された場合は反映しません。依存が選択したGoより新しい版を要求した場合は、表示された版を `--go` に指定してやり直します。確認後の配布ビルドと稼働反映は既存の運用手順で行います。
