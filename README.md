# OimoBBS

Goで動く匿名掲示板です。Webブラウザと専用ブラウザから閲覧・投稿でき、板・スレッド・投稿・管理設定を永続保存します。一般利用者のログインは不要です。

## はじめる

Linux、Bash、Go1.27.3とソースコードを用意し、リポジトリのルートで実行します。miseを使う場合は先に `mise install` を実行してください。

| 目的 | 最初に読む手順 |
| --- | --- |
| 自分のPCで動きを試す | 下の「ローカルで試す」 |
| サーバーでHTTPS公開する | [HTTPSのセットアップ](docs/setup.md#httpsで公開するサイトを作る) |
| Dockerで起動する | [Dockerセットアップ](deploy/README.md) |
| 作成済みのサイトを再開・更新する | [運用手順](docs/operations.md) |

### ローカルで試す

新しいサイトを作り、同じPCからアクセスする例です。証明書やsystemd登録は不要です。

```sh
bash scripts/setup.sh --allow-http --url http://127.0.0.1:8080 --start
```

15〜128文字の管理者パスワードを2回入力すると、ビルド・初期設定・起動まで進みます。

| 確認するもの | 接続先・操作 |
| --- | --- |
| 公開トップ | http://127.0.0.1:8080/ |
| 最初の板（運営板） | http://127.0.0.1:8080/operate/ |
| 管理画面 | http://127.0.0.1:8080/admin/ （ログイン名 `owner`） |
| 停止 | 起動したターミナルでCtrl+C |
| 再開 | `./bin/oimobbs validation-serve --config config.json --admin` |

設定は `config.json`、データは `var/site`、バイナリは `bin/oimobbs` に作成します。このセットアップは新規作成用です。作成済みサイトは表の再開コマンドを使います。

### HTTPSで公開する

公開ドメインを用意し、[証明書の自動取得・更新](docs/setup.md#証明書の自動セットアップ)を設定してから、[HTTPSのセットアップ](docs/setup.md#httpsで公開するサイトを作る)へ進みます。初期設定とsystemdへの登録をまとめて行えます。公開サイトの管理画面も同じHTTPSの `/admin/` を使います。

## 使い方と仕様

| 知りたいこと | 文書 |
| --- | --- |
| 閲覧・書き込み・削除依頼・回答の確認 | [掲示板の使い方](docs/user-guide.md) |
| 管理画面の使い方・操作記録の検索 | [管理画面ガイド](docs/admin-guide.md) |
| 日常管理・停止・更新・バックアップ・復旧 | [運用手順](docs/operations.md) |
| 投稿ログの取得・CSV列・署名ZIP | [提出用ログの取得](docs/admin-guide.md#提出用ログを取得する)・[提出ファイルの仕様](docs/features/records.md#提出用ファイル) |
| スレッドのアーカイブ・削除・保存容量の回収 | [記録・削除・保持期限](docs/features/records.md) |
| 設定場所・初期値・反映時点 | [設定一覧](docs/configuration.md) |
| 管理者のロール・担当板・追加権限 | [管理者の権限](docs/admin-permissions.md) |
| 投稿・閲覧・規制・記録の仕組み | [仕様の全体像](docs/specification.md) |
| CPU・メモリへの自動追従、圧縮・JSONの仕組み | [資源管理](docs/features/resources.md)・[符号化・圧縮・並列処理](docs/encoding.md) |
| HTTP要求の追加検査・大量アクセス制限 | [WAF](docs/waf.md) |

[文書一覧](docs/README.md)にすべての手順と仕様をまとめています。管理画面の「マニュアル」でも、画面に沿った操作手順を確認できます。

## 開発時の検証

```sh
mise install
mise exec -- bash scripts/check.sh
```

Python3とネットワーク接続が必要です。対象を絞った検査と確認範囲は[検証方法](docs/testing/README.md)を参照してください。

## 同梱データと依存のライセンス

[文字変換表](third_party/whatwg/README.md)・[Go由来の定数表](third_party/go/LICENSE)・[Argon2id](third_party/argon2/README.md)・[Go moduleの著作権表示](third_party/go-modules/NOTICES.txt)を参照してください。
