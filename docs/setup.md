# Dockerなしのセットアップ

Linuxでサイトを作成し、ローカル起動・HTTPS公開・systemd登録を行う手順です。コマンドはリポジトリのルートで、データを所有する同じOSユーザーから実行します。Dockerを使う場合は[Dockerセットアップ](../deploy/README.md)を参照してください。

この文書の `./bin/oimobbs` は、リポジトリ直下で既定の `config.json` を使う場合のビルド先です。`bin` は必須のフォルダーではなく、ビルドの `-o` で指定している出力先です。ソースコードを取得しただけでは作成されません。`setup.sh` で別の `--config` を指定した場合は、その設定ファイルと同じディレクトリの `bin/oimobbs` に作成します。`--binary` を指定した場合は、その実行ファイルを使います。セットアップ完了時に表示された起動コマンドでも、実際の配置先を確認できます。

## 手順を選ぶ

| 目的 | 手順 |
| --- | --- |
| 自分のPCで試す | [ローカル検証用サイトを作る](#ローカル検証用サイトを作る) |
| 証明書を自動取得・更新する | [証明書の自動セットアップ](#証明書の自動セットアップ) |
| 新しいサイトをHTTPSで公開する | [HTTPSで公開するサイトを作る](#httpsで公開するサイトを作る) |
| 設定と実行ファイルはあるが、サイトは未作成 | [設定ファイルだけある初回導入](#設定ファイルだけある初回導入) |
| 常駐・OS起動時の自動起動を設定する | [systemdへ自動登録](#systemdへ自動登録) |
| 初期化を一工程ずつ進める | [手動でローカル起動](#ローカルで起動する) |
| 作成済みサイトをHTTPSに切り替える | [HTTPSで公開する](#httpsで公開する) |
| 起動後に公開・管理画面を確認する | [起動後の確認](#起動後の確認) |
| 管理画面を掲示板と同じHTTPSで公開する | [管理画面の公開設定](#管理画面を同じポートで公開する) |
| CPU・メモリ・帯域の目安を知る | [帯域別の推奨スペック](#帯域別の推奨スペック) |
| 起動エラーの原因を調べる | [起動できないとき](#起動できないとき) |

## 必要なもの

- Linux、Bash、Go1.27.3、このリポジトリのソースコード
- 確認用のWebブラウザとcurl
- サービス登録には、起動済みのsystemdとsudoを使える一般ユーザー
- HTTPS公開には、公開ドメインと有効なPEM証明書チェーン・秘密鍵。下のスクリプトで取得・自動更新できます

miseを使う場合は先に `mise install` を実行します。スクリプトはGoを直接使うか、mise経由で呼び出します。Pythonは不要です。手動のGoコマンドは `mise exec -- go` に置き換えられます。

## スクリプトでセットアップ

新しいサイトを作るための手順です。ローカル検証とHTTPS公開のどちらか一方を選びます。作成済みサイトの起動には[停止・再開](operations.md#停止再開)を使ってください。

### ローカル検証用サイトを作る

同じPCから試す場合は、HTTPを明示的に許可して8080番で起動します。TLS証明書・sudo・systemd登録は不要です。

```sh
bash scripts/setup.sh --allow-http --url http://127.0.0.1:8080 --start
```

15〜128文字の管理者パスワードを2回入力します。起動後は http://127.0.0.1:8080/operate/ を開きます。管理画面は http://127.0.0.1:8080/admin/ 、ログイン名は `owner` です。

Ctrl+Cで停止します。再開するときは初期化せず、次を実行します。

```sh
./bin/oimobbs validation-serve --config config.json --admin
```

HTTPは同じPCからの検証専用です。外部へ公開する場合は、停止後に[HTTPSへ切り替える手順](#httpsで公開する)へ進みます。

### HTTPSで公開するサイトを作る

HTTPSを既定とし、HTTP待受やHTTPからのリダイレクトは作りません。証明書がなければ、先に[証明書の自動セットアップ](#証明書の自動セットアップ)を実行します。自分で用意した証明書も使えます。ドメインと証明書パスを自分の環境へ置き換えます。

```sh
bash scripts/setup.sh \
  --url https://bbs.example.com \
  --tls-cert /etc/oimobbs/certificates/bbs.example.com/server.pem \
  --tls-key /etc/oimobbs/certificates/bbs.example.com/server.pem \
  --install-service --start
```

管理者パスワードを非表示で2回入力します。[setup.sh](../scripts/setup.sh)が次の順で準備し、HTTPSのサービスを起動します。

1. 入力・既存ファイルを検査し、製品バイナリをビルドする。
2. 設定を保存し、サイトと最初の板を作る。
3. 管理者を登録し、投稿規制と匿名Cookieを有効にする。
4. 保存状態を検査し、指定された方法で起動する。

上の例の公開URLは `https://bbs.example.com/`、管理URLは `https://bbs.example.com/admin/`、管理ログイン名は `owner` です。最初の板は `operate`（運営）です。サービスの停止は `sudo systemctl stop oimobbs.service` です。

作成するファイルと役割は次のとおりです。

| 場所（既定値） | 役割 |
| --- | --- |
| `config.json` | 起動設定。待受・公開URL・保存先など |
| `var/site` | 板・投稿・鍵・管理設定の永続保存先 |
| `bin/oimobbs` | 起動と管理CLIで使う製品バイナリ |
| `/etc/systemd/system/oimobbs.service` | `--install-service` を指定した場合のサービス定義 |

既存の設定・保存先・ビルド出力は上書きしません。`--start` を省略すると初期設定だけを行い、起動コマンドを表示して終了します。作成済みサイトの再開は[停止・再開](operations.md#停止再開)、サービス登録だけを行う場合は[systemdへの登録手順](#systemdへ自動登録)を使います。

### 証明書の自動セットアップ

DockerなしでHTTPSを直接公開するLinux向けです。起動済みのsystemd、sudo、公開ドメインが必要です。OimoBBSを動かす一般ユーザーから実行します。

1. ドメインのAレコードをサーバーの公開IPv4へ設定します。AAAAレコードがある場合はIPv6でも同じサーバーへ到達できるようにします。
2. ルーター・クラウド・OSのファイアウォールでTCP 80と443を許可します。80番は取得後も更新のために到達可能な状態を保ちます。
3. ドメインと連絡用メールアドレスを置き換えて実行します。この実行でLet’s Encryptの利用規約に同意します。

```sh
sudo bash scripts/setup-certificates.sh \
  --domain bbs.example.com \
  --email admin@example.com
```

[setup-certificates.sh](../scripts/setup-certificates.sh)は、Certbotがなければapt-getまたはdnfでCertbotとOpenSSLを導入し、初回証明書を取得します。他のパッケージ管理環境ではCertbotとOpenSSLを先に導入してください。OimoBBSを別のユーザーで動かす場合は `--user oimobbs` を追加します。rootを実行ユーザーには指定できません。

認証はCertbotのstandalone方式でTCP 80を一時的に待ち受けます。80番を使用中のWebサーバーは停止しません。Docker構成の証明書コンテナも含め、80番が使用中なら取得・更新が失敗するため、この手順を併用しないでください。ワイルドカード証明書には対応しません。

| 作成先 | 役割 |
| --- | --- |
| `/etc/oimobbs/certificates/bbs.example.com/server.pem` | 証明書チェーンと秘密鍵をまとめた配信用PEM。実行ユーザー所有・権限600・リンクなし |
| 同じディレクトリの `acme/`・`work/`・`logs/` | このドメイン専用のCertbot管理領域。rootのみアクセス可能 |
| 同じディレクトリの `deploy.sh`・`renew.sh` | 検証・配置と自動更新。rootのみ実行可能 |
| `/etc/systemd/system/oimobbs-cert-bbs.example.com.service`・`.timer` | 毎日0時・12時を基準に最大1時間ずらして更新を確認。OS起動後も継続 |

証明書と鍵の両方に同じ `server.pem` を指定して、[HTTPSのサイト作成](#httpsで公開するサイトを作る)へ進みます。既存サイトでは設定の `public.tls_cert_file` と `public.tls_key_file` をこの絶対パスに変更し、サービスを再起動します。その後の証明書更新は新しいTLS接続で読み込まれるため、OimoBBSの再起動は不要です。

配置前に名前・有効期限・鍵との一致を検査し、完成したPEMだけを差し替えます。更新に失敗した場合は既存の配信用PEMを保持します。同じユーザー・ドメインでの再実行に対応し、一般の既存ディレクトリ・unitや別ユーザーの設定は上書きしません。タイマー登録前に失敗した場合は、原因を直して同じコマンドを再実行してください。

状態と更新試験は次のコマンドで確認します。`--dry-run` はテスト用CAで更新経路を試し、`--run-deploy-hooks` は現在の本番証明書で配置フックを実行します。

```sh
systemctl status oimobbs-cert-bbs.example.com.timer --no-pager
sudo journalctl -u oimobbs-cert-bbs.example.com.service -n 50 --no-pager
sudo certbot renew --dry-run --run-deploy-hooks \
  --config-dir /etc/oimobbs/certificates/bbs.example.com/acme \
  --work-dir /etc/oimobbs/certificates/bbs.example.com/work \
  --logs-dir /etc/oimobbs/certificates/bbs.example.com/logs
```

更新エラーはjournalと上記の `logs/` を確認します。自動通知は設定しないため、定期的に状態・公開証明書の期限を監視してください。専用のCertbot管理領域を使うため、引数なしの `certbot renew` やOS標準のCertbot timerではこの証明書を更新しません。[Certbot公式の更新・フック仕様](https://eff-certbot.readthedocs.io/en/stable/using.html#renewing-certificates)も参照してください。

自動更新だけを止める場合は次を実行します。証明書を使用している間はファイルを削除しないでください。

```sh
sudo systemctl disable --now oimobbs-cert-bbs.example.com.timer
```

### サービス登録せずにHTTPSで起動する

秘密鍵は実行ユーザー所有の通常ファイル、権限600にしてください。手動起動する場合は、先に `--start` なしで準備します。

```sh
bash scripts/setup.sh \
  --url https://bbs.example.com \
  --tls-cert ./tls/fullchain.pem \
  --tls-key ./tls/privkey.pem
sudo setcap cap_net_bind_service=+ep ./bin/oimobbs
./bin/oimobbs serve --config config.json
```

HTTPSの既定待受は `0.0.0.0:443` です。URLで別ポートを指定した場合はそのポートを使い、`--listen` で待受を個別に変更できます。証明書の取得・更新には[自動セットアップ](#証明書の自動セットアップ)を使えます。ポートの到達性は別途設定してください。

一般ユーザーによる標準ポートの待受には権限が必要です。自動登録するsystemdサービスは `CAP_NET_BIND_SERVICE` だけを付与します。[systemdの権限設定](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#Capabilities)を使うため、バイナリへのsetcapは不要です。

手動起動の例ではsetcapでバイナリへ待受権限を付与します。setcapはlibcapのコマンドです。バイナリを入れ替えた場合は再付与してください。1024以上のポートを明示する場合は、通常この権限は不要です。

### オプション

| オプション | 用途・既定値 |
| --- | --- |
| `--config` | 新規設定ファイル。既定 `config.json` |
| `--data-dir` | 設定ファイル基準の新規保存先。既定 `var/site` |
| `--url`、`--listen` | 公開URLと待受。URLの既定 `https://localhost`、HTTPSは既定443。実ドメインと証明書を指定 |
| `--allow-http` | loopback限定のHTTP検証を明示的に許可。HTTPは既定80 |
| `--name`、`--board-key`、`--board-name` | サイト名と最初の板。既定 `OimoBBS`・`operate`・`運営` |
| `--login` | 管理ログイン名。既定 `owner` |
| `--tls-cert`、`--tls-key` | HTTPSの証明書チェーンと秘密鍵。指定時の作業ディレクトリ基準 |
| `--binary` | 既存の製品バイナリを使用。製品のビルドを省略 |
| `--start` | 準備後に起動 |
| `--install-service` | systemdへ新規登録し、自動起動を有効化 |
| `--service-only` | 作成済みサイトのサービス登録のみ。初期化・パスワード入力なし |
| `--password-stdin` | 非対話実行でパスワード1行を標準入力から受け取る |
| `--public-admin=false`、`--admin-port` | 旧方式のloopback別待受を使用。管理ポートの既定 `9081` |

設定JSONは権限600で作成します。管理パスワードを引数・設定へ保存しません。`--binary` や `--service-only` でもセットアップ処理用のGoは必要です。準備済みバイナリだけを起動する場合はGo不要です。

### systemdへ自動登録

HTTPSのサービス登録には、[HTTPSのセットアップ例](#httpsで公開するサイトを作る)を使います。HTTPのローカル検証をサービスにする場合だけ、明示的に許可します。

```sh
sudo bash scripts/setup.sh --allow-http --url http://127.0.0.1 --install-service --start
```

HTTPS公開では `--allow-http` を指定しません。最初にsudoを付けず一般ユーザーから実行しても、登録時にsudoを呼び出します。ビルド・初期化・サービス実行は元の一般ユーザーで行い、rootだけでのサービス登録は受け付けません。

| 指定 | 実行すること |
| --- | --- |
| `--install-service` | 初期設定、サービス登録、自動起動の有効化 |
| `--install-service --start` | 上記に加え、その場でサービスを起動 |
| `--service-only --start` | 作成済みサイトを登録し、その場で起動 |

作成済みサイトは手動起動を止めてから登録します。HTTP設定を登録する場合も `--allow-http` が必要です。

```sh
bash scripts/setup.sh --service-only --config ./config.json --start
```

製品バイナリは設定ファイルと同じディレクトリの `bin/oimobbs` を使います。別配置なら `--binary` を指定します。登録先は `/etc/systemd/system/oimobbs.service` です。同名サービス・既存unitは上書きしません。

設定・データ・証明書・バイナリは現在の場所を使います。登録後も移動・削除せず、実行ユーザーの読取り・書込み権限を維持してください。専用ユーザーで運用する場合は、そのユーザーで最初から準備します。

サービスは異常終了時に5秒後の再起動を行い、ログをjournalへ出力します。状態確認・停止・再開・登録解除は[運用手順](operations.md#停止再開)を参照してください。

### 登録に失敗した場合

sudo・systemd・既存サービスの確認に失敗した場合は、初期化を始めません。初期化後に登録が失敗しても、作成済みの設定・データは保持します。

| 失敗した段階 | 続け方 |
| --- | --- |
| 設定・データの初期化途中 | エラーを解消し、手動手順の未完了工程から続ける |
| 初期化完了後、unit保存前 | `--service-only` で登録を再試行 |
| unit保存後 | unitの内容を確認し、以下のコマンドで登録・起動を再開 |

```sh
sudo systemctl daemon-reload
sudo systemctl enable oimobbs.service
sudo systemctl start oimobbs.service
```

## 起動後の確認

HTTPSセットアップ例での接続先です。実際のドメインと板キーへ置き換えます。

| 画面 | URL |
| --- | --- |
| 公開トップ | https://bbs.example.com/ |
| 運営板 | https://bbs.example.com/operate/ |
| 管理画面 | https://bbs.example.com/admin/ |
| 専ブラ登録用の板メニュー | https://bbs.example.com/bbsmenu.json |

```sh
curl --fail https://bbs.example.com/bbsmenu.json
curl --fail https://bbs.example.com/operate/subject.txt
./bin/oimobbs healthcheck --config config.json
```

次の順に確認します。ローカル検証ではURLを `http://127.0.0.1:8080` に置き換えます。

1. 公開トップと運営板を開く。
2. 管理画面へ `owner` でログインする。
3. 運営板でスレッドを作成し、返信する。
4. `subject.txt` にスレッドが掲載されることを確認する。投稿前は空です。
5. [停止・再開](operations.md#停止再開)を行い、投稿が残ることを確認する。

回線分類は初回起動時に自動取得します。「回線分類」画面で取得状況を確認できます。対象と判定条件は[回線カタログ](networks.md)を参照してください。

## ローカルで起動する

HTTPを明示的に使う、loopback限定の手動検証手順です。標準HTTPポート80で待ち受けます。スクリプトで作成済みなら、この初期化を繰り返す必要はありません。

### 1. バイナリを作る

```sh
go version
mkdir -p bin
CGO_ENABLED=0 go build -trimpath -o bin/oimobbs ./cmd/oimobbs
```

### 2. 自分用の設定ファイルを作る

既存の `config.json` がある場合は、その設定を使います。

```sh
cp -n config.local.example.json config.json
chmod 600 config.json
mkdir -p var
```

設定例の保存先は `./var/site` です。パスは設定ファイルの場所を基準にします。`var/site` は次の `init` が作成するため、ここでは親の `var` だけを用意します。設定項目の形式は[設定一覧](configuration.md)を参照してください。

### 3. サイトと最初の板を作る

```sh
./bin/oimobbs init --config config.json --name 'OimoBBS'
./bin/oimobbs board create --validation --config config.json --key operate --name '運営'
./bin/oimobbs board list --validation --config config.json
```

板一覧に `operate` が表示されれば作成済みです。既に初期化した保存先では `init` を省略します。

### 4. 管理者を登録する

15〜128文字のパスワードを入力します。入力中の文字は画面に表示されません。

```bash
read -r -s -p '管理者パスワード: ' oimo_admin_secret
printf '\n'
printf '%s\n' "$oimo_admin_secret" | ./bin/oimobbs admin init \
  --config config.json --login owner --password-stdin
unset oimo_admin_secret
```

ログイン名は `owner` です。登録済みの管理者がいる場合はこの手順を省略します。

### 5. 投稿規制と匿名Cookieを有効にする

```sh
./bin/oimobbs admission enable --config config.json
./bin/oimobbs anonymous enable --config config.json --mode required
```

投稿規制、匿名Cookieの順で有効にします。

### 6. 起動する

標準ポートの待受権限をバイナリへ付与してから、一般ユーザーで起動します。HTTPの接続先は `http://127.0.0.1/`、管理画面は `http://127.0.0.1/admin/` です。

```sh
sudo setcap cap_net_bind_service=+ep ./bin/oimobbs
./bin/oimobbs validation-serve --config config.json --admin
```

起動後は[公開・管理・保存の確認](#起動後の確認)にあるURLを `http://127.0.0.1` へ置き換えて検査します。Ctrl+Cで停止し、再開時は同じ起動コマンドを使います。

## 設定ファイルだけある初回導入

`config.json` と実行ファイルを用意済みで、まだサイトを作成していない場合の手順です。`serve` はサイトを自動作成しません。`data_dir` が `./var/site` なら、未作成の状態で起動すると `lstat .../var/site: no such file or directory` になります。

以下はリポジトリ直下で実行します。既存の `config.json` は維持します。実行ファイルが未作成なら、先に[ビルド手順](#1-バイナリを作る)を実行してください。既にサイトを作成した場合や、既存データを移す場合には、この初期化を実行しません。

### サイト・板・管理者を作成する

保存先が `./var/site` の例です。親の `var` だけを作り、`var/site` 自体は `init` に作成させます。`data_dir` が別の場所なら、その親ディレクトリを用意してください。

```sh
mkdir -p var
./bin/oimobbs init --config config.json --name 'OimoBBS'
./bin/oimobbs board create --validation --config config.json --key operate --name '運営'
```

次に15〜128文字の管理者パスワードを入力します。入力中の文字は表示されません。ログイン名は `owner` です。

```bash
read -r -s -p '管理者パスワード: ' oimo_admin_secret
printf '\n'
printf '%s\n' "$oimo_admin_secret" | ./bin/oimobbs admin init \
  --config config.json --login owner --password-stdin
unset oimo_admin_secret
```

投稿規制と匿名Cookieを有効にし、最初の板を確認します。

```sh
./bin/oimobbs admission enable --config config.json
./bin/oimobbs anonymous enable --config config.json --mode required
./bin/oimobbs board list --validation --config config.json
```

### 初回の公開起動

`config.json` の公開URL・管理URL・TLS証明書を[HTTPS公開の設定](#2-サーバーを止めて設定を変更する)に合わせて準備済みなら、手動起動は次の順です。setcapは実行ファイルへ443番の待受権限を付与します。

```sh
sudo setcap cap_net_bind_service=+ep ./bin/oimobbs
```

```sh
./bin/oimobbs serve --config config.json
```

管理画面は公開URLの `/admin/` です。[起動後の確認](#起動後の確認)を行います。systemdで運用する場合は手動起動・setcapを省略し、[サービス登録](#systemdへ自動登録)へ進みます。次回以降は初期化を繰り返さず、起動だけを行います。

## HTTPSで公開する

作成済みのローカルサイトをHTTPSへ切り替える手順です。新規サイトは[HTTPSのセットアップ例](#httpsで公開するサイトを作る)、設定と実行ファイルだけ準備済みなら[初回導入の続き](#設定ファイルだけある初回導入)を使います。

### 1. 公開先と証明書を用意する

公開ドメインのDNSをサーバーへ向け、必要なポートの到達性を用意します。以下は `https://bbs.example.com` の例です。証明書チェーンと秘密鍵をPEM形式で配置し、実行ユーザーが読める状態にします。秘密鍵は同じユーザー所有、権限600にしてください。

### 2. サーバーを止めて設定を変更する

手動起動はCtrl+C、サービス起動は `sudo systemctl stop oimobbs.service` で停止します。既存の `config.json` の `public` を次の値へ変更します。他の項目は維持してください。

```json
{
  "listen": "0.0.0.0:443",
  "base_url": "https://bbs.example.com",
  "tls_cert_file": "./tls/fullchain.pem",
  "tls_key_file": "./tls/privkey.pem"
}
```

これは設定全体ではなく `public` の値です。証明書パスは設定ファイル基準です。`base_url` の末尾に `/` は付けません。`admin.origin` も `https://bbs.example.com/admin/` に揃えます。

標準HTTPSポート443を直接使うため、8443へのポート転送は不要です。HTTPの待受は追加しません。

### 3. 公開用コマンドで起動する

まず実行ファイルの配置先を確認します。以下は、リポジトリ直下（`go.mod` のあるディレクトリ）に移動し、既存の `config.json` を使う場合の例です。

```sh
pwd
ls -l ./bin/oimobbs
```

`No such file or directory` なら、まだビルドしていないか、別の場所へ配置しています。`--binary` を指定した場合やsystemdへ登録済みの場合は、既存の実行ファイルの場所を使ってください。既定の場所へまだ作成していない場合は、リポジトリ直下で次を実行します。

```sh
mkdir -p bin
CGO_ENABLED=0 go build -trimpath -o ./bin/oimobbs ./cmd/oimobbs
```

miseでGoを用意している場合は、ビルドの `go build` を `mise exec -- go build` に置き換えます。この操作は実行ファイルを作るだけです。既存の設定・保存データは使い続け、`init`・板作成・管理者登録は繰り返しません。

**手動で起動する場合**は、ビルド成功後に443番の待受権限を付与します。setcapはlibcapのコマンドです。実行ファイルを別の場所へ配置した場合は、以降の `./bin/oimobbs` をそのパスに置き換えてください。

```sh
sudo setcap cap_net_bind_service=+ep ./bin/oimobbs
```

その後、別のコマンドとして起動します。

```sh
./bin/oimobbs serve --config config.json
```

`serve` は作成済みサイトを起動します。同じ待受の管理画面も起動するため `--admin` は不要です。

**systemdで運用する場合**は、上の手動起動・setcapは不要です。登録済みのサービスでは、実際のバイナリ・設定のパスを次で確認できます。

```sh
systemctl show oimobbs.service --property=ExecStart --no-pager
```

HTTPで登録したsystemdサービスは、設定JSONだけを変更しても起動コマンドが `validation-serve` のままです。`sudo systemctl edit --full oimobbs.service` で `ExecStart` のサブコマンドを `serve` に変更し、末尾の `--admin` を外します。バイナリ・設定の絶対パス、User、Groupは維持してください。

### 4. 自動起動を設定する

systemdへ未登録なら、手動起動を止めて登録します。

```sh
bash scripts/setup.sh --service-only --config ./config.json --start
```

既に登録済みでunitを変更した場合は、次で反映します。

```sh
sudo systemctl daemon-reload
sudo systemctl start oimobbs.service
```

公開URLで[起動後の確認](#起動後の確認)を行います。サービスの起動成功に加え、HTTPS接続、管理ログイン、投稿・返信と再起動後の保存を確認してください。

## 管理画面を同じポートで公開する

通常の管理画面は、掲示板と同じHTTPS待受の `/admin/` です。セットアップスクリプトと[設定例](../config.admin-public.example.json)はこの方式を使います。

```json
{
  "listen": "",
  "transport": "public_path",
  "origin": "https://bbs.example.com/admin/"
}
```

これは `admin` の値です。公開URLとscheme・ホスト・ポートを一致させます。`public_path` では `admin.listen` は空文字で、管理用ポートを開きません。`admin` は予約パスのため板キーには使えません。

公開入口（edge）を使う場合は、入口の `oimoedge serve --admin-path` に同じ管理パスを末尾の `/` なしで指定します。[公開入口の構成](security-operations.md#公開入口と管理接続)を参照してください。

設定の `admin.origin` へ直接接続し、登録した管理者でログインします。管理URLへのリンクは公開ページへ掲載しません。接続元の制限は「管理画面のアクセス」で設定します。自己締め出し時の解除は[運用手順](operations.md#管理画面のアクセス制限を解除する)、認証条件は[管理認証・権限・CAP](features/administration.md)を参照してください。

証明書更新後は、新しいTLS接続で更新後のファイルを読みます。証明書と鍵を整合する状態で置き換え、実行ユーザーの読取り権限を維持してください。

## 帯域別の推奨スペック

OimoBBSを1台で専用運用する場合の、運用開始時の構成目安です。OS・HTTPS・バックアップの余裕を含みます。他のアプリを同居させる場合は、その使用分を別に加算してください。

| 上り帯域 | CPUの目安 | メモリの目安 | SSDの開始目安 |
| --- | --- | --- | --- |
| 100〜1000Mbps | 2vCPU以上 | 4GiB以上 | 100GB以上 |

この目安は過去の2CPU・1GiBのアプリ枠での合成試験を参考にしています。最小要件や、各帯域を常時使い切れる保証ではありません。必要資源は本文サイズ、圧縮、キャッシュ、同時接続、投稿量、保存期間、ディスクの同期書込み遅延で変わります。SSDは原本・ログ・バックアップ・一時退避の容量を積み上げて選びます。

現行ComposeのBBSは、上限を省略するとホスト資源へ追従します。上限を設ける場合は `OIMO_CPUS` と `OIMO_MEMORY` を指定し、コンテナを再作成します。CPU・メモリへの追従方法と、手動設定が上限になる条件は[CPU・メモリ・帯域の管理](features/resources.md)を参照してください。

`egress_budget_bits_per_second` はアプリ側の送信予算です。設定例は80Mbps、同梱のDocker用設定は100Mbpsです。設定を増やしても実回線の速度は増えません。自分の環境で[負荷試験](testing/performance.md#帯域ごとの構成確認)を行い、投稿遅延・CPU・メモリ・欠測を併せて確認してください。過去の条件と全試行は[測定資料一覧](testing/measurements.md)から参照できます。

## 起動できないとき

| 症状 | 対応 |
| --- | --- |
| Goのバージョンが違う | Go1.27.3を用意。mise利用時は `mise exec -- go` で実行 |
| setcapで `No such file or directory` | 実行ファイルが指定先にありません。[配置先の確認とビルド](#3-公開用コマンドで起動する)を行い、存在するファイルへsetcapを実行 |
| `serve` で `lstat .../var/site: no such file or directory` | 初回でサイト未作成なら[初期化手順](#設定ファイルだけある初回導入)を実行。既存サイトなら `config.json` の `data_dir` とデータの配置先を確認 |
| サービス登録に失敗 | 初期化前なら原因を解消して再実行。初期化後は[登録失敗時の対応](#登録に失敗した場合)を確認 |
| 保存先が既にある | 初期化済みなら `init` を省略。不完全な初期化は内容を調べてから復旧 |
| ロック・所有者・権限のエラー | 同じ保存先のサーバーを停止し、初期化時と同じOSユーザーで実行 |
| ポートが使用中 | 公開待受ポートの使用を確認。設定の待受とURLを揃える |
| 管理画面へログインできない | 設定した管理URL、ログイン名、パスワードを確認。再設定は[運用手順](operations.md)へ |
| Cookieの設定エラー | `admission enable` が先。`anonymous enable` には `--mode required` を指定 |
| JSONエラー | 設定例と比較。必須項目の欠落・重複・未知項目・型違いは拒否 |
| 標準ポートで permission denied | systemd登録の権限設定、または手動起動時のsetcapを確認 |
| 公開起動でHTTPSエラー | 公開URL、証明書名・期限・秘密鍵・読取り権限を確認 |
| 投稿済みデータの `check` が失敗 | 停止後に `board list --validation` で投稿・署名を含めて照合 |

閲覧制限、パスワード再設定、バックアップは[運用手順](operations.md)を参照してください。
