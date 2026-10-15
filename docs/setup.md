# Dockerなしのセットアップ

Linuxでの初回起動とHTTPS公開の手順です。コマンドはリポジトリのルートで、データを所有する同じOSユーザーから実行します。

## 必要なもの

- Linux、Go1.27.2、このリポジトリのソースコード
- Webブラウザ、curl
- 以下のパスワード入力に使うbash

miseを使う場合は `mise install` を実行し、`go` を `mise exec -- go` に置き換えます。ビルド済みバイナリの実行にGoは不要です。

## スクリプトでセットアップ

[setup.sh](../scripts/setup.sh) は設定生成・ビルド・サイトと板の作成・管理者登録・規制とCookieの有効化を行います。BashとGo1.27.2が必要で、Pythonは不要です。管理パスワードは非表示で2回入力します。

ローカルで起動する場合：

```sh
bash scripts/setup.sh --start
```

HTTPSで起動する場合は、有効なPEM証明書チェーンと秘密鍵を先に用意します。秘密鍵は実行ユーザー所有の通常ファイル、権限600にしてください。

```sh
bash scripts/setup.sh \
  --config https-config.json \
  --url https://bbs.example.com:8443 \
  --tls-cert ./tls/fullchain.pem \
  --tls-key ./tls/privkey.pem \
  --start
```

ドメインと証明書パスは自分の環境へ置き換えます。HTTPSの待受は既定 `0.0.0.0:8443` です。URLを標準443にする場合は外部443を8443へ転送します。証明書の取得・更新は別途設定してください。

| オプション | 用途 |
| --- | --- |
| `--config` | 新規設定ファイル。既定 `config.json` |
| `--data-dir` | 設定ファイルの場所を基準にした新規保存先。既定 `var/site` |
| `--url`、`--listen` | 公開Originと待受。HTTPはURLと同じアドレス・ポートで待受 |
| `--name`、`--board-key`、`--board-name` | サイト名・最初の板。既定はOimoBBS・news・ニュース |
| `--login` | 管理ログイン名。既定 `owner` |
| `--admin-port` | 旧方式 `--public-admin=false` の別待受ポート |
| `--public-admin` | 公開と同じ待受で管理。既定trueでランダムな管理パスを生成 |
| `--binary` | 指定した既存バイナリを使い、製品のビルドを省略。セットアップ処理用のGoは必要 |
| `--password-stdin` | 非対話実行でパスワード1行を標準入力から受け取る |
| `--start` | 準備後に起動。省略すると起動コマンドを表示して終了 |

新規サイト専用です。既存の設定・保存先・ビルド出力へ上書きせず、失敗時も作成済みの設定・データを保持します。途中で失敗した場合はエラーを解決し、以下の手動手順で未完了の工程から続けてください。既存バイナリを使う場合は `--binary ./bin/oimobbs` を指定します。

設定JSONは権限600で作成し、パスワードは設定や引数へ保存しません。管理URLは設定の `admin.origin` とセットアップ完了時の表示で確認します。管理用の別ポートは開きません。自動起動は[systemdの手順](#5-自動起動を設定する)を使います。

## ローカルで起動する

### 1. バイナリを作る

```sh
go version
mkdir -p bin
CGO_ENABLED=0 go build -trimpath -o bin/oimobbs ./cmd/oimobbs
```

### 2. 自分用の設定ファイルを作る

既存の `config.json` がある場合は、その設定を使います。

```sh
cp -n config.example.json config.json
chmod 600 config.json
mkdir -p var
```

設定例の保存先は `./var/site` です。パスは設定ファイルの場所を基準にします。`var/site` は次の `init` が作成するため、ここでは親の `var` だけを用意します。設定項目の形式は[設定一覧](configuration.md)を参照してください。

### 3. サイトと最初の板を作る

```sh
./bin/oimobbs init --config config.json --name 'OimoBBS'
./bin/oimobbs board create --validation --config config.json --key news --name 'ニュース'
./bin/oimobbs board list --validation --config config.json
```

板一覧に `news` が表示されれば作成済みです。既に初期化した保存先では `init` を省略します。

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

```sh
./bin/oimobbs validation-serve --config config.json --admin
```

ターミナルを開いたまま、ブラウザで次のURLへ接続します。

| 画面 | URL |
| --- | --- |
| 公開トップ | http://127.0.0.1:9080/ |
| ニュース板 | http://127.0.0.1:9080/news/ |
| 管理画面 | 設定の `admin.origin`（公開トップと同じ9080） |
| 専ブラ登録用の板メニュー | http://127.0.0.1:9080/bbsmenu.json |

管理画面は `owner` と登録したパスワードでログインします。設定と一致する `127.0.0.1` のURLを使ってください。

回線分類は初回起動時に自動取得します。取得状況は管理画面の「回線分類」、対象は[回線カタログ](networks.md)で確認できます。

別のターミナルで疎通を確認します。

```sh
curl --fail http://127.0.0.1:9080/bbsmenu.json
curl --fail http://127.0.0.1:9080/news/subject.txt
./bin/oimobbs healthcheck --config config.json
```

ニュース板でスレッドを作り、確認画面から投稿します。返信も確認し、`subject.txt` にスレッドが表示されることを確かめます。投稿前の `subject.txt` は空です。

Ctrl+Cで停止します。再開は同じ起動コマンドを実行します。板・投稿・設定は保存され、以降のHTTPS公開でも引き継ぎます。試験データを分ける場合は別の設定と `data_dir` を使ってください。

## HTTPSで公開する

### 1. 公開先と証明書を用意する

公開ドメインのDNSをサーバーへ向け、必要なポートの到達性を用意します。ここでは `https://bbs.example.com:8443` で公開する例を示します。`bbs.example.com` は自分のドメインへ置き換えてください。

有効な証明書チェーンと秘密鍵をPEM形式で用意し、実行ユーザーが読める場所へ置きます。取得・定期更新は証明書管理ツールで設定します。

### 2. 起動設定をHTTPSへ変更する

ローカルサーバーをCtrl+Cで停止します。`config.json` の `public` を次の内容へ変更し、`admin.origin` のscheme・ドメイン・ポートも同じ公開URLへ揃えます。管理パスと他の保存設定は維持します。

```json
{
  "listen": "0.0.0.0:8443",
  "base_url": "https://bbs.example.com:8443",
  "tls_cert_file": "./tls/fullchain.pem",
  "tls_key_file": "./tls/privkey.pem"
}
```

上記は `public` の値です。証明書パスは設定ファイルの場所が基準です。`base_url` の末尾に `/` は付けません。

標準ポートで公開する場合は外部TCP 443を8443へ転送し、`base_url` の `:8443` を外します。管理画面も同じ443を使います。

### 3. 公開用コマンドで起動する

ローカル手順のサイト・板・管理者・規制・Cookie設定をそのまま使います。新しいサーバーの場合は先にローカル手順の1〜5を済ませてください。

```sh
./bin/oimobbs serve --config config.json
```

`serve` は登録済みサイトと同じ待受の管理画面を公開します。`--admin` は不要です。

公開トップ、板メニュー、投稿・返信を確認し、再起動後にも投稿が残ることを確かめます。

### 4. 遠隔から管理する

ブラウザで設定の `admin.origin` を直接開き、管理者パスワードでログインします。掲示板と同じHTTPSポートを使い、管理用のポート転送は不要です。

管理画面の「管理画面のアクセス制限」で、許可CIDRを `127.0.0.1/32` にすると127.0.0.1以外を拒否できます。IPv6のlocalhostも使う場合は `::1/128` を追加します。制限をONにして保存してください。現在の接続元を拒否する保存は422で防ぎます。画面に表示される接続元IPを基準に指定します。

公開入口を使う場合も、mTLSで認証した入口が実接続から確定した利用者IPで判定します。Dockerのホストから接続した場合はgatewayのIPに見えることがあります。URLに127.0.0.1を使っても、サーバーが観測する接続元が127.0.0.1になるとは限りません。

### 5. 自動起動を設定する

専用OSユーザー `oimobbs` と配置先 `/srv/oimobbs` を用意し、同じユーザーで初期化します。バイナリ・設定・データ・証明書を配置し、次を `/etc/systemd/system/oimobbs.service` に保存します。

```ini
[Unit]
Description=OimoBBS
After=network.target

[Service]
Type=simple
User=oimobbs
Group=oimobbs
WorkingDirectory=/srv/oimobbs
ExecStart=/srv/oimobbs/bin/oimobbs serve --config /srv/oimobbs/config.json
Restart=on-failure
RestartSec=5
TimeoutStopSec=35
UMask=0077
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

手動起動を止めてから登録します。

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now oimobbs
sudo systemctl status oimobbs
sudo journalctl -u oimobbs -n 50 --no-pager
```

停止・再開は `sudo systemctl stop oimobbs`、`sudo systemctl start oimobbs` です。証明書を更新すると、アプリは新しいTLS接続で更新後のファイルを読みます。証明書と鍵を整合する状態で置き換え、実行ユーザーの読取り権限を維持してください。

## 管理画面を同じポートで公開する

通常の管理接続は、掲示板と同じHTTPS待受の管理パスです。設定例は [config.admin-public.example.json](../config.admin-public.example.json) です。直結HTTPSと認証済み公開入口（edge）の両方に対応します。セットアップスクリプトでは既定でこの方式を生成します。

公開用の証明書・鍵と管理者パスワードを設定した後、サーバーを停止し、`admin` を次のように設定します。管理パスは通常 `/admin/` を使います。

```json
{
  "listen": "",
  "transport": "public_path",
  "origin": "https://bbs.example.com:8443/admin/"
}
```

`origin` のscheme・ドメイン・ポートを `public.base_url` と一致させます。`admin` は予約済みのパスで、板キーには使えません。管理画面はパスワード認証と接続制限で保護します。

`public_path` では `admin.listen` は空文字にし、管理用ポートを開きません。edgeを使う場合は、公開入口の `oimoedge serve --admin-path` に同じ管理パス（末尾の `/` なし）を設定します。設定後に起動します。

```sh
./bin/oimobbs serve --config config.json
```

設定したURLを直接開き、管理者パスワードでログインします。公開ページへの管理リンクは掲載しません。認証・クローラー制限の詳細は[確定仕様](specification.md#管理者とcap)を参照してください。

## 起動できないとき

| 症状 | 対応 |
| --- | --- |
| Goのバージョンが違う | Go1.27.2を用意。mise利用時は `mise exec -- go` で実行 |
| 保存先が既にある | 初期化済みなら `init` を省略。不完全な初期化は内容を調べてから復旧 |
| ロック・所有者・権限のエラー | 同じ保存先のサーバーを停止し、初期化時と同じOSユーザーで実行 |
| ポートが使用中 | 公開待受ポートの使用を確認。設定の待受とURLを揃える |
| 管理画面へログインできない | 設定した管理URL、ログイン名、パスワードを確認。再設定は[運用手順](operations.md)へ |
| Cookieの設定エラー | `admission enable` が先。`anonymous enable` には `--mode required` を指定 |
| JSONエラー | 設定例と比較。項目の省略・重複・未知項目・型違いは拒否 |
| 公開起動でHTTPSエラー | 公開URL、証明書名・期限・秘密鍵・読取り権限を確認 |
| 投稿済みデータの `check` が失敗 | 停止後に `board list --validation` で投稿・署名を含めて照合 |

閲覧制限、パスワード再設定、バックアップは[運用手順](operations.md)を参照してください。
