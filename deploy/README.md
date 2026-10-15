# Dockerセットアップ

Docker EngineとComposeを使い、リポジトリのルートで実行します。同梱Composeは `patatanmc.f5.si` 向けの永続型検証構成です。Dockerなしの起動は[セットアップ](../docs/setup.md)を参照してください。

## 設定を確認する

- [deploy/config.json](config.json)：公開URL、TLS、保存先、資源、自動整理。
- [compose.yaml](../compose.yaml)：BBS、証明書取得、volume。
- [compose.admin.yaml](../compose.admin.yaml)：同じ公開待受で管理画面を有効にする上書き設定。
- [certificates.sh](certificates.sh)：証明書の取得・更新。

自分のドメインに合わせ、`deploy/config.json` の公開URLと `certificates.sh` のドメイン・cert-name・証明書ディレクトリを変更します。新規の直結HTTPS構成では `edge` と `auto_reports` を `null`、`trusted_proxies` を `[]` にします。

DNSをサーバーへ向け、TCP 80・443の到達性を用意します。80は証明書取得用、443はアプリの直結HTTPSです。証明書はDocker volumeへ保存し、ホストの証明書を自動流用しません。

## 既存の稼働環境を扱う場合

既存サイトは `.env` の `COMPOSE_FILE` とvolume指定を維持します。[compose.slip.yaml](../compose.slip.yaml) は外部データvolume・使用イメージ・公開入口を指定する上書き設定です。

公開入口のmTLS・証明書・バックアップ設定は[セキュリティ運用](../docs/security.md)を参照してください。

```sh
docker compose ps
docker compose stop
docker compose up -d
```

以下の新規用 `-f` 指定へ置き換えると保存先が変わる場合があります。既存サイトのCLI・更新も、現在のCompose指定で実行してください。

更新の順序は[更新](#更新)を参照してください。

## 新規環境での初回起動

以下は新規環境用のCompose指定です。

```sh
docker compose -f compose.yaml up -d certificates
docker compose -f compose.yaml ps
docker compose -f compose.yaml logs --tail=50 certificates
```

証明書取得後、BBSを起動する前にサイトと検証板 `oimo` を登録します。

```sh
docker compose -f compose.yaml build bbs
docker compose -f compose.yaml run --rm --no-deps bbs init --config /etc/oimobbs/config.json --name OimoBBS
docker compose -f compose.yaml run --rm --no-deps bbs board create --validation --config /etc/oimobbs/config.json --key oimo --name 検証板
```

管理者・規制・Cookieを登録する間はBBSを停止します。

```sh
docker compose -f compose.yaml stop bbs
docker compose -f compose.yaml run --rm --no-deps bbs admission enable \
  --config /etc/oimobbs/config.json
docker compose -f compose.yaml run --rm --no-deps bbs anonymous enable \
  --config /etc/oimobbs/config.json --mode required
```

管理者パスワードは15〜128文字です。bashから登録します。

```bash
read -r -s -p '管理者パスワード: ' oimo_admin_secret
printf '\n'
printf '%s\n' "$oimo_admin_secret" | docker compose -f compose.yaml run --rm -T --no-deps bbs \
  admin init --config /etc/oimobbs/config.json --login owner --password-stdin
unset oimo_admin_secret
```

自動通報を使う場合だけ、停止中に受付板を作ります。

```sh
docker compose -f compose.yaml run --rm --no-deps bbs board create --validation \
  --config /etc/oimobbs/config.json --key report --name '通報受付'
```

板の作成後、`auto_reports` に板キーと運用開始時刻を設定します。[設定例](../docs/configuration.md#自動通報)を参照してください。

管理者登録後にBBSを起動します。

```sh
docker compose -f compose.yaml -f compose.admin.yaml up -d --build
docker compose -f compose.yaml -f compose.admin.yaml ps
```

公開URLは設定した `public.base_url`、管理画面は `admin.origin`、ログイン名は `owner` です。管理画面も公開サイトと同じ443を使います。IP制限は管理画面の「管理画面のアクセス制限」で設定できます。

## 再開・停止

```sh
docker compose -f compose.yaml -f compose.admin.yaml stop
docker compose -f compose.yaml -f compose.admin.yaml up -d
```

板・投稿・鍵はdata volume、証明書とACMEアカウントはcertificates、配信用PEMはtls volumeに残ります。通常の停止で `down -v` は使いません。

## 板の追加

管理画面の板設定から、サイト管理者が稼働中に追加できます。停止中CLIを使う場合：

```sh
docker compose -f compose.yaml -f compose.admin.yaml stop bbs
docker compose -f compose.yaml run --rm --no-deps bbs board create --validation \
  --config /etc/oimobbs/config.json --key news --name 'ニュース'
docker compose -f compose.yaml run --rm --no-deps bbs board list --validation \
  --config /etc/oimobbs/config.json
docker compose -f compose.yaml -f compose.admin.yaml up -d
```

投稿済み保存先にも `--validation` を付けて照合します。

## 更新

以下は新規用のCompose指定です。既存サイトは各コマンドを普段のCompose指定に置き換えます。旧イメージ・設定・停止中データの復旧用コピーを保持してください。

```sh
docker compose -f compose.yaml -f compose.admin.yaml build
docker compose -f compose.yaml -f compose.admin.yaml stop bbs
```

ここで停止中データの復旧用コピーを確保し、次を実行します。

```sh
docker compose -f compose.yaml -f compose.admin.yaml up -d --force-recreate
docker compose -f compose.yaml -f compose.admin.yaml ps
docker compose -f compose.yaml -f compose.admin.yaml logs --tail=50 bbs
```

復旧用コピーには所有者・権限・鍵・全保存先を含めます。通常の本文/鍵バックアップと完全保存先の復旧コピーは同じものではありません。一般のバックアップ・復元は[運用手順](../docs/operations.md)を参照してください。

## 証明書と確認

証明書コンテナは取得後も定期更新します。アプリは新しいTLS接続で更新後のPEMを読みます。更新試験：

```sh
docker compose -f compose.yaml exec -T certificates \
  certbot renew --dry-run --no-random-sleep-on-renew
```

公開トップ、板メニュー、管理ログイン、投稿・返信、再起動後のDATを確認します。

## 公開運用へ進める場合

HTTPS・管理者・投稿規制を準備した後、BBSの起動コマンドを `serve --config /etc/oimobbs/config.json` に変更したComposeを用意します。`serve` は初期化済みサイトと管理リスナーを起動します。

設定の各項目と稼働中の帯域・キャッシュ変更は[設定一覧](../docs/configuration.md)を参照してください。

## 同じHTTPS URLの管理パスで管理する

直結HTTPSと公開入口構成のどちらでも、[同じポートでの管理公開](../docs/setup.md#管理画面を同じポートで公開する)に従って `admin.transport: public_path` と `admin.origin` を設定します。公開入口の `--admin-path` は保存サーバーと同じ管理パスにします。管理用ポートと管理リレーは使いません。

旧別待受から変更する場合は、データvolume指定を維持し、管理ポート・リレーをComposeから外します。公開入口も更新して、同じHTTPSの管理URLでログインを確認します。
