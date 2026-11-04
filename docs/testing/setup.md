# 導入・HTTP配信の検証

セットアップ、起動・投稿、専ブラ通信とHTTP圧縮を確認する手順です。[共通の準備と確認範囲](README.md)を先に確認し、コマンドはリポジトリのルートで実行します。

## 手順を選ぶ

- [導入と基本動作](#導入と基本動作)
- [セットアップスクリプト](#セットアップスクリプト)
- [起動・投稿の確認](#起動投稿の確認)
- [専ブラの確認](#専ブラの確認)
- [揮発性の通信試験サーバー](#揮発性の通信試験サーバー)
- [HTTP配信と圧縮](#http配信と圧縮)

## 導入と基本動作

### セットアップスクリプト

証明書の取得・自動更新スクリプトは、ACMEとsystemdを置き換えて隔離検査します。Python3・Bash・OpenSSLが必要です。

```sh
bash -n scripts/setup-certificates.sh
python3 -B scripts/test_setup_certificates.py -v
```

実PEMの読込み・更新、名前や鍵が不正な場合の旧PEM保持、取得失敗、既存unit・リンク・所有者変更の拒否を確認します。実ドメインでの取得、外部からの80番到達性、実ホストでのtimer発火は、この検査には含みません。[証明書のセットアップ手順](../setup.md#証明書の自動セットアップ)で別途確認します。

ビルド済みの製品バイナリ、Go1.27.3、Python3、TLS試験用のOpenSSLを用意します。

```sh
mise exec -- go test ./tools/setup
OIMO_SETUP_TEST_BINARY="$PWD/bin/oimobbs" mise exec -- python3 scripts/test_setup.py -v
```

セットアップ検証にはunitのsystemd構文検査、既存unitの上書き拒否、登録コマンドの途中失敗、`--service-only` の設定・データ保持も含みます。サービス連携試験ではsudo/systemctlを代替し、ホストへの登録は行いません。実際のsystemd起動・OS再起動後の自動起動は対象環境で別途確認してください。

Goの単体試験でHTTPS 443と運営板の既定値、HTTPの明示許可、入力・パス・既存ファイルの保護を確認します。Pythonの試験は隔離した保存先でビルド・初期設定、明示許可したHTTPと検証済みTLSでの管理ログイン・TLSポートへの平文要求の拒否、再起動、`--start`、既存設定・データの保護、誤った証明書とパスワードの拒否を確認します。バイナリ未指定時は実HTTP試験をskipします。

### 起動・投稿の確認

[Dockerなしの手順](../setup.md#ローカルで起動する)で別の保存先を作成し、以下を確認します。

1. 管理者登録・板作成・規制・Cookie有効化が成功する。
2. 公開トップ、メニュー、板一覧、管理ログインが開く。
3. Webスレ立てと返信が確認後に保存され、DAT・subjectへ反映する。
4. 同一再送が重複投稿にならない。
5. 正常停止・再起動後に投稿と設定が残る。
6. Cookieなし、無効な資格、古い確認・CSRF、規制該当、旧版への差分取得を拒否する。
7. 専ブラ専用板でWeb403、DAT・CGIの維持、転載・クローラー条件を確認する。
8. 管理パス管理の認証・再認証・フォーム・API更新・資産・Cookie範囲を確認し、公開HTML/robotsへのパス漏れ、既知クローラー、別Host・平文・曖昧なパスを拒否する。
9. 共通・板別・管理用の閲覧設定を保存し、Web/DAT/一覧/検索・HEAD/Range/304・再起動で拒否を確認する。閲覧拒否では投稿・CAP・再送も拒否し、投稿だけの禁止は閲覧を妨げないことを確認する。
10. 管理用設定による自己締め出しを拒否し、停止中CLIで管理用条件だけを解除して同じパスワードで再ログインできることを確認する。

変更に合わせて `internal/bootstrap` の実HTTP・停止点・復旧試験を選びます。ストレージ・署名・規制の変更では、既存試験で改変・欠落・期限・再送の拒否が維持されることも確認します。

周期保守が混雑板を待ち、サイト共通ロックで閲覧まで止めないことは、次で検査できます。期限回収の再開、明示・周期の監査移管の中断・再起動・重複防止も含みます。

```sh
mise exec -- go test -race ./internal/bootstrap -run 'PeriodicControlMaintenance|ControlExpiry|ThreadAuditTransfer|RequiredCheckpoint|BodyCarryRetirement|BodyCarrySweep' -count=1
```

### 専ブラの確認

`tools/clientcheck/` はOle Board Browserの実パーサーを使う通信検査です。対象checkoutとNode環境が別途必要です。CAPを含む隔離通信検査は次です。

```sh
mise exec -- python3 tools/clientcheck/run_caps.py
```

対象checkoutの配置はスクリプトで確認します。端末の画面操作とCookie保持は別途確認します。

### 揮発性の通信試験サーバー

```sh
mise exec -- go run ./cmd/compatprobe
```

loopbackの公開9080・管理9081を使います。管理キーは `var/compatprobe-admin.key` です。終了すると投稿は消えるため、永続サイトには [validation-serve](../setup.md#ローカルで起動する) を使います。

## HTTP配信と圧縮

```sh
mise exec -- go test ./internal/bootstrap -run '^(TestWebCompressionRequired|TestAdminCompressionBeforeNonce|TestWebCompressionTLS)$' -count=1
mise exec -- go test -race ./internal/compat ./internal/publicedge ./internal/webui ./tools/webassets
mise exec -- go run ./tools/webassets -check
```

Web・管理画面の受付条件、専ブラのidentity/304/206、HTTP/1.1・HTTP/2の実TLS通信を検査します。旧HTTPの拒否とSSHトンネル内部の例外は[HTTP世代の検証記録](web-http-protocol.md)、圧縮条件は[圧縮対応必須化の検証記録](web-compression-required.md)を参照してください。実ブラウザや稼働サーバーの確認は別に行います。過去の比較条件は[圧縮の測定記録](measurements.md#http配信と圧縮)に記載しています。
