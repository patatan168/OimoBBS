# OimoBBS

Goで動く匿名掲示板です。Webブラウザと専用ブラウザから閲覧・投稿でき、板・スレッド・投稿・管理設定を永続保存します。一般利用者のログインは不要です。

## はじめる

| 使い方 | 手順 |
| --- | --- |
| Dockerなしで、自分のPCで試す | [ローカルセットアップ](docs/setup.md#ローカルで起動する) |
| Dockerなしで、サーバーへ公開する | [HTTPSで公開する](docs/setup.md#httpsで公開する) |
| Dockerで起動する | [Dockerセットアップ](deploy/README.md) |

LinuxとGo1.27.2でビルドできます。[セットアップスクリプト](docs/setup.md#スクリプトでセットアップ)はBashとGoで動き、HTTP・HTTPSの初期設定をまとめて行います。

## 文書

機能は[確定仕様](docs/specification.md)、設定・運用・開発の資料は[文書一覧](docs/README.md)を参照してください。

管理画面の「マニュアル」に画面操作とCAPコマンドを掲載しています。

## 開発時の検証

```sh
mise install
mise exec -- bash scripts/check.sh
```

Python3とネットワーク接続が必要です。検査内容は[検証方法](docs/testing/README.md)を参照してください。

## ライセンス

同梱データ・依存の出典は[文字変換表](third_party/whatwg/README.md)、[Go由来の定数表](third_party/go/LICENSE)、[Argon2id](third_party/argon2/README.md)を参照してください。
