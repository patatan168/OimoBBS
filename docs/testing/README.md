# 検証方法

リポジトリのルートで実行します。Go1.27.3とPython3が必要です。

Go試験・ビルドを直接実行する前に、`mise exec -- go generate ./internal/webui` で静的資産を生成します。生成先の `internal/webui/generated/` はGit管理しません。共通チェック・セットアップ・Docker・自動更新では自動生成します。静的資産の生成と配信は `mise exec -- go test -race ./tools/webassets ./internal/webui`、生成物の一致は `mise exec -- go run ./tools/webassets -check` で確認できます。

## 検査を選ぶ

| 変更・確認の対象 | 手順 |
| --- | --- |
| 文書のみ | [文書・fixtureの検査](#文書を変更したとき) |
| 実装全体・依存関係 | [共通チェック](#共通チェック)・[依存更新器](#依存更新器の検証) |
| セットアップ・起動・専ブラ | [導入と基本動作](setup.md#導入と基本動作) |
| Webの406・圧縮・専ブラ互換 | [HTTP配信と圧縮](setup.md#http配信と圧縮) |
| 公開・管理画面の表示 | [ブラウザー検査の準備](#ブラウザー検査の準備)・[画面と管理操作](admin-ui.md#画面と管理操作) |
| ログイン・再認証・権限 | [管理認証と権限](authentication.md#管理認証と権限) |
| 提出用CSV・ZIP・案件検索 | [提出CSVとZIPの検査](storage.md#提出csvとzipの検査) |
| 保存・復旧・容量回収 | [保存と復旧](storage.md#保存と復旧) |
| WAF・投稿入力・攻撃再現 | [セキュリティ](security.md#セキュリティ) |
| CPU・メモリ・負荷回復 | [性能の検証手順](performance.md) |

性能測定・セキュリティ診断・稼働反映の結果は[検証記録の一覧](measurements.md)から探せます。

## 確認範囲

| 検査 | 確認できる範囲 |
| --- | --- |
| 文書・fixture | リンク、JSON、保存形式、合成入力に対する判断 |
| Go試験・race・fuzz | 試験条件内の動作・競合・入力境界 |
| パーサー検査 | 専ブラの通信解析 |
| Chromiumの隔離UI検査 | fixture上の画面・フォーム操作 |
| 隔離Dockerの性能測定 | 指定した負荷と資源枠での性能 |

実機操作、電源断、実NIC・WAN、本番負荷は、それぞれの環境で確認します。

## 共通チェック

### 文書を変更したとき

```sh
mise exec -- python3 tools/designcheck/check.py
```

Markdownの相対リンクは、同じ文書内・別文書内の見出しも検査します。同一リポジトリを指すGitHub絶対URLと、Security policyの相対リンクの解決基準も検査します。外部サイトへのHTTP接続は行いません。コードブロック、JSON、合成fixtureの保存形式も確認します。サーバーの動作・画面操作・実環境の性能を証明する検査ではありません。

### 実装全体を確認するとき

```sh
mise install
mise exec -- bash scripts/check.sh
```

通常テスト、race、vet、依存検査、CGO無効ビルド、文書・fixture、既知脆弱性検査、fuzzを実行します。Goの対象は `./cmd/... ./internal/... ./tools/...` です。bootstrapのraceは親試験ごとに分割します。変更範囲だけを確認する場合は、[各機能の検査](#検査を選ぶ)を選びます。

### JSON・文字コード・圧縮処理を変更したとき

```sh
mise exec -- go run ./tools/jsonencodegen -check
mise exec -- go test ./internal/jsonencode ./internal/strictjson ./internal/parallel \
  ./internal/textcodec ./internal/zstdencode ./internal/zstddecode ./internal/store ./tools/jsonencodegen
```

生成済みJSONの一致、入力境界、並列処理の枠と順序、文字コード変換、圧縮の復号と破損拒否を確認します。現在の分担条件は[符号化・圧縮・並列処理](../encoding.md)、race・差分fuzz・測定の再実行は各[検証記録](measurements.md#復号処理)を参照してください。この検査だけではHTTP全体の性能や本番負荷での回復は確認できません。

### 脆弱性検査だけを実行するとき

```sh
mise exec -- bash scripts/check-security.sh
```

脆弱性検査にはネットワーク接続が必要です。

## ブラウザー検査の準備

PlaywrightとChromiumを検証環境へ用意し、次の環境変数を設定します。

| 環境変数 | 指定する絶対パス |
| --- | --- |
| `OIMO_BROWSER_NODE` | Nodeの実行ファイル |
| `OIMO_PLAYWRIGHT` | Playwrightパッケージ |
| `OIMO_CHROMIUM` | Chromiumの実行ファイル |

これらの環境変数を使うGoのブラウザー試験は、未指定の場合スキップされます。各手順の `smoke-*.mjs` を直接実行する検査は、各節に記載したNode.js・Chromiumと専用の環境変数を使います。

<!-- 移動前の見出しURLを保持します。新しいリンクは移動先を指定します。 -->
<a id="セットアップスクリプト"></a>
<a id="専ブラの確認"></a>
<a id="揮発性の通信試験サーバー"></a>
<a id="起動投稿の確認"></a>

## 導入と基本動作

セットアップ、起動・投稿、専ブラ、通信試験サーバーの手順は、[導入・HTTP配信の検証](setup.md)を参照してください。

## HTTP配信と圧縮

Webの406、専ブラのidentity/304/206、実TLS通信の手順は、[導入・HTTP配信の検証](setup.md)を参照してください。

<!-- 移動前の見出しURLを保持します。新しいリンクは移動先を指定します。 -->
<a id="ソフトウェア更新と再起動の確認"></a>
<a id="ボタンの配色"></a>
<a id="レス管理削除依頼再認証の期限切れ"></a>
<a id="国内回線の初回取得と管理ui"></a>
<a id="板の管理"></a>
<a id="板の追加名前とキーの変更"></a>
<a id="板の閉鎖"></a>
<a id="監査画面と専用資産"></a>
<a id="閲覧制限の管理画面"></a>

## 画面と管理操作

板の追加・閉鎖、ボタン、監査、レス管理、回線と閲覧制限の手順は、[画面・管理操作の検証](admin-ui.md)を参照してください。

<!-- 移動前の見出しURLを保持します。新しいリンクは移動先を指定します。 -->
<a id="未認証の画面要求を並走させる検査"></a>
<a id="登録用qrの検査"></a>
<a id="管理画面のパスキー"></a>
<a id="管理者otpと一時パスワード"></a>
<a id="管理者権限"></a>
<a id="管理認証のブラウザ検査"></a>
<a id="管理認証の可用性とセッション上限"></a>
<a id="通常の回帰検査"></a>

## 管理認証と権限

ロール、OTP、パスキー、QR、ブラウザ操作、セッション上限の手順は、[管理認証・権限の検証](authentication.md)を参照してください。

<!-- 移動前の見出しURLを保持します。新しいリンクは移動先を指定します。 -->
<a id="保存圧縮"></a>
<a id="容量回収の回帰検査"></a>
<a id="提出csvとzipの検査"></a>
<a id="障害性能提出用記録"></a>

## 保存と復旧

保存障害、バックアップ、提出用CSV・ZIP、容量回収、保存圧縮の手順は、[保存・復旧の検証](storage.md)を参照してください。

<!-- 移動前の見出しURLを保持します。新しいリンクは移動先を指定します。 -->
<a id="wafの入力境界と管理画面"></a>
<a id="waf検出ログと掲示板全体の投稿規制"></a>
<a id="web脆弱性の回帰検査"></a>

## セキュリティ

Web脆弱性、WAF、検出ログ、全板規制の手順は、[セキュリティの検証](security.md)を参照してください。

## 依存更新器の検証

```sh
python3 -B scripts/test_update_dependencies.py
```

外部コマンドを差し替え、Go指定の同期、検証失敗時の無変更、同時編集の保護、差分表示と検証済み反映を確認します。実際の新バージョンとの互換性は、更新器が実行する検証の結果で判断します。
