# 検証方法

リポジトリのルートで実行します。Go1.27.2とPython3が必要です。

目的別の詳細は[管理者の権限](../admin-permissions.md)と[CPU・メモリ・復旧時間の検証](performance.md)を参照してください。

## 管理者権限

現在のロール・追加権限・画面表示は[管理者の権限](../admin-permissions.md)にまとめています。

```sh
mise exec -- go test -race ./internal/adminaccess ./internal/bootstrap \
  -run 'Test(AdministratorRoleMatrix|AdminHTTPPrivilegeBoundaries|PrivateReportsRequireExplicitPermission|PrivateReportSendRechecksSession|ModeratorExtraPermissionsDoNotGrantAdministrativeReads|AdminNavigationPermissions|AdminInherited|ThreadActionRoleAndScope|EvidenceSendChecksAfterReservation|AdminQueuedSessionLogout)' \
  -timeout 10m
```

| 検査対象 | 確認すること |
| --- | --- |
| ロール・担当板 | 下位ロール、担当外・存在しない板、サイト範囲へのアクセスを拒否 |
| 追加権限 | なし・片方・両方の個別付与と、上位ロールの自動許可 |
| 閲覧制限 | 管理担当の板設定・スレッド一覧・操作記録は、追加権限と再認証があっても拒否 |
| メニュー | PC・スマホ、関連リンク、マニュアル内リンクの表示とURL直アクセスの拒否 |
| 保存・送信 | 世代失効、最後のサイト管理者保護、送信直前のログアウト・権限変更 |
| 操作の継続 | 管理担当による投稿削除・公開停止・投稿停止が利用可能 |

ブラウザではログイン・再認証、担当板のチェック、上位ロールの追加権限のチェック済み・変更不可、降格時のチェック解除を確認します。320・390・1280pxとJavaScript無効時を含めます。Go試験と実ブラウザ確認は別々に記録します。

## 共通チェック

```sh
mise install
mise exec -- bash scripts/check.sh
```

通常テスト、race、vet、依存検査、CGO無効ビルド、文書・fixture、既知脆弱性検査を実行します。Goの対象は `./cmd/... ./internal/... ./tools/...` です。bootstrapのraceは親試験ごとに分割します。

文書・fixtureのみの検査：

```sh
mise exec -- python3 tools/designcheck/check.py
```

脆弱性検査のみ：

```sh
mise exec -- bash scripts/check-security.sh
```

脆弱性検査にはネットワーク接続が必要です。

## セットアップスクリプト

ビルド済みの製品バイナリ、Go1.27.2、Python3、TLS試験用のOpenSSLを用意します。

```sh
mise exec -- go test ./tools/setup
OIMO_SETUP_TEST_BINARY="$PWD/bin/oimobbs" mise exec -- python3 scripts/test_setup.py -v
```

Goの単体試験で入力・パス・既存ファイルの保護を確認します。Pythonの試験は隔離した保存先でビルド・初期設定、HTTPと検証済みTLSでの管理ログイン、再起動、`--start`、既存設定・データの保護、誤った証明書とパスワードの拒否を確認します。バイナリ未指定時は実HTTP試験をskipします。

## 起動・投稿の確認

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

## 専ブラの確認

`tools/clientcheck/` はOleBoardBrowserの実パーサーを使う通信検査です。対象checkoutとNode環境が別途必要です。CAPを含む隔離通信検査は次です。

```sh
mise exec -- python3 tools/clientcheck/run_caps.py
```

対象checkoutの配置はスクリプトで確認します。端末の画面操作とCookie保持は別途確認します。

## 障害・性能・提出用記録

実ファイルと署名journalの照合、Syncエラー、途中停止、再起動、再送を確認します。SIGKILLは電源断でOSキャッシュを失う試験とは別です。バックアップは作成成功だけでなく隔離再生と復元先の照合も確認します。

記録には秘密カナリアを使い、公開HTML・DAT・JSON・通常ログに認証秘密が入らないことを検査します。非公開照会・保全・出力は担当板・追加権限・期限・欠測を検査し、保存されていない情報を出力で補いません。

性能試験はCPU・メモリ・ディスク・帯域・投稿/閲覧比率・クライアント数・測定期間・エラー率を明記します。専ブラ80%／Web20%の混在条件を使う場合はその配分を維持します。復旧後の5秒以内を判定する指標は予定送信時刻から完了までのp95で、サーバー内部時間だけで置き換えません。

結果にはコマンド、環境、成功・失敗、未確認範囲を記録します。

## 国内回線の初回取得と管理UI

外部接続なしで並列数・全ASN要求・手動設定の保持・厳密な圧縮表・実フォームを検査します。

```sh
mise exec -- go test ./internal/bootstrap ./cmd/oimobbs -run 'Test(Network|DomesticNetwork|ValidationServerLifecycle)'
```

実際の公開取得先から、国内204 ASN・VPN事業者/共有基盤7 ASNと国/VPNをまとめて取得し、保存・再読込まで確認する場合：

```sh
OIMO_NETWORK_LIVE=1 mise exec -- go test ./internal/bootstrap -run '^TestNetworkDomesticLiveStartup$' -count=1 -v
```

Node.js24以降とChromiumを使う隔離UI検査：

```sh
OIMO_NETWORK_PAGE_OUTPUT=/tmp/oimo-networks-page.html mise exec -- go test ./internal/bootstrap -run '^TestNetworkDomesticManagementPage$' -count=1
OIMO_NETWORK_PAGE_OUTPUT=/tmp/oimo-networks-page.html node scripts/smoke-network-ui.mjs
```

Chromiumの場所は `OIMO_CHROME`、画像・結果の保存先は `OIMO_UI_OUTPUT` で指定できます。160/320/390/1280px、名前・ASN検索、区分フィルター、空結果、20件切替、保存失敗した行の表示、JavaScriptなしの概要・フォームを確認します。

## 閲覧制限の管理画面

Node.js24以降とChromiumで、Goが描画した隔離fixtureを検査します。

```sh
OIMO_READING_PAGE_OUTPUT=/tmp/oimo-reading-page.html mise exec -- go test ./internal/bootstrap -run '^TestReadingManagementPageFixture$' -count=1
OIMO_READING_PAGE_OUTPUT=/tmp/oimo-reading-page.html OIMO_CHROME=/path/to/chromium node scripts/smoke-reading-ui.mjs
```

160・320・390・1280・1800・1920・2200pxで値の保持・条件切替・解除案内・横幅を確認します。JavaScriptなしのフォームも検査します。

## CPUとメモリ

入力の一致、単体ベンチマーク、実HTTPの負荷条件、復旧時間の指標は[CPU・メモリ・復旧時間の検証](performance.md)を参照してください。

## 揮発性の通信試験サーバー

```sh
go run ./cmd/compatprobe
```

loopbackの公開9080・管理9081を使います。管理キーは `var/compatprobe-admin.key` です。終了すると投稿は消えるため、永続サイトには [validation-serve](../setup.md#ローカルで起動する) を使います。

## 確認範囲

| 検査 | 確認できる範囲 |
| --- | --- |
| 文書・fixture | リンク、JSON、保存形式、合成入力に対する判断 |
| Go試験・race・fuzz | 試験条件内の動作・競合・入力境界 |
| パーサー検査 | 専ブラの通信解析 |
| Chromiumの隔離UI検査 | fixture上の画面・フォーム操作 |
| 隔離Dockerの性能測定 | 指定した負荷と資源枠での性能 |

実機操作、電源断、実NIC・WAN、本番負荷は、それぞれの環境で確認します。
