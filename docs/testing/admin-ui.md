# 画面・管理操作の検証

板の管理、画面表示、操作記録、再認証の期限切れを確認する手順です。[共通の準備と確認範囲](README.md)を先に確認し、コマンドはリポジトリのルートで実行します。

## 手順を選ぶ

- [板の管理](#板の管理)
- [板の追加・名前とキーの変更](#板の追加名前とキーの変更)
- [板の閉鎖](#板の閉鎖)
- [画面と管理操作](#画面と管理操作)
- [ソフトウェア更新と再起動の確認](#ソフトウェア更新と再起動の確認)
- [ボタンの配色](#ボタンの配色)
- [監査画面と専用資産](#監査画面と専用資産)
- [レス管理・削除依頼・再認証の期限切れ](#レス管理削除依頼再認証の期限切れ)
- [国内回線の初回取得と管理UI](#国内回線の初回取得と管理ui)
- [閲覧制限の管理画面](#閲覧制限の管理画面)

## 板の管理

### 板の追加・名前とキーの変更

```sh
mise exec -- go test -race ./internal/bootstrap -run '^Test(AdminBoardMetadata|BoardMetadata|BoardDirectoryMetadata|AdminBoardCreate|AdminCapBoardCreate)' -count=1
```

権限・再認証・CSRF・同一再送・古い画面・キーの重複を検査します。旧キーと新キーの閲覧・投稿、既存DATの保持、並行投稿、保存前後のSIGKILL、再起動・snapshot・オンラインバックアップの隔離再生を含みます。

実画面は、管理者`owner`を登録した新しい隔離サイトで確認します。試験は板と投稿を作り、板名・キーを変更します。[ブラウザー検査の準備](README.md#ブラウザー検査の準備)に加え、`OIMO_BOARD_ADMIN_URL`にそのサイトの`/admin` URL、`OIMO_TEST_PASSWORD`に試験用パスワードを指定します。

```sh
"$OIMO_BROWSER_NODE" scripts/test-board-management-browser.mjs
```

`OIMO_BOARD_SCREENSHOTS`を指定すると追加画面の390px・1280px表示と変更画面を保存します。再認証後の戻り先、エラー時の入力保持、JavaScriptなしのフォーム、旧URL・新URLで同じDATを取得できることを検査します。

### 板の閉鎖

```sh
mise exec -- go test -race ./internal/bootstrap ./internal/app -run 'Test(BoardClosure|ClosedBoard|StoragePressure)' -count=1
```

閉鎖時の再認証・板キー確認、公開取得と返信の拒否、通常ログの保持、再起動、容量不足時の優先回収を検査します。本文回収済みスレッドの原本回収、全体の原本自動整理が無効の場合の期限回収を含みます。

[ブラウザー検査の準備](README.md#ブラウザー検査の準備)に従って環境変数を設定すると、次の検査で新しい隔離サイトを用意し、再認証後の戻り先・入力エラー・JavaScriptなしのフォーム・公開停止を確認できます。

```sh
mise exec -- go test ./internal/bootstrap -run '^TestBoardClosureBrowser$' -count=1 -v
```

`OIMO_LAYOUT_SCREENSHOTS`を指定すると、閉鎖確認画面の390px・1280px表示をライト・ダークの両テーマで保存します。実時間で6ヶ月間待つ試験や、本番サーバーの削除状態を確認する試験ではありません。

## 画面と管理操作

### ソフトウェア更新と再起動の確認

```sh
mise exec -- go test -race ./internal/selfupdate
mise exec -- go test ./internal/bootstrap -run 'TestSoftwareUpdate|TestAdminNavigationPermissions|TestAuditPresentationCoverage' -count=1
python3 -B scripts/test_deploy_software_update.py -v
```

ブラウザー検査の環境変数を指定すると `TestSoftwareUpdateBrowser` が有効になり、確認・キャンセル・再認証・同意・受付を操作します。実Gitの隔離取得、確認対象の固定、再送、期限、権限・世代失効、監査保存、Docker/systemdコマンドを差し替えた停止・バックアップ・置換順序を検査します。[更新サービスの設定と確認範囲](../software-updates.md)も参照してください。

### ボタンの配色

[ブラウザー検査の準備](README.md#ブラウザー検査の準備)を済ませてから実行します。

```sh
mise exec -- go test ./internal/bootstrap -run '^TestButtonColorsBrowser$' -count=1
```

隔離サイトの公開・管理画面で、折りたたみ内も含め、ボタンとナビゲーションリンクの通常時・ホバー時を明暗両テーマで検査します。有効な操作部品の文字と背景のコントラスト比は4.5以上を必要とします。`OIMO_BUTTON_SCREENSHOTS` に出力先を指定すると、提出用ログ画面の画像も保存します。

### 監査画面と専用資産

[管理操作の記録](../admin-guide.md#管理操作の記録を調べる)の検索・ページ送りと、管理HTML・CSS/JSの権限を確認します。

```sh
mise exec -- go test ./internal/bootstrap ./internal/webui \
  -run 'Test(Audit|AdminAudit|AdminPageAssets|AdminPrivateAssets|AdminResponseTiming|AdminTiming|PageAssetIsolation|AllTemplatesParse)' -count=1
```

このコマンドは保存・再起動・検索条件・表示用分類・資産の権限境界を検査します。画面操作も確認する場合は、[ブラウザー検査の準備](README.md#ブラウザー検査の準備)を済ませて次を実行します。

```sh
mise exec -- go test ./internal/bootstrap -run '^TestAdminAuditBrowser$' -count=1
```

| ブラウザ検査の対象 | 確認すること |
| --- | --- |
| 操作者・操作の絞り込み | 操作者候補、操作名の検索、候補なし、選択後の検索結果 |
| キーボード・JavaScript無効時 | Enter・Escapeと、候補一覧から選ぶ代替操作 |
| 一覧と詳細 | ページ送り、条件の維持、操作説明、対象、詳細項目 |
| 狭い画面・PC | 320〜1440pxの幅での表示と横方向のはみ出し |

`OIMO_FIREFOX=1` で、Playwrightが管理するFirefoxでも同じ検査を実行できます。`OIMO_AUDIT_SCREENSHOTS` に保存先ディレクトリを指定すると、画面画像を保存します。いずれも隔離した試験用サイトでの検査で、実環境の認証済み画面や回線速度を確認した結果ではありません。

### レス管理・削除依頼・再認証の期限切れ

次の試験は隔離した実データとHTTPサーバーを使います。管理認証の検査は、通常のログイン期限切れと、重要操作に使う再認証の10分の期限切れを区別します。

| 試験 | 確認すること |
| --- | --- |
| `TestAdminPosts` | 対象レスだけの削除、非公開記録の保持、権限、規制対象、再送、版の競合、50件のページ送り |
| `TestAdminPostActionsBrowser` | 実際のSLIP付き名前、ボタン配置、規制・解除・停止・削除と公開反映 |
| `TestAdminReauthenticationExpiry` | ログインは有効でも再認証が切れた操作を拒否し、再認証後に復帰できること |
| `TestAdminReauthenticationExpiryBrowser` | 入力後の期限切れ、操作の拒否、元画面への復帰、HTML取得後の資産取得中の期限切れ |
| `TestAdminExpiredSessionBrowser` | ログイン状態そのものが失効した場合のログイン画面と資産の復帰 |
| `TestReportRequestBrowser` | レスからの依頼、連続送信の拒否、照会、設定した送信間隔の変更 |
| `TestDateInputsBrowser` | 期間候補・カレンダー、日本時間と入力精度、JavaScript無効時の入力 |

```sh
mise exec -- go test ./internal/bootstrap -run 'TestAdminPosts|TestAdminReauthenticationExpiry$' -count=1
```

ブラウザー試験の実行環境は[ブラウザー検査の準備](README.md#ブラウザー検査の準備)を参照してください。環境変数を設定すると、次の試験を実行できます。

```sh
mise exec -- go test ./internal/bootstrap -run 'TestAdmin(PostActionsBrowser|ReauthenticationExpiryBrowser|ExpiredSessionBrowser)|TestReportRequestBrowser|TestDateInputsBrowser' -count=1 -timeout=3m
```

再認証の期限切れは、11分前に本人確認したセッションで再現し、実時間で10分待つ方式は使いません。Firefoxでは、資産の再認証拒否から画面を開き直す経路も確認します。`OIMO_FIREFOX=1` でFirefox、`OIMO_NOJS=1` でレス管理操作のJavaScript無効時を確認できます。隔離試験の成功だけでは、稼働環境での管理操作を確認したことにはなりません。

### 国内回線の初回取得と管理UI

通常更新での標準分類の反映、手動上書きの保持、停止中・更新予定前の動作、取得失敗時の旧表保持、並列数・厳密な圧縮表を、外部接続なしで検査します。毎日・毎週・毎月の日本時間での予定、月末・うるう年・年越し、旧設定の読込、保存・再起動後の保持、reader108の境界も検査します。日時の境界検査は時計待ちなしで行います。

```sh
mise exec -- go test -race ./internal/bootstrap ./cmd/oimobbs -run 'Test(Network|DomesticNetwork|MixedNetwork|ServiceNetwork|SpecialNetwork|ValidationServerLifecycle)' -count=1
```

実際の公開取得先から、[標準カタログ](../networks.md)の全ASNと国/VPNを取得し、保存・再読込まで確認する場合：

```sh
OIMO_NETWORK_LIVE=1 mise exec -- go test ./internal/bootstrap -run '^TestNetworkDomesticLiveStartup$' -count=1 -v
```

画面の確認は、[ブラウザー検査の準備](README.md#ブラウザー検査の準備)に従い、`OIMO_BROWSER_NODE`・`OIMO_PLAYWRIGHT`・`OIMO_CHROMIUM`を設定して実行します。Go試験が新しい隔離サイトと管理HTTPサーバーを用意します。

```sh
mise exec -- go test ./internal/bootstrap -run '^TestNetworkCatalogueBrowser$' -count=1 -v -timeout=5m
```

管理画面に「逆引きできない接続元」を拒否する制限がある場合は、同じブラウザー設定で`TestNetworkSettingsAccessBrowser`を実行します。隔離したHTTPSサーバーと固定DNS応答を使い、OS標準DNSの旧設定を保存した直後のHTML・CSS/JS・次回の画面表示が403にならないことを確認します。`TestNetworkSettingsPreserveDNSAccess`は修正前に「設定は保存されるが応答だけ403」を再現し、修正後は保存・再表示の成功と、明示したIP拒否が引き続き403になることを検査します。外部DNSへの照会は行いません。

実際にログインし、390/1280px・明暗の表示で毎日04:00・毎週月曜04:00・毎月31日/月末04:00を保存し、次回予定・不要な即時取得がないこと・再表示後の選択値を確認します。「今すぐ更新」から取得・自動再表示・保存結果までを確認し、予定と手動上書きの保持、標準取得元追加、JavaScript無効時の保存も検査します。画面の警告・HTTPエラー・JavaScript例外と横スクロールがないことを確認します。通常は架空の取得データを使い、`OIMO_NETWORK_LIVE=1`を付けると公開データを実取得します。`OIMO_NETWORK_BROWSER_OUTPUT`を指定すると画面と`result.json`を保存します。

分類の根拠と実行結果は[標準カタログの見直しと検証](network-catalogue-review.md)を参照してください。本番の設定や動作を確認する試験ではありません。

### 閲覧制限の管理画面

Node.js24以降とChromiumで、Goが描画した隔離fixtureを検査します。

```sh
OIMO_READING_PAGE_OUTPUT=/tmp/oimo-reading-page.html mise exec -- go test ./internal/bootstrap -run '^TestReadingManagementPageFixture$' -count=1
OIMO_READING_PAGE_OUTPUT=/tmp/oimo-reading-page.html OIMO_CHROME=/path/to/chromium node scripts/smoke-reading-ui.mjs
```

160・320・390・1280・1800・1920・2200pxで値の保持・条件切替・解除案内・横幅を確認します。JavaScriptなしのフォームも検査します。
