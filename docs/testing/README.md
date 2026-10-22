# 検証方法

リポジトリのルートで実行します。Go1.27.3とPython3が必要です。

## 検査を選ぶ

| 変更・確認の対象 | 手順 |
| --- | --- |
| 文書のみ | [文書・fixtureの検査](#文書を変更したとき) |
| 実装全体 | [共通チェック](#共通チェック) |
| セットアップ | [セットアップスクリプト](#セットアップスクリプト) |
| 投稿・保存・再起動 | [起動・投稿の確認](#起動投稿の確認)・[障害の確認](#障害性能提出用記録) |
| 保存容量・古いスレッドの回収 | [容量回収の回帰検査](#容量回収の回帰検査) |
| 操作記録の検索・表示、CSS/JSの権限 | [監査画面と専用資産](#監査画面と専用資産) |
| レス管理・削除依頼・再認証の期限切れ | [レス管理と再認証の検査](#レス管理削除依頼再認証の期限切れ) |
| 権限・管理画面 | [管理者権限](#管理者権限)・[閲覧制限の管理画面](#閲覧制限の管理画面) |
| CPU・メモリ・負荷回復 | [性能の検証手順](performance.md) |

記録済みの性能結果は[測定資料一覧](measurements.md)にまとめています。

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

通常テスト、race、vet、依存検査、CGO無効ビルド、文書・fixture、既知脆弱性検査、fuzzを実行します。Goの対象は `./cmd/... ./internal/... ./tools/...` です。bootstrapのraceは親試験ごとに分割します。変更範囲だけを確認する場合は、下の各機能の検査を選びます。

### 脆弱性検査だけを実行するとき

```sh
mise exec -- bash scripts/check-security.sh
```

脆弱性検査にはネットワーク接続が必要です。

## ボタンの配色

Playwright用の環境変数を指定し、`mise exec -- go test ./internal/bootstrap -run '^TestButtonColorsBrowser$' -count=1` を実行します。隔離サイトの公開・管理画面で、折りたたみ内も含め、ボタンとナビゲーションリンクの通常時・ホバー時を明暗両テーマで検査します。有効な操作部品の文字と背景のコントラスト比は4.5以上を必要とします。`OIMO_BUTTON_SCREENSHOTS` に出力先を指定すると、提出用ログ画面の画像も保存します。

## 監査画面と専用資産

[管理操作の記録](../admin-guide.md#管理操作の記録を調べる)の検索・ページ送りと、管理HTML・CSS/JSの権限を確認します。

```sh
mise exec -- go test ./internal/bootstrap ./internal/webui \
  -run 'Test(Audit|AdminAudit|AdminPageAssets|AdminPrivateAssets|AdminResponseTiming|AdminTiming|PageAssetIsolation|AllTemplatesParse)' -count=1
```

このコマンドは保存・再起動・検索条件・表示用分類・資産の権限境界を検査します。ブラウザ操作は、次の環境変数を指定した場合だけ実行します。

Playwrightとそのブラウザを別途用意し、`OIMO_BROWSER_NODE` にNode.jsの実行ファイル、`OIMO_PLAYWRIGHT` にPlaywrightモジュールのパス、`OIMO_CHROMIUM` にChromiumの実行ファイルを指定します。指定方法の例は[管理認証のブラウザ検査](#管理認証のブラウザ検査)を参照してください。

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

## レス管理・削除依頼・再認証の期限切れ

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

ブラウザー試験の実行環境は[管理認証のブラウザ検査](#管理認証のブラウザ検査)を参照してください。環境変数を設定すると、次の試験を実行できます。

```sh
mise exec -- go test ./internal/bootstrap -run 'TestAdmin(PostActionsBrowser|ReauthenticationExpiryBrowser|ExpiredSessionBrowser)|TestReportRequestBrowser|TestDateInputsBrowser' -count=1 -timeout=3m
```

再認証の期限切れは、11分前に本人確認したセッションで再現し、実時間で10分待つ方式は使いません。Firefoxでは、資産の再認証拒否から画面を開き直す経路も確認します。`OIMO_FIREFOX=1` でFirefox、`OIMO_NOJS=1` でレス管理操作のJavaScript無効時を確認できます。隔離試験の成功だけでは、稼働環境での管理操作を確認したことにはなりません。

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

## セットアップスクリプト

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

`tools/clientcheck/` はOle Board Browserの実パーサーを使う通信検査です。対象checkoutとNode環境が別途必要です。CAPを含む隔離通信検査は次です。

```sh
mise exec -- python3 tools/clientcheck/run_caps.py
```

対象checkoutの配置はスクリプトで確認します。端末の画面操作とCookie保持は別途確認します。

## 障害・性能・提出用記録

実ファイルと署名journalの照合、Syncエラー、途中停止、再起動、再送を確認します。SIGKILLは電源断でOSキャッシュを失う試験とは別です。バックアップは作成成功だけでなく隔離再生と復元先の照合も確認します。

記録には秘密カナリアを使い、公開HTML・DAT・JSON・通常ログに認証秘密が入らないことを検査します。非公開照会・保全・出力は担当板・追加権限・期限・欠測を検査し、保存されていない情報を出力で補いません。

性能試験はCPU・メモリ・ディスク・帯域・投稿/閲覧比率・クライアント数・測定期間・エラー率を明記します。専ブラ80%／Web20%の混在条件を使う場合はその配分を維持します。復旧後の5秒以内を判定する指標は予定送信時刻から完了までのp95で、サーバー内部時間だけで置き換えません。

結果にはコマンド、環境、成功・失敗、未確認範囲を記録します。

### 提出CSVとZIPの検査

```sh
mise exec -- go test ./internal/disclosure -run 'Test(Export|Submission|SampleZIP|ContentExport|LogExplanation)' -count=1
mise exec -- go test ./internal/bootstrap -run '^Test(EvidenceExtractFromDraft|PostingReverseDNSPersistsAndExports|AdminEvidenceHTTPCompleteLifecycle|AdminUnboundHTTPObservationQueryAndRestart|AdminRejectedEvidenceHTTP)$' -count=1
```

| 対象 | 確認すること |
| --- | --- |
| 対象と本文 | 保存済みの `board_key`・`thread_key`・`post_number`、本人の `public_body`、自動投稿の除外 |
| 応答終了時刻 | 対応するHTTP原本の自動保全、同一要求の照合、記録あり・欠測が混在するCSV |
| CSVの読み方 | JST、空欄・null・空文字の区別、数式と桁落ちの防止、実列ごとの型と説明 |
| ZIPとサンプル | 実ZIPの署名・件数・ファイルハッシュ、サンプルがCSVとREADMEだけの未署名見本であること |
| 一覧・検索 | 通常投稿と未受理・閲覧の入口分離、作成日時順、検索・状態・並び順、条件付きページ送り、担当外の非表示 |
| 管理操作 | 全項目でのZIP取得、削除済み照会・受渡し経路と入力の拒否、版競合・再送・権限・期限の検査 |

画面では、案件作成からZIP取得までを確認します。ZIP内の `readme.txt` とサンプルは実際に展開して読み、表示・列名が[現在の仕様](../features/records.md#提出用ファイル)と一致することを確認します。隔離HTTPの検査と稼働環境での取得確認は分けて記録します。

## 容量回収の回帰検査

隔離した一時保存先で、容量の開始・終了基準、7日の境界、回収順、案件保全、途中停止と再起動、別板の投稿継続、HTTP投稿とバックアップ再生を検査します。

```sh
mise exec -- go test ./internal/app ./internal/bootstrap -run '^TestStoragePressure' -count=1
mise exec -- go test -race ./internal/app ./internal/bootstrap -run '^TestStoragePressure' -count=1
```

既存の期限満了・保全・原本回収への影響を確認する場合：

```sh
mise exec -- go test ./internal/app ./internal/bootstrap \
  -run 'TestRequiredRetirement|TestRequiredGCJob|TestRequiredOriginalRepository|TestRequiredHoldProduct|TestPostingCapacity|TestPersistentExpiry|TestReclaimedBodyBackupReplay' -count=1
```

これらはディスク空き容量を模擬する隔離試験です。実ディスクを満杯にする試験、電源断、本番負荷での遅延や、稼働環境への適用確認は含みません。

## 国内回線の初回取得と管理UI

外部接続なしで並列数・全ASN要求・手動設定の保持・厳密な圧縮表・実フォームを検査します。

```sh
mise exec -- go test ./internal/bootstrap ./cmd/oimobbs -run 'Test(Network|DomesticNetwork|ValidationServerLifecycle)'
```

実際の公開取得先から、[標準カタログ](../networks.md)の全ASNと国/VPNを取得し、保存・再読込まで確認する場合：

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

## 揮発性の通信試験サーバー

```sh
go run ./cmd/compatprobe
```

loopbackの公開9080・管理9081を使います。管理キーは `var/compatprobe-admin.key` です。終了すると投稿は消えるため、永続サイトには [validation-serve](../setup.md#ローカルで起動する) を使います。

## 保存圧縮

| 確認すること | 参照先 |
| --- | --- |
| 圧縮する対象と保存形式 | [内部設計](../architecture.md#ログ関連の圧縮範囲) |
| 同じ入力の圧縮量・時間・割り当て | [保存codecの比較](../../tools/storagebench/README.md) |
| 実HTTPのCPU・メモリ・復旧 | [性能の検証手順](performance.md) |
| 過去の条件・全試行・不採用候補 | [保存圧縮の測定資料](storage-compression.json) |

合成入力の圧縮率や復号速度だけで、実HTTPの投稿性能を判断しません。実測では保存件数・DAT・ログ欠測・OOMも確認し、CPU・メモリ枠が異なる結果を混ぜずに記録します。

## WAFの入力境界と管理画面

クエリ128／129項目、同名・空項目、percent符号化された区切り、本文の未読、拒否判定の追加割当0を確認します。既存の検知・ON/OFF・認証・CSRF・保存・再送・再起動の検査も実行します。

```sh
mise exec -- go test -race ./internal/waf ./internal/bootstrap \
  -run 'TestInspect|TestInspection|TestWAF' -count=1 -timeout=10m
OIMO_WAF_PAGE_OUTPUT=/tmp/oimo-waf-page.html mise exec -- go test ./internal/bootstrap \
  -run '^TestWAFManagementPageFixture$' -count=1
OIMO_WAF_PAGE_OUTPUT=/tmp/oimo-waf-page.html OIMO_CHROME=/path/to/chromium \
  node scripts/smoke-waf-ui.mjs
```

ブラウザ検査にはNode.js24以降とChromiumが必要です。320・390・700・1280・1920pxで横幅、詳細の開閉、編集値の保持、閉じた項目を含む22項目の送信データを確認します。JavaScriptなしの開閉も確認します。fixtureでの画面検査と、実HTTPでの保存・再起動を区別して記録します。


## 管理者OTPと一時パスワード

認証アプリのコード検証と、認証手段を失った管理者の復旧を確認します。

```sh
mise exec -- go test -race ./internal/adminauth ./internal/bootstrap \
  -run 'TestTOTP|TestStrongReauthentication|TestAdminOTP|TestAdminTemporaryPassword|TestAdminPasswordTemporary|TestAdminSiteAdministratorRecovery' \
  -timeout=10m
```

| 確認対象 | 主な検査内容 |
| --- | --- |
| コードの正しさ | RFC6238のSHA1既知ベクトル、時刻窓、6桁の形式 |
| 一度限りの利用 | 並列認証、使用済み区間、再起動後の再送拒否 |
| 登録用データ | 登録待ちの期限・用途・容量、暗号文の改変・他の管理者への転用 |
| 保存失敗 | 使用済み区間を保存できない場合は認証しない |
| ログイン制限 | パスワード単独の拒否、最後の認証手段の削除拒否 |
| 復旧 | サイト管理者は停止中CLI、他の管理者はWebの一時パスワード |
| 一時パスワード | 期限切れ、再発行、本人の変更強制、変更前の管理操作拒否 |
| 復旧経路の制限 | サイト管理者のWebリセット・降格によるリセットの拒否 |

### 登録用QRの検査

`TestEnrollmentQR`で容量境界・PNG形式・余白を検査します。独立した復号検査には、検証専用の`jsqr`と`pngjs`を製品外へ用意し、次の環境変数を設定します。

| 環境変数 | 指定する絶対パス |
| --- | --- |
| `OIMO_BROWSER_NODE` | Nodeの実行ファイル |
| `OIMO_QR_DECODER` | `scripts/decode-enrollment-qr.mjs` |
| `OIMO_QR_JSQR` | 検証用の`jsqr`パッケージ |
| `OIMO_QR_PNGJS` | 検証用の`pngjs`パッケージ |

設定後、次を実行します。検証ツールは製品依存に含めません。

```sh
mise exec -- go test ./internal/adminauth -run '^TestEnrollmentQR' -v
```

## 管理画面のパスキー

```sh
mise exec -- go test -race ./internal/bootstrap \
  -run 'TestAdminPasskey|TestAdminNavigationPermissions' -timeout=10m
```

`TestAdminPasskey`は次の境界を検証します。

- チャレンジの期限・一度限りの利用・用途とブラウザへの束縛。
- HTTPのOrigin・CSRF・再認証、鍵一覧の版競合、停止後の保存復旧。
- ログイン名・鍵一覧が未ログインの応答へ出ないこと。
- パスキー開始がパスワード認証の試行枠を消費しないこと。
- 鍵削除・パスワード再設定後の全セッション失効と、旧世代で確定待ちの操作の拒否。

## 管理認証のブラウザ検査

PlaywrightとChromiumを検証環境へ用意し、次の環境変数を設定します。

| 環境変数 | 指定する絶対パス |
| --- | --- |
| `OIMO_BROWSER_NODE` | Nodeの実行ファイル |
| `OIMO_PLAYWRIGHT` | Playwrightパッケージ |
| `OIMO_CHROMIUM` | Chromiumの実行ファイル |

```sh
mise exec -- go test ./internal/bootstrap \
  -run '^TestAdmin(OTPBrowser|PasskeyBrowser)$' -v -timeout=10m
```

試験は隔離サーバーを起動し、通常の管理URLと`/admin`配下の両方で画面を操作します。

| 試験 | 画面で確認する流れ |
| --- | --- |
| `TestAdminOTPBrowser` | OTP登録、パスキー再認証、パスワード単独認証の禁止、パスワード＋OTPでのログイン・再認証、制限解除、OTP削除 |
| 同試験の復旧操作 | 一時パスワードの発行、管理操作を制限したログイン状態、本人のパスワード変更、再ログイン |
| `TestAdminPasskeyBrowser` | 仮想認証器による登録、ログアウト、パスキーログイン・再認証、削除、再送拒否、保存復旧 |
| 同試験の失効確認 | 削除後のパスワードセッション・複製した再認証済みCookieで管理APIが401となり、パスワードで再ログインできること |
| 同試験の不正応答 | 署名・Origin・チャレンジ・本人確認フラグ・RPハッシュの変更、ログイン名・本人ID・鍵IDの不一致の拒否 |

OTPコードはNode標準cryptoで独立に計算します。QR検査用の環境変数も設定すると、幅320pxの画面のQRをスクリーンショットから復号します。実スマートフォンの認証アプリへの登録、実端末の指紋・顔認証の検証は含みません。

Playwright用Firefoxを用意して`OIMO_FIREFOX=1`を追加すると、Firefoxでも次を確認します。

- ログイン直後の登録拒否と再認証への案内。
- 再認証後の登録開始API成功と、ブラウザAPIへのバイト列変換。
- キャンセル時とエラー別の案内。

Firefoxの認証器APIは試験用にキャンセルするため、実認証器による登録完了は検証しません。`OIMO_PASSKEY_SCREENSHOTS`に出力先の絶対パスを指定すると、幅390px・2400pxで画面を保存し、両メニューのアイコンと横はみ出しも検査します。

## 管理認証の可用性とセッション上限

### 通常の回帰検査

```sh
mise exec -- go test -race ./internal/adminauth ./internal/bootstrap \
  -run 'TestLoginForm|TestPasswordAttemptsAreSourceScoped|TestSession.*Capacity|TestAdminPasswordFailures|TestAdminOTPWrongPassword|TestAdminOTPVerifiedPassword' \
  -timeout=10m
```

| 試験 | 確認すること |
| --- | --- |
| `TestLoginForm*` | 2万回の画面トークン発行後も利用できること。署名・期限・プロセス束縛・接続元制限・使用済み記録の最大9,600件 |
| `TestPasswordAttemptsAreSourceScoped` | 接続元ごとの1分5件と期限。時刻は注入して検査 |
| `TestAdminPasswordFailuresDoNotLockOtherSource` | WAF有効の隔離HTTPで、他の接続元の失敗が本人のログインを止めないこと |
| `TestAdminPasswordFailuresDoNotBlockReauthentication` | 同じ条件で、既存セッションの再認証を止めないこと |
| `TestAdminOTPWrongPasswordCannotLockOtherSource` | 誤ったパスワードが別IPの正しい二要素認証を止めないこと |
| `TestAdminOTPVerifiedPasswordStillLimitsCodeGuesses` | 正しいパスワードを確認した後は、OTP推測にアカウント共通制限がかかること |
| `TestSessionAccountCapacity` | 32件上限、最終利用順の失効、他の管理者への分離、失効済みセッションによる処理の拒否 |
| `TestSessionConcurrentAccountCapacity` | 同時作成でも32件を超えないこと |
| `TestSessionGlobalCapacity` | 全体10,000件の上限と、自分のセッション入替え・再認証時の件数維持 |

### 未認証の画面要求を並走させる検査

約200要求/秒・50秒間で1万回の画面要求を送るため、明示した場合だけ実行します。

```sh
OIMO_AUTH_AVAILABILITY_PROBE=1 mise exec -- go test ./internal/bootstrap \
  -run '^TestAdminLoginFormsUnderAnonymousFlood$' -v -timeout=3m
```

WAF有効の隔離HTTPへ未認証要求を送りながら、本人のOTPログイン・再認証・認証済み閲覧が成功することを確認します。インターネット回線の大規模DoS耐性を示す試験ではありません。

## 依存更新器の検証

```sh
python3 -B scripts/test_update_dependencies.py
```

外部コマンドを差し替え、Go指定の同期、検証失敗時の無変更、同時編集の保護、差分表示と検証済み反映を確認します。実際の新バージョンとの互換性は、更新器が実行する検証の結果で判断します。

提出案件の実ブラウザー検査は `TestAdminEvidenceSearchBrowser` です。ログイン・検索・状態・並び替え・次ページでの条件保持・検索解除と、幅320/390/800/1280pxの表示を確認します。
