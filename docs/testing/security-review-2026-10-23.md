# Web脆弱性診断記録（2026-10-23）

## 結果と対象

OimoBBSの作業ツリーを、[OWASP WSTG v4.2](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/)の観点で調査した。ソースの確認、既存試験の再実行、攻撃入力の追加、隔離HTTP・TLS・Chromiumでの再現を組み合わせた。

確認した経路では、新しい悪用可能な脆弱性を再現しなかった。到達可能な既知脆弱性は、ソースと今回生成した実行ファイルの両方で0件だった。依存モジュール内にある未使用のOpenPGPの警告は、実行経路上の脆弱性と区別する。

対象はリポジトリ内の製品・検証ツールと、試験ごとに生成するデータ・loopbackサーバー。稼働サービス、既存の保存データ、公開ドメインへ攻撃要求は送っていない。診断結果は、別のイメージで動く本番の安全性を証明しない。

## OWASPとの対応と確認内容

「確認」は表に示した入力・経路での結果であり、WSTGの全手順を網羅した認定を意味しない。

| 観点 | 実施内容と結果 | 主な証跡となる試験・実装 |
| --- | --- | --- |
| CONF-04/05：秘密ファイル・管理経路 | `.git`、`.env`、設定、鍵、データ、バックアップ、pprof、管理APIなど26経路を実HTTPで推測。400/404で拒否し、通常の公開トップは200 | `TestWSTGPublicSensitivePaths`、`TestAdminHTTPPersistenceAndIsolation` |
| IDNT-04：アカウントの存在推測 | パスキー開始応答で既存・未知アカウントによる鍵一覧・本人IDの漏えいを拒否。応答時間の統計的な差は未評価 | `TestAdminPasskeyLoginDoesNotRevealAccount` |
| ATHN-03/09/10：推測・復旧・別認証方式 | 試行回数、パスワード＋OTP、使用済みOTP、パスワード単独禁止、一時パスワードの期限・再発行、耐久保存失敗時の認証拒否を確認 | `adminauth`、`admin_otp_security_test.go`、`admin_otp_twofactor_test.go`、`admin_auth_availability_test.go` |
| ATHN-10：パスキーの改ざん | Chromiumの仮想認証器で実署名を生成。署名、Origin、チャレンジ、RP、本人確認、ログイン時の本人ID・鍵を変更すると拒否 | `TestAdminPasskeyBrowser`、`scripts/test-passkeys-browser.mjs` |
| ATHZ-01：パスの曖昧さ | dot segment、重複スラッシュ、バックスラッシュ、パーセント符号化、NULを公開・管理入口で拒否 | `TestHTTPPathSecurityBoundary`、`FuzzCanonicalPublicPath` |
| ATHZ-02/03/04：権限逸脱・対象IDの差し替え | 管理担当・板管理者・サイト管理者、担当外と未知の板、私情報の追加権限を組み合わせる。再認証しても権限範囲を越えず、拒否要求が保存状態を変更しない | `TestAdminHTTPPrivilegeBoundaries`、`TestAdministratorRoleMatrix`、`TestPrivateReportsRequireExplicitPermission` |
| SESS-02/03/06/07：Cookie・固定化・失効 | Secure・HttpOnly・SameSite、経路別CSRF、再認証でのセッション交換、ログアウト・期限・認証世代変更、待機後・私情報送信時の再検査を確認 | `session_test.go`、`TestPublicAdminHTTPS`、`TestAdminQueuedSessionLogout`、`TestPrivateReportSendRechecksSession` |
| SESS-05：CSRF | null・外部・同一サイト別Origin、重複Origin、別経路の正規CSRFを拒否。Chromiumで別Originのフォームから有効なCSRF値を送っても403となり、サイト設定は不変 | `TestWSTGAdminMutationRejectsAmbiguity`、`TestWSTGBrowser` |
| INPV-01/02、CLNT-01：XSS・DOM注入 | 攻撃文字列を実際に投稿・通報。確認画面、保存後のスレッド、再読込、返信リンク生成、管理者の通報詳細で実行・実行可能DOM・外部通信が発生しないことを確認 | `scripts/test-wstg-browser.mjs`、`TestPostingHTMLRoundTrip`、`internal/webui/assets/thread.js` |
| INPV-03/04：操作・入力の取り違え | 方法別の権限検査に加え、重複CSRF・版・要求ID・Content-Type、未知JSONキー、大文字別名、重複・エスケープしたJSONキー、null・配列・余分なJSON・本文上限を検査。正当な更新を成功対照にする | `TestAdminHTTPPrivilegeBoundaries`、`TestWSTGAdminMutationRejectsAmbiguity` |
| INPV-15/17：HTTP解釈差・Host | 標準クライアントが補正する重複Host、矛盾したContent-Length、不正な本文長、未対応・重複Transfer-Encoding、重複Cookieなどを実socketで送信し拒否。正当な更新は成功 | `TestWSTGAdminRawHTTPBoundary`、`TestPublicOriginHost` |
| INPV-19：SSRF | URL制限、内部・共有・文書用・変換IP、公開と内部IPが混在するDNS回答、検査済みIPへの固定接続を検証。リダイレクト先も検査する実装を確認 | `TestNetworkHTTPSBoundary`、`TestNetworkSpecialAddresses`、`TestNetworkDNSDialBoundary`、`network_fetch.go` |
| ERRH：例外・情報漏えい | 管理失敗応答は固定メッセージ。秘密付き依頼照会は不正ID・不正秘密とも404。ログ・通常DTOからCookie、秘密、パスワード、投稿原本を除く経路を確認 | `TestDeletionReportsHTTPAndRestart`、`TestOptionalLogsProductLifecycle`、`admin_http.go` |
| CRYPST：暗号・TLS境界 | Argon2id参照ベクトル、OTPベクトル、バックアップ暗号の改変・切詰め拒否、mTLSの証明書固定・入口IPの検証。未許可・未提示client証明書を拒否 | `internal/adminauth`、`internal/sealedbackup`、`TestAuthenticatedEdgeTLSAndPosting` |
| BUSL：状態変更・再送・防御の悪用 | CAS・要求IDによる再送、権限変更・失効後の更新拒否、投稿・削除・復旧経路を通常試験で確認。匿名の画面要求1万件中も別接続元のOTPログイン・再認証・認証済み閲覧が成功 | `TestAdminLoginFormsUnderAnonymousFlood`、`TestAdminQueuedSessionLogout`、製品全体の通常試験 |
| その他の出力・資源境界 | CSV数式対策と列選択、HTTP/2の実TLS SETTINGS・stream/window上限、保存パーサーと展開処理のfuzzを確認 | `export_csv_test.go`、`TestPublicHTTP2SecuritySettings`、継続検査の8種のfuzz |

SQL・LDAP・サーバー側XML・シェル実行へのリクエスト入力経路は、対象のGo実装・依存関係の調査では見つからなかった。これは各種外部サービスを含む構成での非該当判定ではない。

## 発見事項と対応

### 未使用モジュールの警告

`govulncheck -show verbose` は [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) をモジュール単位で報告した。対象は `golang.org/x/crypto/openpgp`。今回の結果は「呼び出し経路0件・importされたパッケージ内0件・要求モジュール内1件」で、実行ファイルの検査でも到達する脆弱性は0件だった。

`x/crypto` はArgon2idなどに必要な依存関係なので削除していない。OpenPGPを新しくimportする変更が入った場合は再評価する。本番実行ファイルは今回検査していない。

### 既存テスト5件の前提のずれ

初回の全製品テストはbootstrapで5件失敗した。次の原因を確認し、検証コードを現行画面に合わせた。製品の入力検査・認可・HTMLは変更していない。

| 試験 | 原因と修正 |
| --- | --- |
| `TestMeaningfulPermissionAndRuleForms` | 日時欄が旧`datetime-local`を前提にしていた。現在の日時補助付きtext入力を検査 |
| `TestThreadSlipPolicyForm` | 投稿停止と表示設定のhidden値を混在させていた。送信する表示設定フォームだけを取得し、適用時は確認画面の値を送信 |
| `Test5chThreadIDSelection` | 同じフォーム混在。表示設定フォームだけを取得 |
| `TestSearchAndModerationHTML` | 日時補助の現在時刻で変わる別要求のHTML長を同一視していた。GETの実本文長と、HEADの本文なし・有効な長さを検査 |
| `TestAdminHTMLBoundary` | 未認証401でログインフォームを出す現行仕様に未追従。401・no-store・ログイン表示に加え、管理操作用要求ID・APIのCSRFヘッダーが出ないことを検査 |

修正後、5件を個別に再実行して成功した。以後の全件再検証は下の実行結果に記録する。

### 監査テストの直接追記と起動処理の競合

全bootstrapのrace検査では、`TestAuditSourceOperationDetails` のfixture生成が `repo.mu` を持たずに `ControlLog.Append` を呼び、起動時の回線更新による `State` 参照と競合した。製品の `refreshNetworks` は同じ所有mutexを取得しており、この競合はテスト側の直接追記から発生していた。

fixtureの状態取得から追記までを所有mutexで保護し、race付きで10回連続成功した。失敗した分割に属する54親試験も修正後にすべて成功した。同様の直接追記を行う `TestAdminAuditBrowser` も保護した。競合の初回ログも証跡として残し、製品の脆弱性修正とは区別する。

## 実行結果

- Go1.27.3、製品対象 `./cmd/... ./internal/... ./tools/...`。
- ソースと生成バイナリの既知脆弱性検査：到達する脆弱性0件。
- 既存の認証・公開境界などの重点race：70親試験、子試験を含む154件成功。ブラウザなど5件はこのrace実行ではスキップし、認証ブラウザは別実行。
- Chromium：パスキー、OTP、管理資産、セッション期限、再認証期限、追加したXSS・CSRF試験が成功。
- Chromiumの追加検査：通報フォーム、証拠検索、監査、レス管理、Bot状態、日時入力の6種類が成功。
- 8種のfuzz：各20秒、異常終了なし。保存されたseed corpusに加えて生成入力を検査。
- 匿名画面要求1万件／約50秒と、mTLS境界の隔離試験が成功。
- 全通常試験：bootstrapの860親試験を16分割に全件割り当て、837件成功・23件スキップ・失敗0件。子試験を含む成功は1,680件。他の41パッケージも成功または試験なし。
- 全race：bootstrapの860親試験を全件割り当て、初回は15分割が成功し、1分割で上記のfixture競合を検出。修正後、その分割の54親試験を再実行して成功。他の41パッケージも成功または試験なし。任意環境を指定しない試験のスキップを含む。
- 追加した56件のHTTP攻撃ケースとChromiumのXSS・CSRF検査は、race付きでも成功。追加WAFを有効化しないfixtureでも入力・認可・出力の保護を確認した。
- `go vet`、CGO無効の全製品ビルド、依存ポリシー・モジュール検証、文書・fixture、継続検査スクリプトの構文検査が成功。

最終集計は [JSON記録](security-review-2026-10-23.json) に保存する。生ログ・分割一覧・実行スクリプト・ログのSHA-256は、作業環境の `var/security-wstg-20261023/` に保存する。Gitには実行ファイルや生ログを含めない。

## 再実行と予防

新しい回帰試験は [wstg_security_test.go](../../internal/bootstrap/wstg_security_test.go) と [ブラウザスクリプト](../../scripts/test-wstg-browser.mjs)。[継続検査](../../scripts/check-security-continuous.sh)には、HTTPのWSTG試験、役割別権限、非公開依頼、ログアウト後の更新、パスキーの鍵所有者の検査を追加した。

```sh
mise exec -- go test -race ./internal/bootstrap -run '^TestWSTG' -count=1
mise exec -- bash scripts/check-security-continuous.sh
```

ブラウザ試験を含める場合は、[ブラウザ環境の指定](README.md#管理認証のブラウザ検査)を行う。全製品の通常試験・全race・静的検査は [共通チェック](README.md#実装全体を確認するとき)で再実行できる。

## 未検証と限界

- 本番の公開ネットワーク、実イメージ、Firewall、証明書、管理者アカウントの設定。パスキー・OTP・WAFが実環境で有効かは判定していない。
- 大規模DDoS、WAN、TLS接続を大量維持する攻撃、回線やホスト全体の飽和。1万件の試験は隔離したHTTPハンドラーへの制御された負荷で、外部からの耐性評価ではない。
- 実際の公開入口・中継・保存サーバーを連結した、全種類のHTTP/1・HTTP/2の要求密輸。今回の不正framing試験は管理HTTPサーバーへの直接接続。mTLSと公開proxyは別の試験で確認した。
- 実機認証器・各OS・Safari・Firefoxでの今回の攻撃再現。ブラウザ試験はChromiumの仮想認証器と隔離HTTPサイトで行った。
- 応答時間の統計解析、DNSの実攻撃基盤、外部クラウドの権限、実ホストの復旧訓練。

接続元別の推測制限は分散したIP全体を止める保証ではない。ソース上は、未認証者が他人を締め出すアカウント共通停止を設けず、正しいパスワードの確認後にOTPのアカウント枠を消費する設計である。運用時は[管理者認証の保護](../security-operations.md#管理者認証の保護)に沿って認証方式と制限を確認する。
