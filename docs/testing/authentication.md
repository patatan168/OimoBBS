# 管理認証・権限の検証

ロール、OTP、パスキー、復旧とセッション上限を確認する手順です。[共通の準備と確認範囲](README.md)を先に確認し、コマンドはリポジトリのルートで実行します。

## 手順を選ぶ

- [管理認証と権限](#管理認証と権限)
- [管理者権限](#管理者権限)
- [管理者OTPと一時パスワード](#管理者otpと一時パスワード)
- [管理画面のパスキー](#管理画面のパスキー)
- [管理認証のブラウザ検査](#管理認証のブラウザ検査)
- [管理認証の可用性とセッション上限](#管理認証の可用性とセッション上限)

## 管理認証と権限

### 管理者権限

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

### 管理者OTPと一時パスワード

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

#### 登録用QRの検査

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

### 管理画面のパスキー

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

### 管理認証のブラウザ検査

[ブラウザー検査の準備](README.md#ブラウザー検査の準備)を済ませてから実行します。

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
- キャンセル時とエラー別の案内、幅390pxで失敗理由が画面内に表示されること。
- 認証器からの応答が空の場合の案内と、端末応答後の登録確認・サーバー拒否時の再操作。

Firefoxの認証器APIは試験用のキャンセル・空応答・疑似応答へ置き換えるため、実認証器による登録完了は検証しません。`OIMO_PASSKEY_SCREENSHOTS`に出力先の絶対パスを指定すると、幅390px・3200pxで画面を保存し、両メニューのアイコンと横はみ出しも検査します。
`OIMO_FIREFOX_EXECUTABLE`を指定すると、試験に使うFirefox実行ファイルを明示できます。

### 管理認証の可用性とセッション上限

#### 通常の回帰検査

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

#### 未認証の画面要求を並走させる検査

約200要求/秒・50秒間で1万回の画面要求を送るため、明示した場合だけ実行します。

```sh
OIMO_AUTH_AVAILABILITY_PROBE=1 mise exec -- go test ./internal/bootstrap \
  -run '^TestAdminLoginFormsUnderAnonymousFlood$' -v -timeout=3m
```

WAF有効の隔離HTTPへ未認証要求を送りながら、本人のOTPログイン・再認証・認証済み閲覧が成功することを確認します。インターネット回線の大規模DoS耐性を示す試験ではありません。
