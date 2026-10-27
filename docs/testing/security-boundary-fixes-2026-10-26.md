# 認可・WAF・ドメイン規制の境界修正（2026-10-26）

未認証からの管理者昇格とWAFの迂回を調査し、隔離環境で再現した4件を修正しました。対象は作業ツリーの製品コードです。本番サービスの置換・攻撃試験は行っていません。

## 修正した問題

| 問題 | 修正後の動作 | 回帰検査 |
| --- | --- | --- |
| 自動通報の確認経路では、記録権限だけで非公開通報理由を再認証なしに取得できた | 原本閲覧には10分以内の再認証を要求。非公開通報理由には削除依頼の権限も要求し、不足時は理由を伏せる | `TestAdminAutoReportsMixedVotesPermanentAndRecovery`、`TestAdminAutoReportsPermissionBoundaries` |
| 自動通報の原本応答では、取得後のログアウトを本文送信へ反映しなかった | 帯域待ち後・送信片ごとにセッション・担当板・追加権限・原本の保持期限を検査して中断する | 同上の実ハンドラーによるヘッダー確定時の失効試験 |
| ドメイン規制とブラウザーで、同じ宛先を指すURLの解釈が異なった | Unicodeドット・全角・国際化ドメイン・percent符号化・特殊なIPv4表記・逆スラッシュをブラウザーのURL規則で解釈する | `TestContentRuleBoundaries`、`TestDomainRuleAliasesHTTPAndGlobal` |
| 管理資産URLに埋め込んだ表示元ページは、復号後のWAF検査を通らなかった | 内部の表示元ページにもWAF検査を適用。認証QRなどHTML以外の処理を資産の表示元として実行しない | `TestWAFAdminAssetSourceInspection` |

ドメイン規制の実HTTP試験では、WAFを有効にした投稿受付で `example。test`・`%65xample.test` などの拒否と、無関係の宛先の受理を確認しています。全板共通規制も同じ条件を確認しました。宛先の解析・IPv4表記・UTS #46・NFC・Punycodeは標準ライブラリーと自前コードで実装しています。外部のGo依存は追加せず、外部へのDNS/HTTP照会も行いません。Unicodeの公式変換表の出典・固定ハッシュ・ライセンスは [Unicodeデータ](../../third_party/unicode-urlhost/README.md)を参照してください。

新しいURL判定は復旧時にも適用します。旧判定で記録された追加投稿枠の集合と新判定が一致しない場合は、破損として復旧を拒否します。既存データとの互換性を維持する分岐は追加していません。

## 未認証の昇格・WAF全体の迂回の検査

- 管理経路50種類、GET/POST/PATCH/HEAD、7種類のCookie・偽装情報、WAFのON/OFFによる2,800要求を拒否。管理セッションの発行、サイト状態の変更、WAFの無効化なし。正常なログインと管理API取得も成功対照として確認。
- パスキーの登録・ログイン・再認証・削除をChromiumの仮想認証器で確認。署名・Origin・チャレンジ・本人確認フラグ・RP・本人ID・鍵IDの改変を拒否。OTPの二要素・再送、期限切れや失効済みセッション、一時パスワードの制限は既存試験でも検査。
- loopback HTTP、公開パスHTTP、管理HTTPSのHTTP/1・HTTP/2、mTLS公開パスのHTTP/1・HTTP/2の6通りで、経路・メソッド・転送ヘッダーを変えてもWAF検査が適用されることを確認。頻度拒否で検査漏れを覆わないよう、この試験では大量アクセス制限を停止。頻度・同時処理は既存のWAF試験で別に検査。
- 自動通報の再認証案内を320px・1024pxで表示し、再認証前の原本フォーム非表示、再認証から元の画面への復帰、原本確認の送信までChromiumで確認。
- URLホストの54例を実Chromiumの解釈と照合。Unicode公式の正常なIDNA変換549例、NFC検査20,034例・各5列、SHA-256を固定した生成表も照合。

上記の条件では、未認証からの管理者昇格とWAF全体の迂回は再現していません。WAFの本文検査除外、公開入口自身のヘルスチェックなど、仕様上の適用範囲を全面的な防御とみなすものではありません。

## 再実行

```sh
mise exec -- go test ./internal/bootstrap -run \
  'Test(UnauthenticatedAdminRouteMatrix|AdminAutoReports|WAFTransportRouteCoverage|WAFAdminAssetSourceInspection|ContentRuleBoundaries|DomainRuleAliasesHTTPAndGlobal)' -count=1
mise exec -- go test -race ./internal/bootstrap -run \
  'Test(UnauthenticatedAdminRouteMatrix|AdminAutoReports|WAF|ContentRuleBoundaries|DomainRuleAliasesHTTPAndGlobal)' -count=1
```

[ブラウザー検査の環境変数](README.md#ブラウザー検査の準備)を設定すると、次の試験も実行できます。

```sh
mise exec -- go test ./internal/bootstrap -run \
  '^Test(AdminAutoReportSecurityBrowser|AdminPasskeyBrowser|WSTGBrowser)$' -count=1 -v
```

直接の観測出力は `var/security-spec-review-20261026/` に保存しています。bootstrap以外の製品・検証ツールの通常試験と、bootstrapの認証・権限・WAF・HTTP関連試験、対象のrace、WAFと自前ホスト解析のfuzz、vet、CGO無効ビルド、依存固定・文書検査を実施しています。bootstrap全件を含む一括試験は未完了です。既知脆弱性検査は到達可能な問題0件で、使用していない既存依存モジュール内の1件は別に報告されています。
