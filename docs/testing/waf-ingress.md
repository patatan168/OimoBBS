# WAFのヘッダー・Host・宣言本文長の入口検査

2026-10-25〜26に実装・隔離検証しました。[仕様](../waf.md)と[検査・単体測定記録](waf-ingress.json)を参照してください。その後の[稼働反映](posting-waf-deployment.md)は別に記録しています。既存WAFスイッチに従い、既定の無効設定も維持しています。

## 追加した条件

| 対象 | 条件 |
| --- | --- |
| Host | 設定済み公開・管理originとそれぞれ照合。大文字小文字・標準portは既存規則で正規化。転送ヘッダーで補正しない |
| ヘッダー値 | NUL、CR、LF、HTAB以外のASCII制御文字、DELを拒否。Cookie・Authorizationにも構文・サイズ検査を適用 |
| User-Agent | 全値を合計して1,024byteまで |
| ヘッダー全体 | 名前と値の合計16KiB、解析後の値の数128まで。同名の複数値も数える。HostはGoの別フィールド |
| Content-Length | 負数・不正な十進数・overflow・解釈値との不一致等を拒否。公開64KiB、管理256KiBまで |

設定がそのIPやlocalhostならHostとして許します。文字列で一律に禁止する方式ではありません。小さいHost・宣言本文長の検査は頻度枠より前、従来の攻撃パターン検査は頻度制限の後で実施します。拒否時は固定403とno-storeを返し、本文・資格情報・規則名を記録しません。

HTTPで許されるHTABと非ASCIIのbyteを残し、本文の追加走査はしません。Cookie・Authorizationは攻撃パターン検査から従来通り除外します。これは[HTTPのfield valueの規則](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.5)に沿った構文検査です。

## 実HTTPの検査

公開・管理の実サーバー設定を使い、TCPへ直接HTTP/1を書き込んで確認しました。Go標準parserが先に拒否する入力と、WAFが拒否する入力を区別しています。

| 入力 | 結果 |
| --- | --- |
| 通常の公開・管理GET、HTAB入り値 | 成功 |
| User-Agent 1,024/1,025byte | 成功/403 |
| User-Agent 100KiB | Goの上限で431 |
| NUL・SOH・DEL入り値、重複Host | Goのparserで400 |
| 設定外Host、本文上限超過 | WAFで403 |
| 負数・64bit overflowのContent-Length | Goのparserで400 |
| 解析後128/129値 | 成功/403 |
| 通常のchunked投稿 | 投稿確認画面へ正常到達、WAF拒否数増加なし |

本文を送らず大きいContent-Lengthと`Expect: 100-continue`だけを送る試験でも、100応答や本文を待たず403で終了しました。HTTP/1では未受信本文がある拒否接続を閉じます。TLSのHTTP/2では拒否後に同じ接続で通常要求へ成功し、別streamを巻き込みません。

CRLFによって正当な別ヘッダーとなったbyte列から元の文字列の意図は復元できません。Goが同一値へ正規化する旧来の折返しや重複Content-Lengthも、WAFから元の行を再検査はできません。独自HTTP parserを追加せず、Goの解釈とアプリで見える値を検査します。未知長のchunkedは既存の本文読取り上限に従います。

## 回帰・コスト

全ASCII byte、複数値・秘密ヘッダー・境界値、設定済みIP/IPv6・標準port・Unicode類似文字、本文未読・頻度枠未消費を単体検査しました。関連raceを3回、ヘッダーfuzzを20秒・440,195実行、既存の要求全体fuzzを約11秒・85,712実行して通過しています。通常の投稿・閲覧の同時負荷は[投稿の測定記録](posting-multicore.md)を参照してください。

既存のフィルター単体benchmarkはGOMAXPROCS=2、100,000回×5試行の中央値で247.7→290.4ns、4B/opでした。追加は約43nsです。この値は外側のHost検査・ネットワーク・保存を含みません。整数表示の0allocs/opから毎要求の割当なしとは断定しません。頻度制限込みの値の揺れをWAF追加による高速化とも扱いません。

全体テスト・vet・ビルド・docs検査の結果はJSONに記録します。実インターネットからの経路、リバースプロキシとの解釈差、DDoS耐性、本番の正規ユーザーの全User-Agent・Cookie分布は未検証です。
