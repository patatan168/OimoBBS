# HTTP/3のWAF・DoS対策検証

2026-11-04。loopbackの使い捨て設定・データ・証明書で検証した。稼働環境への反映や設定変更は行っていない。

## 結果と修正

HTTP/3の公開・管理受付はTCPと同じ製品ハンドラーを通り、WAF自体を省く経路は見つからなかった。
一方、HTTPより手前に以下の処理量制限の不足があり、修正した。

| 対象 | 修正前の再現 | 修正後 |
| --- | --- | --- |
| Retry・Version Negotiation | 未知CIDの1200byte packetを512件送り、512応答・512送信。約43msで既存の接続頻度制限を通らず応答した | token検証・暗号処理・応答前に独立した全体/回線別の頻度枠を適用。512入力で290応答・290送信、約539ms。その期間の回線枠291以内 |
| 空frame | ヘッダー前の未知frame、本文の空DATA、本文の未知frameを各1025件送信。通常の204応答まで到達した | frameヘッダーも処理枠に計上。ヘッダー前は`H3_EXCESSIVE_LOAD`で接続終了、本文受信ではエラーを返してhandlerが400応答 |
| 制御枠の補充 | 不正な`:scheme`の要求を32件開閉した後、128KiBのQPACK decoder入力を送っても処理枠の超過を検出しなかった | 要求ヘッダーの検証後に補充する。空stream・不正要求で増えず、同じ入力を`H3_EXCESSIVE_LOAD`で拒否 |

packet試験の応答数はtoken bucketの補充を含む。要求/秒の性能比較ではない。
未検証入力への上限は[WAFのHTTP/3適用範囲](../waf.md#http3での適用)を参照。
送信元を偽装したUDP入力も想定して記録数を制限するが、実回線のUDP floodや回線帯域の飽和は試験していない。
処理量を制限する方針は[RFC 9000のDoS考慮事項](https://www.rfc-editor.org/rfc/rfc9000.html#section-21.1)と
[RFC 9114の資源枯渇対策](https://www.rfc-editor.org/rfc/rfc9114.html#section-10.5)も確認した。

## 実HTTP/3のWAF経路

製品の`ValidationHTTPServer`を使い、直結と「公開HTTP/3 → mTLSのHTTP/2 → 保存側」の両構成を検査した。
一つのQUIC接続を再利用し、client側の再接続で障害を隠さない。

- 公開・投稿・検索・削除依頼・管理ログイン・管理API・管理資産・存在しないURLの9経路をGET/POST/HEADで通し、1KiB超のUser-Agentを全件403で拒否。
- さらに未送信の64KiB本文を持つ投稿も403。各構成のWAF遮断集計は28件。
- 回線別の同時枠を埋めると429、別回線で全体枠を埋めると503。`Retry-After`と`Cache-Control: no-store`を確認。
- 本文を一切送らない要求でも、clientの2秒期限内に拒否応答と本文を読み終える。保存側の本文受信期限は10秒。
- 拒否中・拒否後も同じQUIC接続から管理ログイン画面を200で取得し、処理枠の残留がないことを確認。
- 偽の`X-Forwarded-For`と`X-Oimo-Client-IP`でも回線枠を回避できない。

接続前の単体試験では、IPv6 /64の共有、全体枠、未検証入力とTLS admissionの独立、
拒否時の無応答・接続未生成、既存CIDのpacketが未検証枠を消費しないことも確認する。

## 再実行

外部QUIC clientは[固定バージョンの一時module](../../tools/quicreference/README.md)へだけ追加する。
製品の`go.mod`・`go.sum`は変更しない。

```sh
mise exec -- go test -race ./internal/delivery ./internal/quicv1 \
  ./internal/http3native ./internal/httptransport ./internal/waf ./internal/publicedge
python3 scripts/quic-reference.py test -- -race -count=3 -timeout=5m \
  ./internal/bootstrap ./internal/http3native ./internal/httptransport ./internal/quicv1 \
  -run 'TestWAFHTTP3|TestHTTP3EmptyFrame|TestHTTP3InvalidRequests|TestHTTP3Unvalidated|TestUnvalidatedGate' -v
python3 scripts/quic-reference.py test -- -race -timeout=5m \
  ./internal/quicv1 ./internal/http3native ./internal/httptransport ./internal/publicedge \
  ./internal/evidence ./internal/bootstrap ./cmd/oimobbs \
  -run 'HTTP3|QUIC|QPACK|Prepared|Buffered|ControlFlood|WrongALPN|FirstData|Concurrent.*(Response|Bodies)|RequestFields|SiteWeb.*BoardsAndIsolation|ClientTrace'
```

通常の投稿・返信・板分離・DAT・条件付き/Range・再起動後の取得、損失・MTU縮退・小さい受信窓、
並行応答の混線防止、UDP停止後のHTTP/2継続、shutdown、接続観測を含む関連race試験が通った。
新しい回帰試験はrace付き3回ですべて通過した。関連相互接続の親試験43件、既存WAF・HTTP/2の関連試験、
関連packageのvet、全製品packageのCGO無効build、455packageの許可依存検査、文書検査も通過した。
bootstrapを含むリポジトリ全体の試験、大規模/分散DoS、WAN・実機、本番のWAF有効状態は今回の確認範囲に含めない。

## 生出力

`var/http3-security-20261104-*`に保持する。

- `baseline.log` / `baseline.json`: 修正前`f8d57ea`の製品sourceに新しい回帰試験を適用した失敗出力と対象file。
- `product.log` / `final.log`: 製品packageのraceと、外部clientを使った関連相互接続race。
- `regressions.log`: 新しい回帰試験のrace付き3回実行。
- `waf.log` / `vet.log` / `deps.log`: 既存WAF・HTTP/2試験、静的検査、許可依存検査。

`initial.log`は最初の経路検証。`interop.log`は全bootstrap試験まで含めた起動を中断した記録で、完走結果には使わない。
