# HTTP/3の送信失敗・経路応答の追加防御

2026-11-04。[前回の性能・鍵管理強化](http3-more-20261104.md)を含む作業ツリーから追加修正した。
HEADは`55bfb9b`で、過去2回の未コミット変更も維持している。稼働設定や稼働データへの変更は含まない。

## 再現と修正

| 対象 | 修正前の再現 | 修正後 |
| --- | --- | --- |
| sender失敗 | 暗号化後にsenderへ渡せず、同じ接続状態で次の送信を行うと同じnonceを再使用した | 暗号化前に送信番号を確保し、失敗しても番号を戻さない |
| 送信履歴の上限 | 1024件の履歴を持つ状態でMTU試行→ACK送信を行うと、暗号化済み2packetが同じnonceでqueueに入った | 履歴の上限は暗号化・queue投入より前に検査。MTU試行は送らず、ACKは未使用の番号で送信する |
| 送信番号の枯渇 | 最大値の番号を送れた。終了後も別の番号空間で暗号化を試み得た | 上限到達で接続を取り消し、取消済みの接続は暗号化を開始しない |
| 経路応答のサイズ | 実TLS・UDPでPATH_CHALLENGEへ36byteで応答した | PATH_RESPONSEを含むdatagramを1200byte以上にする。CID長とpacket番号長が変わっても最小長を維持する |
| 経路応答の再送 | 損失検出とPTOで同じPATH_RESPONSEを再送した | 経路応答を再送対象から外す。ACK待ちのbyte数と輻輳制御は維持し、PTOでは新しいPINGを使う |
| 経路応答の反復 | 9個のPATH_CHALLENGEを受け入れた | 接続ごとに瞬間8件・毎秒1件補充まで。超過は`INTERNAL_ERROR`で接続を終了する。HTTP要求や長い待機で枠を無制限に増やせない |
| 旧鍵の破棄時刻 | 20ms後の破棄期限があっても、次のtimerが約1秒後になった | 旧鍵の期限もtimerの起床候補へ含める |

nonceは鍵ごとに重複させてはいけない暗号入力で、QUICではpacket番号から生成する。
送信失敗・履歴上限の再現は、試験内でsender障害と履歴の境界状態を注入したもの。
実稼働での攻撃成功を確認した記録ではない。

経路応答は通常のSTREAM・CRYPTO・FIN等と再送の扱いが異なるため、queue内で区別する。
同じpacketへまとめる際も再送可能なframeとは分離し、損失時に本文まで失うことや、
応答だけを無制限に再送することを防ぐ。未確認byteは送信履歴に残し、ACKまたは損失で回収する。

## 実通信と検証

独立したQUIC clientとnative listenerの間に、復号・改変をしないloopback UDP relayを置いた。
短命の試験TLS接続のtraffic secretを試験内だけで保持し、認証されるPATH_CHALLENGEを同じ実endpointから送る。
製品へ鍵の記録機能を追加する変更はない。

通常の試験では、1200byte以上のPATH_RESPONSEを暗号認証して確認する。
その応答をclientへ返さず、PTOで同じ応答が再送されず、新しいPINGが届くことまで確認する。
過剰入力の試験では9frameを送信し、認証された接続終了frameのcodeが`INTERNAL_ERROR`になることを確認する。
修正前の実UDP試験は36byte応答で失敗し、修正後は通常・過剰入力の双方がrace付き3回成功した。

単体試験では実際のAEAD呼出しのnonceを監査し、失敗後と履歴上限後の重複が消えたことを確認した。
番号上限、全番号空間の停止、旧鍵timer、応答creditの補充・最大値、
CID長0/8/20byteとpacket番号長2/4byteでのpaddingもrace付き3回検証した。

関連5packageのraceを3回、外部QUIC相互接続を8packageで実行した。
損失・重複、MTU縮退、小さい受信窓、鍵更新、通常の並行応答、POST・Cookie・Range・gzip、
取消後の処理枠、直結・mTLS中継のWAF、HTTP/2への退避を含む既存試験も対象にした。
全製品・toolのvet、CGO無効build、依存検査455packageも成功し、公式DBの検査では既知の脆弱性は検出されなかった。
製品の`go.mod`・`go.sum`は変更していない。

送信状態列・鍵更新状態列・QUIC frameを各30秒・2workerでfuzz検査し、合計1,012,075入力で
nonce重複・panic・検査対象の資源枠違反を検出しなかった。内訳は送信状態列304,891、
鍵更新状態列313,246、QUIC frame393,938入力である。

## 再実行と記録

```sh
mise exec -- go test -race ./internal/quicv1 ./internal/http3native ./internal/httptransport ./internal/delivery ./internal/publicedge -count=3
python3 scripts/quic-reference.py test -- -race -timeout=30s ./internal/quicv1 \
  -run '^TestQUICPathResponseOverRealUDP$' -count=3 -v
mise exec -- go test ./internal/quicv1 -run '^$' -fuzz '^FuzzSendStateSequence$' -fuzztime=30s -parallel=2
```

生出力は`var/http3-send-security-20261104/`に保存した。
`before.log`・`nonce-before.log`・`path-before-real-udp.log`・`path-flood-before.log`・`cancel-before.log`が修正前の失敗、
`targeted-final.log`・`race-final.log`・`interop-final.log`・`path-final.log`が修正後の確認である。
修正前の対象sourceとhashは`before/`に退避し、Git履歴や作業中のsourceを戻さずに比較した。
`fuzz-final.log`には送信状態列・鍵更新状態列・QUIC frameのfuzz結果を保持する。
送信状態列の対象は継続検査の`check-security-continuous.sh`にも追加した。

## 根拠と限界

[RFC 9000の送信番号](https://www.rfc-editor.org/rfc/rfc9000.html#section-12.3)、
[経路応答](https://www.rfc-editor.org/rfc/rfc9000.html#section-8.2.2)、
[再送する情報](https://www.rfc-editor.org/rfc/rfc9000.html#section-13.3)、
[RFC 9001のAEAD入力](https://www.rfc-editor.org/rfc/rfc9001.html#section-5.3)を確認した。
暗号primitiveとTLSは従来の標準実装を使い、新しい暗号方式は導入していない。

WANの帯域飽和・分散攻撃・実NIC・本番負荷での耐性は未検証。
今回はセキュリティの回帰検証で、変更前後の速度・CPU・通信量の比較は実施していない。
前回の性能測定値を今回の追加修正後の実測値としては扱わない。
