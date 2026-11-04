# 独自QUIC v1・HTTP/3の採用と検証

2026-11-03開始、2026-11-04更新。QUIC v1・HTTP/3・QPACKを独自実装へ切り替えた。
製品の `go.mod`・`go.sum` からquic-goとqpackを削除し、比較用client/backendは一時moduleでのみ使用する。
HTTP/3を有効にした場合の実装は独自版に統一した。既定の `public.http3: false` は維持し、稼働環境には反映していない。

## HTTP/2へのフォールバック

TCP/TLSのHTTP/2とUDPのHTTP/3は同じ公開portに併設する。
OSがUDPを確保できない起動はHTTP/2を継続し、HTTP/3を広告しない。
稼働中にUDP待受だけが停止した場合もTCPは継続し、以後のTCP応答は `Alt-Svc: clear` を返す。
正常なHTTP/3稼働中の広告は `h3=":公開port"; ma=60`。

ルーターのUDP到達性はOSのbind成功から判断できないため、自動有効化しない。
UDP未開放の環境は既定のままHTTP/2で動く。ルーター・UPnP・hostのファイアウォールを変更しない。

実Chromium140.0.7339.16で、通常のAlt-SvcによるHTTP/2→HTTP/3移行を確認した後、
loopback relayでUDPの両方向を黙って破棄した。
3回とも次のGETはHTTP/2へ自動再試行され、200・65,536byte・全本文SHA-256が一致した。
各試行の続く10件もすべてHTTP/2で成功した。最初の切り替えは3回とも約6.4秒で、瞬時ではない。
relayではUDPをそれぞれ10/18/18個破棄した。TCPとUDPの公開先portは同一で、暗号文は改変しない。

使い捨てprofileと短命の合成証明書を使用した。
SPKI例外と、実際には使わない `--origin-to-force-quic-on=localhost:1` を指定し、
未知rootの試験用例外をlocalhostに限定した。試験originの動的portは強制指定していない。
Chromiumの[未知rootの許可先構築](https://github.com/chromium/chromium/blob/main/net/quic/quic_session_pool.cc)と
[証明書判定](https://github.com/chromium/chromium/blob/main/net/quic/crypto/proof_verifier_chromium.cc)を確認した上で設定した。
一般の信頼storeや本番のTLS検証は変更していない。

これはGETの試験で、POSTの再送や全clientでの自動切り替えを保証しない。
HTTP/3専用clientにTCP fallbackをサーバー側から強制することはできない。

再現コマンドとfixtureの仕組みは[参照clientの検証手順](../../tools/quicreference/README.md)を参照。
実UDP停止と起動時のUDP競合は `internal/httptransport/http3_test.go` のrace試験でも確認した。

## 比較条件

[全試行・環境・hash](native-quic-20261103.json)に、最終比較と改善途中・不利な条件の結果を保存する。
測定中にrace試験・profile・脆弱性検査を並行実行しない。

- サーバーとGo clientは別コンテナ、それぞれ2CPU・512MiB。外部公開port・稼働volumeを使わない。
- Docker内部bridge、同時要求8、固定合成DAT、同じTLS証明書・圧縮・Range・帯域制御を使用。
- warm比較は接続を再利用し、用途ごとに期待本文を1回取得してから測定。coldは毎回新規接続で20件。
- status・protocol・応答全byteのSHA-256を全件で確認する。zstdは圧縮byteも同一である。
- 用途は304、非圧縮64KiB、zstd64KiB、1KiB Range、新規接続1KiB。
- 順序を各周で回し、3周の中央値を報告する。要求数・成功数・失敗数は合計も保存する。
- 通信量は仮想NICの送受信byte合計で、物理WANの通信量ではない。GSOがあるためNIC packet数をUDP datagram数とみなさない。

比較専用バイナリは外部HTTP/3 clientを含むが、製品バイナリは含まない。
移行前の記録のラベル `h3` は旧quic-go、`h3-native` は独自版。
採用後の記録では `h3-reference` が旧版、`h3` が独自版となる。
全試行のJSONには記録ごとの対応を明示する。

この合成配信は共通の送信予算を使用するが、実サイトの板検索・公開リース・認証・保存I/Oは含まない。
特に公開状態や閲覧権限を再検査する応答は、16KiBのI/O境界を保つため本文集約を使用しない。
その経路の性能を、この集約可能な合成DATの数値から推定しない。
実サイトのHTTP/3経路は別の結合試験で検証する。

## 採用後の最終比較

依存分離と期限切れの回帰修正を含む最終sourceで3周を測定し直した。
warm用途は各方式60,000件、coldは各方式60件、合計720,180件がすべて成功した。

| 用途 | HTTP/2 要求/秒 | 旧HTTP/3 要求/秒 | 独自HTTP/3 要求/秒 | 独自版CPU/要求 | 独自版p95 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 304 | 27,071 | 22,019 | 24,500 | 58.6µs | 0.556ms |
| 非圧縮64KiB | 4,891 | 3,819 | 4,077 | 317.7µs | 2.663ms |
| zstd64KiB | 11,507 | 11,132 | 11,938 | 126.0µs | 1.209ms |
| Range1KiB | 20,873 | 18,104 | 21,840 | 73.1µs | 0.694ms |
| 新規接続1KiB | 685 | 623 | 626 | 1,104.3µs | 1.859ms |

非圧縮64KiBは旧HTTP/3より約6.8%高速、サーバーCPUは約17.7%少ない。
HTTP/2のサーバーCPU317.3µsに対して同程度だが、要求/秒は約16.6%低く、目標は未達。
304は旧HTTP/3より約11.3%高速だがHTTP/2より約9.5%低い。
zstdとRangeは今回の中央値で両方式を上回った。新規接続のHTTP/3同士はほぼ同程度で、改善とは判断しない。

仮想NICの送受信byte/要求は、304がHTTP/2 185.7 / 旧HTTP/3 284.9 / 独自260.4、
非圧縮64KiBが67,394 / 67,828 / 67,984、zstdが11,719 / 11,635 / 11,662だった。
独自版は旧HTTP/3に対して304で約8.6%少ない一方、大きい本文ではわずかに多く、全用途で通信量が同等以下とはしていない。

以下の改善過程も残す。最終比較より良かった途中の数値を最終結果として置き換えない。

## 改善過程の非圧縮64KiB比較

本文集約まで適用した比較では、各方式90,000要求、合計270,000要求がすべて成功した。

| 方式 | 要求/秒 | サーバーCPU/要求 | p95 | 送受信byte/要求 |
| --- | ---: | ---: | ---: | ---: |
| HTTP/2 | 4,888 | 316.1µs | 2.466ms | 67,396 |
| 旧HTTP/3 | 3,884 | 385.8µs | 2.926ms | 67,834 |
| 独自HTTP/3 | 4,200 | 312.6µs | 2.496ms | 67,987 |

旧HTTP/3より約8.1%高速、サーバーCPUは約19%少ない。
HTTP/2との差は当初約19%から約14%へ縮まったが、要求/秒はまだHTTP/2に届いていない。
サーバーCPUはHTTP/2と同程度、p95の差は約1.2%。
Go client側のCPUはHTTP/2より多く、この結果からすべてのclientで同じ差が出るとは判断しない。

改善はHEADERSと最初のDATAの統合、実際のCID/stream IDに合わせたMTU内の充填、
再送用bufferへの直接コピー、暗号文の連続配置とGSO送信のコピー削減を含む。
本文が確定していて追加の公開・権限検査がない応答だけ、最大64KiBの専用領域へ集約する。
ストリーミング・明示Flush・権限検査付き応答は元の送信境界を保つ。

## 改善過程の304・圧縮・Range

集約後の比較は3周×20,000要求×3方式×3用途、540,000件すべて成功した。

| 用途 | HTTP/2 要求/秒 | 旧HTTP/3 要求/秒 | 独自HTTP/3 要求/秒 | 独自版CPU/要求 |
| --- | ---: | ---: | ---: | ---: |
| 304 | 26,559 | 22,468 | 25,875 | 57.2µs |
| zstd64KiB | 11,821 | 12,392 | 13,089 | 117.0µs |
| Range1KiB | 20,369 | 18,029 | 22,199 | 72.4µs |

zstd本文は65,536→11,007byte、約83.2%削減した。
HTTP/3でも共通配信層の `Accept-Encoding`・`Content-Encoding: zstd`・表現別ETagを使用する。
HTTP/3専用の別codecは持たない。304は本文なしだが、ヘッダー・ACK・TLS/QUIC・予約処理が残るため無料にはならない。

独立clientのaioquic1.7.2・LS-QPACKでも、要求/応答header、encoder/decoder stream、UDP payloadを別々に計測した。
短い304で無条件に動的表を使うとSectionACKの追加通信が削減を打ち消したため、応答の節約が小さい場合は動的表を使わない。
採用後の独立比較・暗号別検証は合計18,000件がすべて成功した。
最終3周の中央値は旧版2,217要求/秒、独自版2,143要求/秒で、独自版が約3.3%低かった。
UDP payloadは214.4→160.6byte/要求で約25.1%削減した。
改善途中の独立比較では独自版が速い試行もあったが、独立clientでの速度優位は再現が揃っていない。
Go client比較と独立client比較の指標を混ぜて優位を主張しない。全試行はJSONへ保存する。
Cookie/Authorization/Set-Cookieやnever-index指定の値を公開header cacheや動的表へ入れない。

## 資源上限と安全性

QUIC v1、HTTP/3 framing、QPACKを自前で実装する。TLS1.3はGo標準の `crypto/tls.QUICServer`、
AEADは標準暗号と固定版x/crypto、Huffman符号はx/netのprimitiveを使用し、暗号方式そのものを自作しない。

- sourceとCIDに結び付けた10秒Retry token、未検証送信元への増幅制限、接続総数/接続元別のadmission。
- 有限の受信窓、stream数、再構成segment、ACK履歴、送信/再送queue、QPACK表・blocked stream・header数/byte。
- handshake期限、idle期限、HTTP header/body/write期限、key update、AES128/256-GCMとChaCha20-Poly1305。
- critical streamの処理予算、未知stream数制限、誤ALPN・不正pseudo-header・control floodの拒否。
- TCPと同じhandler/ConnContext、実際のUDP/TLS接続情報、要求取消、正常shutdown時の受理済み応答とACKの待機。
- 公開・権限検査付き応答の16KiB境界を維持。期限更新を接続actorでも確認し、待機goroutineの起床前に
  flow creditが増えても、失効済みの残り本文を送信queueへ入れない。

期限切れとflow credit追加の順序競合は、修正前に失敗する決定的な回帰試験を作り、修正後にrace付き10回で通した。
取消済みのprepared本文は、queue投入前と実際のflow待ちの両方で止まることも確認した。

外部clientによる実UDP相互接続は、損失/重複、MTU1200への縮退、途中のMTU低下、IPv4/IPv6、
GSO非対応時の送信、鍵更新、同時送信での本文/Cookie混線防止、逐次stream回収、
小さい受信窓、Flush、HTTP shutdownを含む。
AES128/256-GCM・ChaCha20-Poly1305は独立clientで実際の交渉結果を検査した。
実サイトは投稿/返信・板分離・同意/cookie・DAT・条件付き/Range・再起動後の取得を別に確認した。

0-RTT、接続migration、HTTP Datagram、CONNECT/WebTransport、push、応答trailerは対応範囲外。
すべてのRFC適合試験、長期間のInternet運用、大規模DDoS耐性、WANでの速度優位は確認していない。

## 不利な条件・除外した試行

4CPU clientや32並列への変更だけでは、全用途の優位にならなかった。
client4CPU/2GOMAXPROCSでも差は残り、CPU quotaによるthrottlingだけでは説明できなかった。
これらの全結果もJSONへ残し、最良の1回だけを採用していない。

初期の独立client比較は短い304の過剰な動的表ACKで悪化した。
その結果と最終方針の比較を残す。

cold100件の試行は接続rate制限のburst64を超え、HTTP/2の64成功/36 EOFで停止した。
制限は緩和せず、全方式20件で比較し直した。
race試験と重複した性能測定は停止して集計対象外とした。

ブラウザー試験の初期設定ではEd25519証明書の非対応、圧縮overrideの解除、同一URLのcache lock、
自己署名rootの拒否、localhostのIPv6/v4不一致があった。これらを性能結果に含めていない。
強制HTTP/3での旧版/独自版各1,000件は成功したが、NetLog付きの診断であり性能比較には使わない。
同時期のHTTP/2試験は994成功/6件 `ERR_NETWORK_CHANGED` で、成功した試行として扱わない。
最終fallback試験はネットワーク作成後に安定を待ち、新しいprofileと本文hashを用いて確認した。

## 再現と記録

```sh
python3 scripts/probe-http3.py \
  --output var/native-quic-20261103/adopted-performance \
  --protocols h2,h3-reference,h3 --requests 20000 --rounds 3 \
  --workloads 304,identity64k,zstd64k,range1k,cold1k
python3 scripts/compare-native-http3.py \
  --python var/quic-native-venv/bin/python --requests 2000 --rounds 3 \
  --all-ciphers --key-update --output var/native-quic-20261103/adopted-independent
```

製品の通常build・race/vet・許可依存検査と、外部clientを一時moduleで追加する相互接続raceを分ける。
header/reassembly/varint/QPACKのfuzzも実行する。
関連製品packageと実サイト経路のrace、4種のfuzz各5秒、Go vet、全製品packageのCGO無効build、
455packageの依存検査、文書検査が通った。リポジトリー全体のraceはこの変更では再実行していない。
固定版の脆弱性検査でsourceとCGO無効のoimobbs/oimoedgeを別々に確認し、いずれも検出0件。
検証toolの外部依存は製品に戻していない。
試行ごとの生出力・server log・失敗ログは `var/native-quic-20261103/` に保持する。
