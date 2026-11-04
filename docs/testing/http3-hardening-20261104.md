# 独自HTTP/3の追加強化

2026-11-04。変更前の基準は`55bfb9b`。loopbackの短命証明書と使い捨てQUIC接続で検証した。
実装は`internal/quicv1`と`internal/http3native`で、外部clientは一時module内だけに追加する。
稼働環境の反映・設定変更は含まない。

## 再現と変更

| 対象 | 修正前の再現 | 修正後 |
| --- | --- | --- |
| 取消の反復 | handlerが取消後も実行中の場合、同じ接続で33件目を開始できた | header読取からhandler終了まで接続32件に制限。超過は`H3_EXCESSIVE_LOAD` |
| 接続の開き直し | 8接続で32件ずつ処理を残して接続を閉じた後、257件目を開始できた | 接続終了後も処理を待受全体256件の枠に保持する |
| 要求field | 空のHostと別のHostの重複、値の先頭SP・末尾HTABを受け入れた | Hostの存在と値を別に数え、前後のSP/HTABを拒否する |
| trailer | `connection`・`transfer-encoding`・`authorization`・`te`・`trailer`を受け入れた | 禁止fieldを拒否し、全fieldの検証後にだけ`Request.Trailer`へ反映する |
| 本文エラー | 不正なtrailerを読んだ後にもう一度読むと、エラーがEOFに変わり得た | 最初の失敗を保持し、以降のReadにも同じ失敗を返す。受信も停止する |
| 禁止frame | HTTP/2用の予約番号2・6・8・9を、要求header前・本文・制御streamの12パターンで無視した | `H3_FRAME_UNEXPECTED`で接続を終了する。本文では読取時に検出する |
| 設定・片方向stream | 予約済みSETTINGSのID 0と、client開始のpush streamを受け入れた | 予約設定を拒否し、clientのpush streamは`H3_STREAM_CREATION_ERROR`で終了する |
| 既存CIDへのUDP入力 | 未対応versionと1200byte未満のInitialが復号queueに入った | 状態を変更せず破棄する。併合datagramのInitialは全体長で判定し、後続packetにもRetry前の頻度枠を適用する |
| 空の受信断片 | offsetだけを持つ空区間が保存され、後続の連続dataの読取を妨げ得た | 空区間を保存せず、受信creditと最終長の検証は維持する |

正常な未知拡張frameの読み飛ばし、Cookie・POST・Range・圧縮・16KiB field上限、
既存WAF経路とHTTP/2への退避は維持する。
要求本文の処理量超過は既存どおり受信を止め、handlerが400を返せる。
不正なframe順序やQPACKの復号失敗は、単なるEOFとして扱わず接続エラーにする。

## 検証

新しい不正入力は変更前に失敗を再現し、修正後に同じ入力で拒否を確認した。
追加の全体枠・push・予約設定・空区間の再現は、基準版の対象sourceを一時moduleへ戻して実行した。
作業中の製品sourceやGit履歴を戻す操作は行っていない。

実QUICの追加回帰試験はrace付き3回成功。
32件のhandlerを戻さずstreamを取り消す試験と、256件を戻さず接続だけを閉じる試験を含む。
通常の32並行・320要求も、同じQUIC接続で全件成功することを3回確認した。
不正trailerの400応答後、同じ接続で分割Cookie・POST本文・Rangeヘッダー・正常trailerを読み、
handlerの206・gzip応答を復号して本文の一致まで確認した。
通常の相互接続試験はQUIC・HTTP/3・transport・publicedge・evidence・bootstrap・公開コマンド・配信測定toolの8packageで成功。
直結とmTLS中継のWAF拒否、同一接続の継続、通常POST、並行応答、損失・重複packet、鍵更新、HTTP/2関連の既存試験も対象にした。

既存のpacket header・再構成・QPACK field復号に加え、状態をまたぐ受信再構成、
認証後のQUIC frame、QPACKの両方向の制御命令をfuzz対象へ追加した。
新しい対象は`check-security-continuous.sh`にも登録した。

6種類を各30秒、2workerで実行し、合計2,074,533入力でpanicと検査対象の資源枠違反を検出しなかった。

| fuzz対象 | 入力数 |
| --- | ---: |
| packet header | 487,324 |
| 単一の受信断片 | 471,698 |
| 受信断片の反復 | 724,665 |
| 認証後のQUIC frame | 108,999 |
| QPACK field section | 103,917 |
| QPACK制御命令 | 177,930 |

`go vet`、CGO無効build、依存検査455package、Go公式DBを使う`govulncheck`は成功し、既知の脆弱性は検出されなかった。
製品の`go.mod`・`go.sum`に変更はない。

再実行の例:

```sh
mise exec -- go test -race ./internal/quicv1 ./internal/http3native ./internal/httptransport ./internal/delivery ./internal/publicedge
python3 scripts/quic-reference.py test -- -race -timeout=5m \
  ./internal/quicv1 ./internal/http3native ./internal/httptransport ./internal/publicedge \
  ./internal/evidence ./internal/bootstrap ./cmd/oimobbs ./tools/httptransportbench \
  -run 'HTTP3|QUIC|QPACK|Prepared|Buffered|ControlFlood|WrongALPN|FirstData|Concurrent.*(Response|Bodies)|RequestFields|SiteWeb.*BoardsAndIsolation|ClientTrace'
mise exec -- go test ./internal/quicv1 -run '^$' -fuzz '^FuzzQUICFrames$' -fuzztime=30s -parallel=2
mise exec -- go test ./internal/quicv1 -run '^$' -fuzz '^FuzzReassemblySequence$' -fuzztime=30s -parallel=2
mise exec -- go test ./internal/http3native -run '^$' -fuzz '^FuzzQPACKInstructions$' -fuzztime=30s -parallel=2
```

作業時の直接出力は`var/http3-hardening-baseline-{unit,interop,extra}.log`、
`var/http3-hardening-targeted-final.log`、`var/http3-hardening-interop-final.log`、
`var/http3-hardening-fuzz.log`、`var/http3-hardening-{vet,build,deps,vuln}.log`に保存した。
`var`はGit管理外で、移植可能な回帰入力はテストsourceとfixtureに保持する。

## 根拠と限界

入力の扱いは[RFC 9000のInitial最小長](https://www.rfc-editor.org/rfc/rfc9000.html#section-14.1)、
[RFC 9114の不正要求](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1.2)、
[禁止frame](https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.8)、
[fieldの中継時の検査](https://www.rfc-editor.org/rfc/rfc9114.html#section-10.3)を確認した。
暗号primitiveとTLSはGo標準および既存の暗号ライブラリーを使用し、今回新しい暗号方式は導入していない。

これは指定入力と隔離通信での検証である。WANのUDP flood、実回線の帯域飽和、
分散攻撃、実稼働での耐性、速度・CPU・通信量の変更前後比較は未検証。
有限時間のfuzzや既知脆弱性検査は、独自実装全体の安全性を保証しない。
