# 外部QUIC clientを使う検証

製品のQUIC v1・HTTP/3・QPACKは `internal/quicv1` と `internal/http3native` が実装する。
製品の `go.mod`・`go.sum`・配布バイナリにはquic-goとqpackを含めない。

相互接続試験では、[固定バージョン](dependencies.json)の外部clientを一時moduleにだけ追加する。
`.go.txt` は一時moduleへ展開する試験fixtureで、製品の通常buildではGo sourceとして扱わない。
外部検証依存のライセンスは [NOTICES.txt](NOTICES.txt) に分離して保持する。
比較専用backendは移行前のコミット `ed658630541b12e5ba840443832ece8121e85f00` の実装を保存したもので、製品から選択できない。

```sh
python3 scripts/quic-reference.py test -- -race -timeout=5m \
  ./internal/quicv1 ./internal/http3native ./internal/httptransport \
  -run 'QUIC|HTTP3|QPACK|Prepared|Buffered|ControlFlood|WrongALPN|FirstData|Concurrent'
python3 scripts/quic-reference.py build-benchmark --output var/httptransportbench
```

buildは製品source・fixture・実行バイナリのSHA-256と外部clientのバージョンを
`var/httptransportbench.reference.json` へ記録する。参照用バイナリだけには外部ライブラリーが含まれる。
一時moduleは終了時に削除し、元の `go.mod`・`go.sum` は変更しない。
稼働データ・秘密設定・`var` 内の使い捨てsourceは複写しない。

`python3 scripts/probe-http3.py --protocols h2,h3-reference,h3` で同条件の比較を行う。
`h3` は製品と同じ独自実装、`h3-reference` は比較専用の旧実装を表す。
`h3-native` は `h3` の別名としてのみ残す。移行前の測定記録の `h3` は旧実装なので、記録の日付・環境情報を確認する。

独自実装の変更前後は、変更前のsourceで作ったバイナリと隣の `.reference.json` を保存し、
`--baseline-binary` と `h3-baseline,h3` を指定して交互に比較する。
両サーバーへ同じ変更後のclientを使い、各バイナリ・製品sourceのhashを測定記録へ残す。

```sh
python3 scripts/probe-http3.py --output var/http3-paired \
  --baseline-binary var/http3-before/httptransportbench \
  --protocols h3-baseline,h3 --requests 30000 --rounds 4 \
  --workloads 304,identity64k,zstd64k,range1k,cold1k
```

UDP遮断時の実ブラウザー確認は次で実行する。使い捨てChromium profile、短命証明書、loopback relayと
外部接続のないDocker networkだけを使い、hostの証明書store・ルーター・ファイアウォールは変更しない。

```sh
python3 scripts/probe-http3-fallback.py --chrome /path/to/chromium --node /path/to/node
```

通常のAlt-Svc経由でHTTP/3へ切り替わった後にUDPだけを捨て、HTTP/2応答のstatus・全本文hash・protocolを検査する。
Chromiumの未知root制限に対して、短命証明書のSPKIと試験で使わない `localhost:1` のみを例外指定する。
試験originのportにHTTP/3を強制しない。TCP/UDPは同じ公開portへ中継し、暗号文を復号・改変しない。
これはGETの試験で、POSTの自動再送や全ブラウザーの挙動を保証するものではない。
