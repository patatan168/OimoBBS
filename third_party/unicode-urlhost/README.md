# URLホスト比較のUnicodeデータ

`internal/urlhost` はHTTP/HTTPSの宛先解析・IPv4変換・UTS #46の非移行変換・NFC・Punycodeを自前で実装しています。追加のGoモジュールや外部処理は使用しません。一般用途のURLパーサーやDNS名の登録検査を提供するものではありません。

文字ごとの変換・結合情報にはUnicode 17.0.0の公式データを使用します。出典とSHA-256は [SOURCES.json](SOURCES.json)、Unicodeのライセンスは [LICENSE](LICENSE) に記録しています。第三者ライブラリーの実装コードは含みません。

`SOURCES.json` に記録した原本を同じディレクトリへ保存し、次のコマンドで生成表と照合できます。生成器はネットワーク通信せず、各原本のSHA-256を先に検証します。

```sh
mise exec -- python3 scripts/generate-urlhost-tables.py <原本のディレクトリ> --check
```

`internal/urlhost/testdata/browser_hosts.json` は隔離Chromiumで `new URL(input).hostname` を取得した54例です。Unicode公式の `NormalizationTest.txt` と `IdnaTestV2.txt` も同じディレクトリに保存すると、NFCの20,034例・各5列と正常なIDNA変換549例を追加で照合できます。

```sh
OIMO_UNICODE_CONFORMANCE_SOURCES=<原本のディレクトリ> \
  mise exec -- go test ./internal/urlhost -count=1 -v
```

ホスト入力は4096byte、非ASCIIのPunycodeラベルは256文字までです。NFCの結合順序は安定ソートで処理し、長い結合文字列による二次の並べ替えを避けます。Unicodeデータの更新時は、原本の版・SHA-256・生成表・Chromiumとの照合を同時に確認してください。
