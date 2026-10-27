# 文書と保存形式の検査

Go1.27.3とPython3を用意し、リポジトリのルートで実行します。

```sh
mise exec -- python3 tools/designcheck/check.py
```

| 検査 | 対象 |
| --- | --- |
| Python | 必須文書、相対リンク、Markdownの見出し・明示アンカー、コードフェンス、JSON構文・重複キー |
| Go | WAL・pack・controlの配置、CRC32C・SHA256、gzip、HTTP判断、HMAC、月末期限 |

[fixture](../../docs/design/fixtures/)は架空の鍵・IP・投稿を使い、期待値は実装と独立に定義します。古い形式は対応・拒否境界の検査用です。実HTTP・障害・端末・性能の検査は[検証方法](../../docs/testing/README.md)を参照してください。

見出しを変更するときは、同じページの目次と別文書からのリンクも更新してください。同名の見出しに付く番号、日本語の見出し、URLで符号化されたパスも検査します。コード例に書かれたリンクは対象外です。外部サイトへの接続は行わないため、外部ページの移動やアクセス制限は別に確認します。

リンク検査自体の回帰試験は次のコマンドで実行できます。

```sh
mise exec -- python3 -m unittest discover -s tools/designcheck -p 'test_doclinks.py'
```

GitHubのSecurity policyは、通常の文書表示と相対リンクの解決基準が異なります。ルートの `SECURITY.md` を案内に使い、詳しい運用手順は `docs/security-operations.md` に置いて、どちらも相対リンクを維持します。検査はルート・`.github` の文書と、選択されるSecurity policyの解決基準も確認します。同一リポジトリのGitHub絶対URLがある場合も、外部リンクとして読み飛ばさず実ファイルと見出しを確認します。

ファイルの存在確認と、GitHubが生成したリンクの確認は別です。表示方法を変えた場合は、文書単体・フォルダーのREADME表示・Security policyの実際の画面でリンク先を確認してください。
