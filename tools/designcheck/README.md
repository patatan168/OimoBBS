# 文書と保存形式の検査

Go1.27.2とPython3を用意し、リポジトリのルートで実行します。

```sh
mise exec -- python3 tools/designcheck/check.py
```

| 検査 | 対象 |
| --- | --- |
| Python | 必須文書、ローカルリンク、コードフェンス、JSON構文・重複キー |
| Go | WAL・pack・controlの配置、CRC32C・SHA256、gzip、HTTP判断、HMAC、月末期限 |

[fixture](../../docs/design/fixtures/)は架空の鍵・IP・投稿を使い、期待値は実装と独立に定義します。古い形式は対応・拒否境界の検査用です。実HTTP・障害・端末・性能の検査は[検証方法](../../docs/testing/README.md)を参照してください。
