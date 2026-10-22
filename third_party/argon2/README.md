# Argon2idの依存とライセンス

管理パスワードの導出に使う依存です。

| module | バージョン | 使用パッケージ |
| --- | --- | --- |
| `golang.org/x/crypto` | v0.58.0 | `argon2`、内部依存の `blake2b` |
| `golang.org/x/sys` | v0.49.0 | CPU判定用の `cpu` |

出典は [Go Cryptography](https://go.googlesource.com/crypto/) と [Go System](https://go.googlesource.com/sys/) です。配布条件は同梱の [x/crypto LICENSE](x-crypto-LICENSE) と [x/sys LICENSE](x-sys-LICENSE) を参照してください。Dockerイメージにも `/usr/share/licenses/oimobbs/argon2/` として含めます。
