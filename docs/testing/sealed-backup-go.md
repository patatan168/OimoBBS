# 暗号化バックアップのGoへの統合

2026-11-03。暗号化・転送・受信・期限回収のPython実装を削除し、既存の `oimoseal` に統合しました。運用コマンドは[暗号化バックアップ](../security-operations.md#暗号化バックアップ)を参照してください。この文書は実装と隔離環境の検証記録です。

同日の本番配備で、ホストの定期バックアップをGo版の `oimoseal sync` へ変更し、実行終了0を確認しました。保存先・周期は維持しています。[配備時の確認](admin-audit-deployment-20261103.md#定期バックアップ)を参照してください。本番のSSH受信先への配布・転送確認は行っていません。

## 実装と互換性

`sync` は完成ログの取得、暗号文の再作成、hash照合、完成記録の同期、再送、期限回収を行います。ログを取得できなくても既存の期限内コピーを再送し、元の取得エラーを返します。`pack` はGo製の `oimobbs backup verify-with-keys` で検証後、標準 `archive/tar` と既存の暗号化処理を接続します。外部shell・tar・Pythonは起動しません。暗号化コンテナの失敗時は、自分が生成した名前の個体だけを回収します。

`send` はOpenSSHクライアントで暗号文を送り、配布済みGoバイナリの `receive` を実行します。既存SSH alias・鍵・known_hostsを使い、ホスト鍵検査を省略しません。受信側にPython・Docker・tarは不要です。`sweep` も同じGoバイナリで実行できます。送信元のDocker CLIとOpenSSHクライアントは引き続き必要です。

`OIMOSEAL1`、4項目の完成記録、転送protocol1、受信世代の配置は維持します。暗号文・完成記録・一時ディレクトリを同期し、完成名へのrenameと親同期後にだけACKを返します。完成世代の再送では保存済みデータと受信streamの両方を検証し、暗号文を書き直しません。期限回収は `.expired-*` へのrenameを同期してから削除するため、途中で完成記録が失われても再開できます。

旧PythonファイルをSSHで渡す方式から、受信先へのバイナリ事前設置へ変わります。送信元と受信先のバイナリ・serviceを更新してください。旧scpの平置きコピーは世代回収の対象外です。

## 検証

通常のGo試験は次で実行します。`scripts/check.sh` に含まれるGo対象です。

```sh
mise exec -- go test ./cmd/oimoseal ./internal/sealedbackup
mise exec -- go test -race ./cmd/oimoseal ./internal/sealedbackup
```

Go試験では長さ・hash不一致、欠落・重複・未知JSON項目、書込・短い書込・同期・Close・rename失敗、設置後の親同期失敗、ACK不一致、破損した送信元の再作成、ログ消失・取得失敗後の再送を確認しました。受信processを暗号文書込中に3回SIGKILLし、前の完成世代が保たれ、回収と再送が成立することも確認しています。保存障害はI/O境界への注入です。

実SSH試験は、隔離した非特権sshdと専用設定・known_hostsを生成して実行しました。3回の転送中断、応答消失後の再送、inodeを維持した完成世代の再利用、不正stream・未知ホスト鍵の拒否が成功しました。受信した暗号文をGoで認証復号し、元の2,320,000byteとの一致を確認しました。既存のSSH設定は変更していません。

```sh
mkdir -p var/sealed-backup-go-20261103
mise exec -- env CGO_ENABLED=0 go build \
  -o var/sealed-backup-go-20261103/oimoseal ./cmd/oimoseal
OIMO_TEST_SEAL_BINARY="$PWD/var/sealed-backup-go-20261103/oimoseal" \
  mise exec -- go test ./cmd/oimoseal -run '^TestGoSSHIntegration$' -v -count=1
```

Docker試験では、Pythonが存在しないruntimeイメージで実際のバックアップを準備し、実ログ取得から `sync` → `pack` → 暗号化まで通しました。Goで復号・tar展開した9ファイルのコピーと鍵束を、コンテナ内の `oimobbs backup verify-with-keys` で再検証しました。2回目の `sync` が再暗号化せず再利用することも確認しました。

```sh
docker build --target runtime -t oimobbs:sealed-go-verification-20261103 .
mise exec -- env CGO_ENABLED=0 go test -c \
  -o var/sealed-backup-go-20261103/oimoseal.test ./cmd/oimoseal
OIMO_TEST_SEAL_IMAGE=oimobbs:sealed-go-verification-20261103 \
OIMO_TEST_SEAL_FIXTURE="$PWD/var/sealed-backup-go-20261103/oimoseal.test" \
  mise exec -- go test ./cmd/oimoseal -run '^TestGoDockerSyncIntegration$' -v -count=1
```

原出力はGit対象外の `var/sealed-backup-go-20261103/` に保持しています。`go-tests-final.txt`、`race-final.txt`、`go-ssh-final.txt`、`go-docker-final.txt` が最終確認、`checks-final.txt` がvet・CGO無効ビルド・文書検査、`systemd-final.txt` が設定例のoffline検査です。統合試験は必要な環境変数がない通常実行ではskipします。

これらは隔離環境での保存・転送・認証復号・署名検証の結果です。実電源断・媒体故障・別ホスト喪失・サイト全体の起動復旧は未検証です。`restore_ready` は元の報告を保持し、完全復元可能とは読み替えません。
