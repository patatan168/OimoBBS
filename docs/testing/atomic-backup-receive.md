# 受信側の原子的なバックアップ設置

以下はPython実装時点の検証記録です。現行の実装・コマンド・検証結果は[Goへの統合](sealed-backup-go.md)を参照してください。ここに記載するPythonファイルと試験はGo版へ置き換え済みです。

2026-11-03。`0a24892` の後、暗号文と完成記録を順にscpする方式を、SSH受信側で一組の完成世代として設置する方式へ変更しました。稼働BBS・既存SSH設定・実際の別ホストは変更していません。

## 受信と設置の規則

送信元は所有者限定の暗号文をSSHの標準入力へ直接渡します。全体をメモリに読み込みません。固定メタデータと受信処理を引用済みのSSHコマンドとして渡し、BatchModeと厳格なホスト鍵検証を維持します。aliasへのSSHオプション混入、相対パス、dot区画、shell構文を受け付けません。

受信先はSSHユーザー所有の0700の親directoryを使い、受信・回収を非待機の共通lockで排他します。次の順序を維持します。

1. `.incoming-<世代>-<一時ID>/` へ暗号文を0600で受信する。
2. 宣言された長さ・EOF・全体のSHA-256を照合し、暗号文を同期・Closeする。
3. 完成記録を0600で保存・同期・Closeし、一時directoryも同期する。
4. 期限を再確認して、`backup-<ID>-<SHA256>/` へdirectory単位でrenameする。
5. 受信先の親directoryを同期してから、世代名とhashを含むACKを返す。

完成世代は `archive.seal` と `manifest.json` の二つだけを含みます。入力のJSONは8KiB以内とし、重複キー・未知の形式・型違い・不正な名前・期限切れを拒否します。暗号文の処理bufferは最大256KiBです。

期限内の以前の完成世代は上書きしません。同じコピーを再暗号化してhashが変わった場合も、別の世代として保存します。設置前の受信中断・書込・同期・Close失敗やrename自体の失敗では、新しい完成世代を公開しません。rename後の親同期失敗では、完全な世代を保持したままACKを返さず失敗します。

再送で同じ完成世代がある場合は、保存済みの両file・長さ・hash・権限を確認し、再同期します。入力stream自体も長さ・hash・EOF・期限を照合してから `existing` と応答します。暗号文の書直しや新しい一時コピーは不要です。壊れた完成世代や別メタデータを正常と報告せず、上書きもしません。

送信側はSSHの終了コード0だけでなく、プロトコル・世代名・hash・状態が一致するACKを要求します。ACKなしやtimeoutは失敗として扱い、次回に再送できます。エラーに埋込み受信プログラム全体を出力しません。

## 受信先の導入と移行

送信元では `seal_online_backup.py`、`atomic_backup_transfer.py`、`receive_sealed_backup.py` を同じ配布物として配置します。引数は従来どおり `--destination SSH設定alias:/absolute/directory` を使います。受信先では `python3` がPython3.11以降で、SSHによるコマンド実行を許可する必要があります。SFTP専用アカウントは対応しません。通常の受信処理はSSH経由で渡すため、受信先への事前のスクリプト設置は不要です。

受信先の保存例は次の形です。

```text
/srv/oimo-backup-receive/
  backup-<ID>-<SHA256>/
    archive.seal
    manifest.json
```

復号時はこの `archive.seal` を入力に指定します。秘密鍵と平文の復号先は受信世代の外に置き、復号成功後も従来の検証付き復元へ進みます。受信側のhash一致は、秘密鍵による認証復号やBBS全体の復元完了を意味しません。

保存配置は従来の平置きの `.seal` と `.json` から変わります。既存の平置きファイルを自動で移動・削除する処理は追加していません。別の受信親directoryを用意し、既存コピーの復元手順と元の期限管理を維持しながら切り替えます。同一コピーの複数の暗号化世代を期限まで保持するため、その容量も確保します。SSHだけ成功させて旧scpへ戻すfallbackはありません。

### 送信元から独立した期限回収

受信側に `tools/receive_sealed_backup.py` を配置すると、次のCLIだけでも回収できます。

```sh
python3 /opt/oimobbs/receive_sealed_backup.py \
  --root /srv/oimo-backup-receive --sweep
```

[service例](../../deploy/oimobbs-backup-receive-gc.service.example)と[timer例](../../deploy/oimobbs-backup-receive-gc.timer.example)を用意しました。UserをSSH受信ユーザーに合わせ、scriptと保存先の絶対パスを設定します。2分後に初回、以後5分ごとの実行例です。実際の受信先への配置・有効化は今回行っていません。

この回収も同じlockを取り、稼働中の受信を削除しません。強制終了後の既知の一時出力だけを回収します。期限切れの完成世代は、まず `.expired-<世代>-<一時ID>/` へrenameして親を同期し、その後に中身を除去します。完成記録の削除後や、空directoryまで削除したところで止まっても、次回に回収を再開できます。元の期限は延長しません。

予期しないfile名・symlink・所有者や権限の異常はエラーとして保護します。従来の平置き形式と、既知の世代名に一致しない物は自動回収しません。受信先の時計と、この独立回収の稼働確認も運用対象です。

## 実SSHで確認したこと

専用鍵・専用設定のOpenSSHサーバーを、一般ユーザー権限でループバックの一時ポートへ起動しました。既存のSSH設定・known_hostsには書き込んでいません。送受信は同じホスト・OSユーザー上です。

実 `oimoseal` で作った2,222,837byteの暗号文を、製品の送信関数と受信処理で転送しました。復号秘密鍵はSSH入力に含めていません。

| 条件 | 確認結果 |
| --- | --- |
| 初回受信と同一コピーの再送 | `installed` → `existing`。保存世代のinodeを維持 |
| 暗号文を書込み済みの受信途中でSSH接続を3回連続切断 | 新しい完成世代なし。以前の正常コピーはbyte不変 |
| 3回の切断後に完全な入力から再送 | 設置成功。一時directoryは0件 |
| 設置・親同期後、ACK出力前に受信processを終了 | 送信側は失敗。再送は `existing`、完成世代のinodeを維持 |
| 転送中の暗号文を1byte改変 | 受信側が拒否。新しい完成世代なし。以前のコピーは不変 |
| 登録済みホスト鍵を受け入れられない状態 | SSH接続を拒否。受信世代を作成しない |
| 受信した暗号文を秘密鍵で復号 | 2,222,080byteのtar全文・SHA-256・合成payloadが元と一致 |
| SSHから独立回収CLIを実行 | 期限切れ1世代だけを除去し、期限内のコピーを保持 |

検証サーバーは終了し、一時的な送受信データは除去しました。原出力と再実行用scriptは `var/atomic-backup-receive-20261103/` に保持しています。`ssh-results-final.txt` と `ssh-results.json` が最終試行です。

## 自動検査と境界

```sh
python3 -B -m unittest discover -s tools -p 'test_*backup*.py' -v
mise exec -- env CGO_ENABLED=0 go build -o var/atomic-backup-receive-20261103/oimoseal ./cmd/oimoseal
mise exec -- python3 -B tools/designcheck/check.py
python3 -B -m unittest discover -s tools/designcheck -p test_doclinks.py
```

41試験が成功しました。受信側の実processへのSIGKILL、容量不足相当・短い書込・同期・manifest Close・renameの失敗、ACK不一致、設置後の親同期失敗からの再送、同じ完成世代の書直し不要、受信中の回収拒否、期限回収の中断再開を含みます。保存障害はI/O境界への注入で、実ディスク全体を満杯にしていません。原出力は `python-tests-final.txt` にあります。通常の `scripts/check.sh` にも登録しています。service/timer例は検証用のUser・絶対パスへ差し替え、systemd-analyzeのoffline検査も成功しました。

WAN・別物理ホスト、電源断・実媒体故障、稼働BBSのバックアップ作成から公開復元までの一括実行、稼働環境への反映は未検証です。SIGKILLは同じOSのpage cacheを保持する試験で、停電の証明にはしません。オンラインコピーの `restore_ready` の意味も変更していません。
