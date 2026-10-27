# 保存codecの比較

合成DAT 3種類と、独立した署名・ID・hash連鎖を持つ架空HTTP記録128件を使います。稼働データや秘密鍵は読みません。標準gzip、配信用Zstandard、保存用level 1/6/9へ同じ入力を渡し、保存bytes、符号化・復号時間、符号化時の確保bytesをJSONへ出力します。各条件を3試行し、各試行の内部で指定回数を反復します。

```sh
mise exec -- go run ./tools/storagebench -count 30 -output /tmp/storage-codecs.json
```

出力先は新規ファイルである必要があります。各条件の計時前に展開後バイトの一致を確認し、Zstandardは独立したGo標準実装由来のテスト用decoderでも検査します。workerを再利用し、初期確保と検証を計時から分離します。

`http_wal_batch_64` は64件をまとめた圧縮入力、`signed_log_snapshot` は署名記録を連結した圧縮入力です。WAL外枠、snapshotコンテナ、ファイルのWrite/Sync、HTTP、起動時間は含みません。これらは別途、実サーバーの混合負荷・復旧試験と停止中コピーの移行検証で測定します。比較対象のビルドとCPU・メモリ条件をそろえ、他の試験・ビルドと並行して速度を測定しないでください。
