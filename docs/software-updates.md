# 管理画面からソフトウェアを更新する

サイト管理者だけが「ソフトウェア更新」画面を使えます。板管理者・投稿管理担当や、追加権限だけを持つ管理者には表示・実行を許可しません。更新機能は初期状態では無効です。以下のホスト設定を済ませると、Dockerとsystemdのどちらでも利用できます。

## 管理画面での操作

1. 「ソフトウェア更新」→「最新版を確認する」を押します。この段階では停止・ビルド・置換を行いません。
2. 「状態を更新する」で、現在と更新対象の完全なコミットIDを確認します。取得元は固定の `https://github.com/patatan168/OimoBBS.git`、対象は `main` です。Gitタグの最新版を選ぶ機能ではありません。
3. 「更新内容と再起動を確認する」を開きます。再認証が必要なら本人確認を済ませ、再度確認画面を開きます。
4. 一時停止・再起動の確認にチェックし、「更新して再起動する」を押します。
5. 検証中は掲示板を継続します。検証に成功すると停止し、データをバックアップしてから更新・再起動します。再接続して「状態を更新する」で結果を確認します。

確認は30分間有効です。実行するのは確認済みのコミットだけで、確認後にmainが進んでも対象を差し替えません。二重送信では同じ更新を繰り返しません。実行直前にもサイト管理者の権限・セッション世代・10分以内の再認証を検査します。

再起動後は必要に応じてログインし直して、更新結果を確認してください。

「操作の記録」には、更新を要求した管理者を記録します。対象コミットは更新画面とホストのジョブ情報で確認します。この記録だけでは更新成功を意味しません。完了判定は更新サービスに保存した状態とヘルスチェックによります。

## ホストの更新サービスを準備する

Linux、Git、Python3、systemdが必要です。Docker方式ではDocker Engineと、`up --wait --wait-timeout` に対応したComposeも必要です。systemd方式では更新先が要求するGoを、指定した絶対パスに事前に用意します。Goの自動インストールは行いません。

更新サービスは掲示板と別のプロセスとしてホストで起動します。Git・Docker・systemctlを使う権限、データ・バイナリの保存権限は更新サービスだけに渡します。ブラウザーから取得元・ブランチ・コマンド・ファイルパスは指定できません。

```sh
mise exec -- go build -trimpath -o bin/oimoupdate ./cmd/oimoupdate
sudo install -d -m 0755 /usr/local/libexec
sudo install -m 0755 bin/oimoupdate /usr/local/libexec/oimoupdate
sudo install -m 0755 scripts/deploy-software-update.py /usr/local/libexec/oimobbs-deploy-update.py
sudo install -d -m 0700 /etc/oimobbs-update /var/lib/oimobbs-update
sudo install -m 0600 deploy/update-agent.example.json /etc/oimobbs-update/agent.json
```

`agent.json` の `current_revision` を、**実際に稼働中のバイナリまたはイメージのソースコミット**に変更します。40桁の完全なSHAを使います。作業中のcheckoutのHEADを、そのまま稼働中のコミットとみなさないでください。更新元と現在のコミットの履歴がつながらない場合は更新を拒否します。

`prepare_command` と `apply_command` は、上の固定スクリプトを呼び出す既定の配列を使います。設定は更新プロセスの実行ユーザー所有・0600、状態保存先は専用の0700ディレクトリとします。掲示板にはUnix socketだけを公開し、設定・バックアップ・実行ログは公開しません。

### Dockerで更新する

```sh
sudo install -m 0600 deploy/update-docker.example.json /etc/oimobbs-update/deployment.json
```

`deployment.json` の各パスとサービス名を、実際の稼働構成に合わせます。

| 項目 | 指定する内容 |
| --- | --- |
| `project_directory` | 既存のComposeプロジェクトの絶対パス |
| `compose_files` | 普段の起動と同じComposeファイルを同じ順番で列挙し、最後に更新用overlayを追加 |
| `service` | 更新する掲示板サービス名。通常は `bbs` |
| `data_destination` | 保存データ全体を含むコンテナ内のマウント先。既定は `/data` |
| `override_file` | 成功後のイメージ名を保存する、ホスト側の専用ファイル |

[更新用overlay](../deploy/compose.update.example.yaml)は `OIMO_UPDATE_SOCKET` とUnix socketのディレクトリをBBSに渡します。現在の構成へこのoverlayを追加して、BBSだけを再作成します。この初回設定にも一度再起動が伴います。Docker socketはBBSへマウントしません。

更新時は `update-check` ビルド段階で認証・Web資産・公開入口・更新器の試験とvetを実行し、`runtime` イメージをビルドします。その後BBSだけを停止します。元のイメージを `oimobbs-update:before-<更新番号>` として保管し、停止済みのデータを元のイメージ内のtarで保存します。バックアップにはSHA-256を付け、全体を読み直してから新イメージを起動します。公開入口や証明書サービスは更新しません。

以後、手動でComposeから起動・再作成する際も、通常の `-f` 群の最後に `-f /var/lib/oimobbs-update/active-compose.json` を追加します。これを省略すると、元のComposeに書かれた古いイメージが選ばれます。

### systemdで更新する

```sh
sudo install -m 0600 deploy/update-systemd.example.json /etc/oimobbs-update/deployment.json
```

`unit`、`binary`、`config`、`data_dir`、`go_binary` を稼働環境の絶対パスへ合わせます。`data_dir` は起動JSONの `data_dir` と同じ保存領域を指定します。バイナリ・起動JSONにはシンボリックリンクを使いません。

掲示板サービスのdrop-inに `Environment=OIMO_UPDATE_SOCKET=/run/oimobbs-update/control.sock` を追加し、更新socketへ接続できるグループを設定します。更新サービスの `Group` と、掲示板側のGIDまたは補助グループを合わせてください。下のunit例の `10001` はDockerの既定GIDなので、systemdの実行ユーザーに合わせて変更します。

更新時は隔離ソースから重点試験・vet・CGO無効ビルドを行います。ビルド成功後に対象unitを停止し、データ・旧バイナリ・起動JSONを保存します。同じディレクトリでバイナリを原子的に置換して起動し、120秒以内のヘルスチェック成功を確認します。

### 更新サービスを起動する

```sh
sudo install -m 0644 deploy/oimobbs-update.service.example /etc/systemd/system/oimobbs-update.service
sudo systemctl daemon-reload
sudo systemctl enable --now oimobbs-update.service
sudo systemctl status oimobbs-update.service --no-pager
```

掲示板にも `OIMO_UPDATE_SOCKET` の設定を反映して再起動した後、サイト管理者で「ソフトウェア更新」を開きます。更新サービス自体・公開入口・証明書・ホスト側のGoは、この機能では更新しません。

## 失敗時の確認

実行ログは `/var/lib/oimobbs-update/jobs/<更新番号>/update.log`、対象コミットは `request.json`、バックアップは同じディレクトリの `data.tar.gz` と `data.tar.gz.sha256` に保存します。systemd方式では `oimobbs.before` と `config.before.json`、Docker方式では `prepared.json` に元のイメージ・コンテナ情報も残します。これらは秘密を含むので公開・共有しません。

ビルドや検証で失敗した場合は、掲示板を停止しません。停止後のバックアップに失敗した場合は、置換せず元のプロセス／コンテナを起動します。新バイナリの起動後やイメージ置換後に失敗した場合は、データの保存形式が変わった可能性があるため、古い実行ファイルへ自動で戻しません。稼働状態と保存済みバックアップを確認して、停止した状態で復旧を判断します。

更新サービス自体が中断した場合も、自動再実行せず「要確認」にします。成功したジョブを含め、バックアップ・隔離ソース・ビルド資産は自動削除しません。空き容量と保存期限を運営者が管理してください。

最新版確認の失敗など、更新番号がまだない段階のログは `sudo journalctl -u oimobbs-update.service -n 100 --no-pager` で確認します。手動で別のコミットを配備した場合は、更新サービスを停止して `agent.json` の初期コミットを合わせ、保存済みの `state.json` を退避してから更新サービスを再開します。稼働コミットと保存状態が一致していないまま、管理画面の更新を進めないでください。

## 検証

```sh
mise exec -- go test -race ./internal/selfupdate
mise exec -- go test ./internal/bootstrap -run 'TestSoftwareUpdate|TestAdminNavigationPermissions|TestAuditPresentationCoverage' -count=1
python3 -B scripts/test_deploy_software_update.py -v
```

Goでは実HTTP・Unix socket・隔離Gitリポジトリで確認済みコミット、再送、期限、権限、再認証、失効、監査を検証します。PythonではDocker/systemctlを差し替え、停止とバックアップの順序、外部変更の拒否、バックアップ失敗時の再起動、ヘルスチェック失敗を検証します。実ホストのDocker置換・systemd再起動・公開経路の復旧は別の確認です。
