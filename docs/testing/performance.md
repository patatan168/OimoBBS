# CPU・メモリ・復旧時間の検証

処理時間・割り当て量を測る単体ベンチマークと、実HTTPのCPU・メモリ・復旧時間を測る負荷試験を分けて確認します。Go1.27.3、Python3、Dockerを用意し、リポジトリのルートから隔離データで実行します。

## 目的から選ぶ

| 確認すること | 手順 |
| --- | --- |
| 最適化前後で受理・拒否の条件が同じか | [入力と処理結果の一致](#入力と処理結果の一致) |
| 閲覧と投稿を同時に処理できるか | [実HTTPの負荷試験](#実httpの負荷試験) |
| メモリ制限への追従と受付の再開 | [CPU・メモリの自動調整](#cpuメモリの自動調整と圧迫時の回復) |
| 予定した投稿数を時間内に処理できるか | [投稿処理量](#投稿処理量の測定) |
| 帯域ごとの負荷と使用資源 | [帯域ごとの構成確認](#帯域ごとの構成確認) |
| 強制終了後に投稿とETagが保たれるか | [異常終了と負荷回復](#異常終了からの再起動と負荷回復) |
| WAFを有効にした追加費用 | [WAFの測定](#wafの追加費用と通常通信) |

過去の測定値・失敗・不採用候補は[測定資料一覧](measurements.md)から参照できます。このページは再実行手順を扱います。

## 入力と処理結果の一致

厳密JSONの受理条件、投稿署名、類似度の判定、公開表現の分離を確認します。空白・Unicode・不正UTF-8・短文・長文・重複文字と、類似度の境界値を含めます。

```sh
mise exec -- go test -race ./internal/compat ./internal/bootstrap \
  -run 'Guard|Compression|Gzip|FeedCache|LiveRead|Publication'
mise exec -- go test ./internal/bootstrap -run '^$' \
  -fuzz FuzzGuardSignatureAndSimilarity -fuzztime=15s -parallel=2
mise exec -- go test ./internal/strictjson -run '^$' \
  -fuzz FuzzDecodeShapeEquivalence -fuzztime=20s -parallel=2
```

## 単体ベンチマーク

圧縮・復号の合成入力とコマンドは[保存codecの比較](../../tools/storagebench/README.md)を参照してください。

同じ入力・CPU枠・測定時間を使い、時間と割り当て量を分けて比較します。通常本文、反復長文、非反復長文、不一致の署名、公開HTMLキャッシュの命中を分けます。合成長文を測定しても製品の投稿上限は変更しません。

`GOMAXPROCS=2`、`-test.benchtime=500ms`、`-test.benchmem` を基準とし、各条件を複数回実行します。

## 実HTTPの負荷試験

### 基準の負荷と記録する指標

[probe-thread-resources.py](../../scripts/probe-thread-resources.py) を使います。測定対象のイメージを `OIMO_PERF_IMAGE` に設定してください。

```sh
OIMO_PERF_IMAGE=oimobbs-validation:performance-check
docker build -t "$OIMO_PERF_IMAGE" .
mise exec -- python3 scripts/probe-thread-resources.py \
  --image "$OIMO_PERF_IMAGE" \
  --peak-mix --egress-bps 100000000 \
  --peak-post-workers 5 --peak-capacity-workers 20 \
  --optional-log-stats --output var/performance-check.json
```

比較対象は同じCPU・メモリ枠、読者数、投稿数、送信予算、圧縮条件で実行します。cgroupのCPU差分と短い間隔の標本を集計し、メモリは総量とanon/fileを分けます。anonにはGoヒープ以外も含まれます。

| 対象 | 確認する指標 |
| --- | --- |
| CPU | ピーク区間の平均、標本のp95、標本間隔 |
| メモリ | ピーク区間・全期間の最大、anon/file、OOMの有無 |
| 閲覧 | 完了件数、エラー、送信量、帯域待ちによる未発行 |
| 投稿 | 受理件数、連番の一意性、DATの旧版prefix、処理量 |
| 復旧 | 予定時刻から完了までのp95・最大遅延、回復区間終了時の残存投稿 |
| 非必須ログ | 欠測、待機、正常終了 |

フォームの準備・要求の発行待ち・HTTP応答時間を分けて記録します。中央値や応答時間だけで復旧時間を判断しません。

### WAFを有効にする場合

WAF有効時の検査費用と異常終了後の復旧は、投稿専用枠内の準備速度で確認します。

```sh
mise exec -- python3 scripts/probe-thread-resources.py \
  --image "$OIMO_PERF_IMAGE" --cpus 2 --memory 512m --waf \
  --prepare-post-rate 10 --crash-recovery --egress-bps 100000000 \
  --optional-log-stats --output var/performance-waf-check.json
```

この例は測定用に2CPU・512MiBへ制限しています。現行ComposeのBBSは、上限を省略するとホスト資源へ追従します。スクリプト既定の1GiBとは条件を分けて比較します。

新規の隔離volumeに一時管理者を作り、実管理APIの認証・再認証・CSRF・版照合を通じてWAFを保存します。公開側で秘密ファイル探索への403も確認してから測定します。頻度枠は利用者10000件/秒・瞬間100000件、全体100000件/秒・瞬間200000件へ上げ、検査・頻度計算・既定の同時処理枠を有効にした処理費用を測ります。投稿には通常枠に加えて、既定で全体60要求/秒・瞬間120要求、回線ごと10要求/秒・瞬間30要求の投稿枠があり、確認往復も消費します。通常枠の引上げでも投稿枠は変わりません。

投稿枠も比較する場合だけ`--waf-posting-rate`と`--waf-posting-concurrent`を明示し、実管理APIで設定・読戻しした値を結果へ記録します。

準備40投稿/秒や追加200投稿の集中試験は拒否される場合があるため、処理能力の比較はWAFなしで行い、WAFありの復旧結果と区別します。この条件は既定の全体300件/秒で許可される投稿量を表しません。設定値を結果の `waf` に記録し、本番の設定は変更しません。

### 閲覧と予定投稿を重ねる場合

WAFを有効にしたまま閲覧負荷と予定20投稿/秒を重ねる場合は、`--peak-no-capacity` で追加200投稿を省きます。準備投稿は10件/秒とします。

```sh
mise exec -- python3 scripts/probe-thread-resources.py \
  --image "$OIMO_PERF_IMAGE" --cpus 2 --memory 1g \
  --waf --prepare-post-rate 10 --peak-mix --peak-no-capacity \
  --peak-post-workers 5 --peak-full-every 1 --peak-polls 2000 \
  --egress-bps 100000000 --optional-log-stats \
  --output var/performance-waf-bandwidth.json
```

この条件は専ブラ32主体・Web8主体で、ピーク12秒間の専ブラ取得を無圧縮全文にして送信を集中させます。予定閲覧数、発行数、完了転送量、帯域待ちによる未発行を分けて確認します。予定420投稿、準備41投稿を含む461行、各投稿番号の一意性、DATのprefix一致、OOMなし、予定起点の回復区間投稿p95が5秒以内、21秒以内の予定投稿完了を検査します。`--peak-capacity-during-load` とは併用できません。追加投稿能力を測った結果には使いません。

### ピーク中の追加投稿能力を測る場合

`--peak-capacity-during-load` は開始6秒（ピーク開始の2秒後）に追加200投稿を投入します。予定投稿と集中投稿で各20主体を使い、接続の共有を避けます。投稿生成5並列・集中投稿20並列以下で利用できます。この指定を省略した従来条件は、21秒の通常・ピーク・回復区間が終わった後の集中書き込みです。いずれも予定20投稿/秒と追加の処理量を区別します。比較時は区間ごとのCPU・最大メモリに加え、容量測定中のCPU使用量も確認します。ピーク中のCPUには並行する閲覧と予定投稿も含みます。サーバーだけのcgroup値と、クライアント側の生成待ちを混同しません。

ピーク中の容量測定が16秒までに終わらない場合、回復区間の予定時刻からの投稿p95が5秒を超えた場合、または21秒の回復終了時に予定投稿が残った場合は、結果を保存して試験を失敗にします。

### 非必須HTTPログの確認

非必須HTTPログは、保存中の分を含め最大4,096件・予約JSON合計16MiBです。一回の保存は最大256件・元JSON4MiB以内で、64件の圧縮blockを最大4個まとめて同期します。通常は保存完了後100msの間隔を空け、1,024件以上の滞留で間隔待ちを解除します。通常は必須投稿を優先し、滞留1,024件または予約8MiB以上のときは投稿中にも非必須保存を進めます。日別64MiB・全日合計128MiBの保存量・展開後現在行の上限も維持します。設計は[保存形式と復旧](../architecture.md#保存形式と復旧)を参照してください。

`optional_shutdown.queue` の `dropped_capacity` と `failed` を併せて確認し、前者だけが減った結果を欠測の解消と判断しません。投稿の保存件数・整合性や正常停止だけでもログ欠測なしとは判断できません。

## CPU・メモリの自動調整と圧迫時の回復

[adaptive-resources.json](adaptive-resources.json) に、資源の大小・実メモリ圧迫・実HTTPS投稿の試験条件と結果を記録します。[自動調整の仕様](../features/resources.md)では、CPU・メモリ予算と共有予約から、保持量や実行できる処理量を決めます。投稿バッチの最大64件・8MiB、WAF、帯域、公平性、保存順序は維持します。

`TestAdaptiveRepresentationResources` は、32MiB〜12GiBのメモリ予算と1〜64並列を組み合わせ、自動保持、CPUに応じた生成数、圧迫時の停止を検査します。`TestCompressionAdaptivePressureAndRecovery` は1024件を超える表現の保持、実行中処理を残した縮小、新規生成の拒否と回復を検査します。共有メモリ予約は同時競合・二重解放・軽い読取りの継続・拒否からの回復を検査します。

`TestPostingBatchFlushesBeforeMemoryRetry` は一候補分しかないRAM予算で6返信を分割保存し、FIFO、再試行回数、確定済み応答の先行返却、予約回収、再起動後のDAT一致を検査します。

`TestResourcePressureProcess` は通常のテストではスキップします。8GiB以下の有限メモリ制限を持つ隔離コンテナ内でだけ `OIMO_RESOURCE_PRESSURE_PROBE=1` を指定し、実際のGo管理領域をGC目標の近くまで増やします。キャッシュ解放、公開要求503、投稿準備の拒否、メモリ解放後の再開、cgroupのOOM・OOM killを確認します。回復を再現するため、試験側だけでGCとOSへのメモリ返却を明示します。製品側は受付停止により割当・GC開始が止まった場合だけ、予約中の処理がないこととGC後の十分な割当増分を条件に回収します。常時の定期GCは行いません。

```sh
CGO_ENABLED=0 mise exec -- go test -c -o var/resource-pressure.test ./internal/bootstrap
docker run --rm --network none --cpus 1 --memory 256m --memory-swap 256m \
  --read-only --tmpfs /tmp:uid=10001,gid=10001,mode=0700 \
  -e OIMO_RESOURCE_PRESSURE_PROBE=1 \
  -v "$PWD/var/resource-pressure.test:/probe:ro" --entrypoint /probe \
  "$OIMO_PERF_IMAGE" \
  -test.run '^TestResourcePressureProcess$' -test.v
```

実HTTPSの投稿試験は別に行い、投稿のACKとDAT本文、重複、以前のprefix、予定起点の遅延、未発行・拒否、回復投稿を確認します。Webの303受理後に表示だけ失敗した場合も受理済み投稿としてDATと照合し、表示失敗は成功件数へ加えません。照合用GETが503の場合は全体で最大5秒だけ再読取りし、その回数を記録します。読取り不能と投稿欠落は区別し、200応答の内容不一致は再試行しません。単体の圧迫試験や設定の追従だけから、投稿性能・WAN・全条件でのOOM回避を保証しません。

## 投稿処理量の測定

固定予定の投稿負荷は、次のコマンドで測定します。毎秒の予定件数を上げ、同じ条件で複数回比較します。

```sh
mise exec -- python3 scripts/probe-thread-resources.py \
  --image "$OIMO_PERF_IMAGE" --cpus 2 --memory 1g \
  --egress-bps 400000000 --posting-capacity-rate 100 \
  --posting-capacity-seconds 20 --posting-capacity-workers 40 \
  --posting-capacity-threads 16 --optional-log-stats \
  --output var/posting-capacity-100.json
```

専ブラ80%・Web20%を混ぜ、実際の確認Cookie、CSRF、耐久保存、Webの303と遷移先取得を通します。指定した主体数（既定40）がそれぞれ一要求ずつ処理し、次の同主体の予定まで遅れた分は未発行として記録します。未発行や拒否を分母から除いて成功率を表示しません。`completed_per_second` は測定時間内に成功応答まで完了した投稿だけを数え、時間外の完了を含む `success_per_second_with_drain` と分けます。5秒ごとの完了数、HTTP所要時間、予定起点のp95、発行待ちも保存します。

既定は同じ一板の16スレッドへ順番に分散します。`--posting-capacity-distribution rotate` は投稿先を750予定ごとに切り替え、単一スレッドへの集中と同じ板の複数スレッドへの分散を区別します。投稿先は測定前にすべて作り、1000レス終了処理を測定へ混ぜません。集中方式では750予定につき一つの投稿先が必要です。準備投稿は測定時間へ含めません。板ごとの所有ワーカーを使うため、複数板の合計処理量はこの一板の結果から推定しません。

この試験の `stable_at_tested_rate` は、全予定の受理、未発行・投稿エラーなし、時間内完了99%以上、予定起点p95が250ms以下、DATの一致、回復100投稿の成功をすべて満たす場合に真です。これは測定用の判定値で、運用上のSLOではありません。回復は負荷完了後に毎秒20投稿を5秒間実行し、別に遅延を記録します。全投稿先の旧版prefixと、応答済み番号の保存・一意性を検査し、未応答の保存も報告します。高負荷で判定が偽になっても結果を保存し、DAT異常・OOM・生成器異常は試験自体の失敗とします。

`--posting-capacity-reads 2000` は実投稿1000レスの独立fixtureを準備し、専ブラ32主体の無圧縮全文とWeb8主体のgzip閲覧を並行します。閲覧にも同じ有界主体の予定を使い、帯域待ちによる未発行とHTTPエラーを分離します。DATの206を使う従来試験の圧縮条件は変更しません。

`--waf` の有無は別条件です。投稿枠や同時処理枠の設定値を記録し、枠による拒否を保存処理の限界と混同しません。本測定の確認経路では専ブラ・Webとも一投稿につき確認と確定の2回のPOSTを行い、既定の毎秒60要求枠をどちらも消費します。毎秒60要求を毎秒60投稿とは換算しません。

非必須ログの終了集計には準備・本測定・回復・整合性確認の要求が含まれます。欠測の有無も投稿処理量と併記します。隔離DockerでもホストのSSDは共有されるため、低CPUでI/O待ちが増える試行は保存媒体の影響を含みます。自動調整された保持上限・生成数と、自動pack保守の有無も記録します。新規データでの短い測定は、長期稼働や複数板の性能を保証しません。メモリ上限に達した試行は `memory_events` の `max` と実効処理量を併せて確認します。

## 保存処理に共通する費用

制御ログの追記はframeを一度解析し、同じ解析結果で連番・CAS・所有者固有の値検証を行います。一括追記では全件の候補検査後に同期し、成功時だけ状態を公開します。署名検証、本文の完全型検査、再起動時の再検証は省略しません。投稿の `proposal → thread → decision` の同期順序も維持します。

保存用の整数・時刻・ID・ハッシュは、通常の正規ASCII表記を入力から一時的に参照して読み込みます。エスケープや周辺空白は標準JSONデコードへ渡し、復号後の先頭ゼロ、大文字の十六進数、範囲外、ゼロIDの拒否条件を維持します。失敗時は受信先を書き換えません。出力JSONと永続化形式も同じです。

```sh
mise exec -- go test ./internal/domain -run '^$' \
  -fuzz '^FuzzScalarJSONEquivalence$' -fuzztime=30s -parallel=2
mise exec -- go test ./internal/store -run '^$' \
  -fuzz '^FuzzControlAppendMatchesApply$' -fuzztime=30s -parallel=2
mise exec -- go test ./internal/domain ./internal/store -run '^$' \
  -bench 'BenchmarkScalarJSON|BenchmarkControlAppendBatch' -benchmem -cpu=2 -count=3
```

スカラーの受理と値を標準JSON・数値・十六進数の復号と照合します。制御ログでは通常適用と単件／一括保存を比較し、不正なJSONやDAT混入の拒否、失敗時の書込なし、公開済み状態の不変性を確認します。単体ベンチマークの制御ログはディスク同期を模擬するため、保存スループットの結論には前述の実HTTP試験を使います。

帯域が先に制約になるかを確認する場合は、同じ投稿・閲覧条件で `--egress-bps` だけを変えて比較します。本文の完了転送量、予算待ち、CPUとI/O待ちを併記します。無圧縮全文、差分、小さい応答、同期が必要な投稿では制約が異なるため、掲示板全体の上限を一つの件数で表しません。

### 投稿バッチの候補寿命

投稿バッチの候補寿命は次の試験で確認します。中間候補の保持ヒープとコンテナ全体の最大メモリを区別し、取消・失敗・再起動後の整合性も検査します。

```sh
mise exec -- go test ./internal/app -run '^TestPostingBatchCandidateLifetime$' -count=1 -v
mise exec -- go test -race ./internal/app ./internal/bootstrap \
  -run 'TestPostingBatch|TestPostingProcessCrash|TestRepositoryPostingCrash|TestPostingIO|TestReplyForm|TestEditing' -count=1
```

## 帯域ごとの構成確認

[推奨スペック](../setup.md#帯域別の推奨スペック)の確認では、100・200・400・1000Mbpsの送信予算を同じCPU・メモリ枠で測ります。配信試験では転送時間を近づけるため、取得件数を送信予算に比例させます。例は1回分です。2回目は帯域の順を逆にし、出力先も変えて全試行を残します。

```sh
for oimo_mbps in 100 200 400 1000; do
  mise exec -- python3 scripts/probe-thread-resources.py \
    --image "$OIMO_PERF_IMAGE" --cpus 2 --memory 1g \
    --waf --prepare-post-rate 10 --new-codecs \
    --egress-bps "$((oimo_mbps * 1000000))" \
    --requests "$((oimo_mbps * 20))" --optional-log-stats \
    --output "var/bandwidth-${oimo_mbps}m-trial1.json" || break
done
```

この試験は全文・差分・304・Web HTMLの配信を個別に測り、別途、差分・304の毎秒1000取得と毎秒20投稿を10秒間重ねます。帯域を使う全文閲覧と投稿の同時負荷は、前述の `--peak-no-capacity` の試験でも各帯域を2回ずつ確認します。小さい応答の集中取得では非必須HTTPログの有界列があふれる場合があるため、`optional_shutdown.queue.dropped_capacity` と `failed` を必ず報告します。非必須HTTPログの日別64MiB・全日合計128MiBの保存上限も維持します。上限到達後はログ書き込みの負荷が変わるため、その区間のCPUだけで推奨値を決めません。

`--optional-log-stats` は停止後の正常終了・欠測集計に加え、読取り専用のvolumeからログファイルの総bytesと日別bytesを `optional_storage` へ記録します。生のHTTP記録は取得しません。サイズの確認は測定区間の後に実行し、CPU・投稿時間の集計には含めません。

記録するメモリはアプリのcgroup全体で、Goヒープだけの値ではありません。負荷生成側とOS・証明書更新・バックアップの資源は含めず、ホストの推奨値では別に余裕を見込みます。同一ホスト内のTLS HTTP/1.1と共有ストレージの試験であり、実回線のNIC帯域、遠隔地の遅延、大規模データ、長時間運用の検証とは区別します。

## Botの自動停止と通常通信

Botの自動停止を変更した場合は、`go test -race ./internal/bootstrap -run 'TestBotGuard|TestAbuseGuard'` で固定窓、重複要求、Cookieごとの分離、容量不足、モード変更、Webと専ブラの実HTTP応答、受理済み再送、旧設定の保存・再起動を確認します。停止期限は注入した時刻で境界を検査し、実際の120秒待機を検証した結果とは分けます。

正常投稿の追加費用は `go test ./internal/bootstrap -run '^$' -bench BenchmarkBotGuard -benchmem` で測定します。これは単体の費用です。全体への影響は同じDocker資源・WAF設定・予定投稿数・主体数・保存先で、変更前後を交互に実HTTP測定し、予定起点p95、完了数、未発行・拒否、回復投稿、DAT整合性、CPU・メモリ・OOMを比較します。短い低負荷試験だけで最大処理能力や長期稼働時の誤検知率を保証しません。

Bot管理画面のブラウザ検査は、`OIMO_BOT_PAGE_OUTPUT` に出力先を指定して `TestBotGuardSettingsCompatibilityAndRestart/reject` を実行し、同じ環境変数を指定して `node scripts/smoke-bot-ui.mjs` を起動します。Playwrightが通常の検索先にない場合は `OIMO_PLAYWRIGHT_MODULE`、ブラウザを指定する場合は `OIMO_CHROME` を使います。これは隔離fixtureの320px/1024px表示と、JavaScript有効・無効でのフォーム送信の検査です。稼働環境への認証後操作とは分けます。

## 異常終了からの再起動と負荷回復

負荷が下がった後の回復と、異常終了後の起動時間は別に測定します。前者は予定起点の投稿遅延と残存投稿数、後者は再起動要求から応答済みデータを再取得できるまでの時間です。

実HTTP試験へ `--crash-recovery` を追加すると、応答済み1,000投稿のDATを保存した後、測定専用コンテナをSIGKILLして同じvolumeから起動します。公開された最初のDATとETagの完全一致、WAF有効時の秘密ファイル探索への403を確認し、`crash_recovery` へ経過時間と、新しいサーバーcgroupのCPU使用時間・CPU制限による待ち時間を記録します。

他の処理が同じホストで動く場合は経過時間だけで変更の効果を断定しません。その後は同じ混合負荷で測定します。再起動前のOOMも検査します。SIGKILL時にメモリーに残っていた非必須HTTP記録は失われる場合があり、終了時の任意ログ集計は最後のプロセスだけを表します。電源断・媒体故障の証明ではありません。

```sh
mise exec -- python3 scripts/probe-thread-resources.py \
  --image "$OIMO_PERF_IMAGE" --cpus 2 --memory 512m \
  --peak-mix --egress-bps 100000000 --crash-recovery \
  --peak-post-workers 5 --peak-capacity-workers 20 \
  --peak-capacity-during-load --optional-log-stats \
  --output var/performance-crash-check.json
mise exec -- go test -race ./internal/app ./internal/bootstrap ./internal/store \
  -run 'TestPostingProcessCrash|TestRepositoryPostingCrash|TestPostingBatch|TestControlReplay' -count=1
```

投稿途中のproposal・thread・decision境界と初回WAL作成中の強制終了は、子プロセスを使う保存試験でも検査します。未受理の要求を公開せず、確定済み操作を一度だけ復旧し、改変・欠落した証跡を拒否する条件を維持します。制御WALの復旧では解析済み操作を同じ全制約の検査へ渡し、対象行だけの候補が全件成功した後に反映します。

証跡の抽出・復号を変更する場合は、厳密JSONの構文・UTF-8・Unicode・深さ・重複キーと、元byte・hash・署名の一致を確認します。最適化の前後で受理・拒否・出力が同じかをfuzzで照合し、割当量と暗号検証の費用は単体測定で確認します。

```sh
mise exec -- go test ./internal/strictjson -run '^$' \
  -fuzz '^FuzzSelectFields$' -fuzztime=20s -parallel=2
mise exec -- go test ./internal/evidence -run '^$' \
  -fuzz '^FuzzSourceEquivalence$' -fuzztime=20s -parallel=2
mise exec -- go test ./internal/evidence -run '^$' \
  -fuzz '^FuzzPayloadEncodingEquivalence$' -fuzztime=20s -parallel=2
mise exec -- go test ./internal/evidence -run '^$' \
  -bench '^BenchmarkEvidenceVerification$' -benchmem -benchtime=500ms -cpu=2 -count=3
```

投稿収集情報を変更する場合は、主体・要求HMAC、規制条件、CAPの期間・板・権限、最終受理時刻、HTTP観測との結合と、frame/DATの照合を確認します。

```sh
mise exec -- go test -race ./internal/postcapture ./internal/bootstrap \
  -run 'TestValidateKeyAndMetadata|Test.*Capture|Test.*Cap|Test.*Override|TestRepositoryPostingCrash' -count=1
mise exec -- go test ./internal/postcapture -run '^$' \
  -bench '^BenchmarkCaptureMetadata$' -benchmem -benchtime=500ms -cpu=2 -count=3
```

## WAFの追加費用と通常通信

WAFのOFF、URL・ヘッダー検査のみ、検査と大量アクセス制限を同一入力で比較します。

```sh
mise exec -- go test ./internal/bootstrap -run '^$' \
  -bench '^BenchmarkWAFMiddleware$' -benchtime=100000x -count=3 -cpu=1,4
OIMO_WAF_PERFORMANCE=1 OIMO_WAF_PERF_WORKERS=8 \
  mise exec -- go test ./internal/bootstrap \
  -run '^TestWAFPublicReadPerformance$' -count=1 -cpu=2 -v
OIMO_WAF_PERFORMANCE=1 OIMO_WAF_PERF_WORKERS=32 \
  mise exec -- go test ./internal/bootstrap \
  -run '^TestWAFPublicReadPerformance$' -count=1 -cpu=2 -v
```

単体測定では1024回線の小さな応答に対する処理時間と割り当てを確認します。回数指定を100000回以下にすることで、設定した瞬間枠内で追加費用を測ります。実HTTP試験は一時保存領域に合成投稿を作成し、DAT、subject.txt、Range、304、HEAD、板ページを混在させ、8または32並列・各条件8192件・3巡で比較します。条件の実行順を入れ替え、正常応答の完了件数／秒、p95、エラー、割り当て、プロセス全体のCPU使用量、応答本文の転送速度を記録します。

割り当てとCPUには同一プロセスの負荷生成側も含みます。`-cpu=2`はGoの並列実行数で、物理CPUの占有やcgroupの制限ではありません。この実HTTP性能試験はLinux向けです。

測定時は通常通信の費用を比べるため頻度枠を引き上げます。初期値の毎秒300件などによる意図した制限を、検査の性能低下と混同しません。単体のns/opの逆数を掲示板全体の処理能力として扱いません。loopback・合成投稿・短い試験の結果であり、長時間のCPUやメモリの安定性、本番ピーク、WANのDDoS耐性を証明しません。

```sh
mise exec -- go test -race ./internal/waf ./internal/bootstrap \
  -run 'TestTraffic|TestWAF' -count=1
mise exec -- go test ./internal/waf -run '^$' \
  -fuzz '^FuzzInspectPathFast$' -fuzztime=15s -parallel=2
```

緩めの瞬間枠、超過後の回復、公開／管理枠の分離、IPv6の集約、4096回線のメモリ上限、処理枠の解放、設定引継ぎ、実TLSでの中継元検証を検査します。高速化した通常パスが従来の注入パターン検出を省略しないことはfuzzでも確認します。

## 結果の扱い

ソース・イメージ、資源枠、負荷条件、実行結果を測定成果物へ記録します。単体の割り当て量はサーバー全体のピークメモリとは区別します。隔離Docker・loopbackの結果から、本番・WAN・実NIC・利用者端末の性能を保証しません。

共通の検査コマンドと確認範囲は[検証方法](README.md)を参照してください。
