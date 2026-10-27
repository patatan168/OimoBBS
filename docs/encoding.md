# 符号化・圧縮・並列処理

JSON、文字コード、圧縮データを処理する現在のアルゴリズムと、CPUへ分担する条件を説明します。保存の確定順序は[内部設計](architecture.md#投稿の確定)、メモリ予約と受付制御は[資源管理](features/resources.md)を参照してください。

## 処理を選ぶ

| 調べたいこと | 参照先 |
| --- | --- |
| 保存JSONの生成・入力検証・一件内の並列化 | [JSONの符号化と厳密な復号](#jsonの符号化と厳密な復号) |
| UTF-8とShift_JISの変換 | [文字コード変換](#文字コード変換) |
| HTTPと保存データの圧縮 | [Zstandardの符号化](#zstandardの符号化) |
| packの全復元・DAT範囲読取り | [Zstandardとpackの復号](#zstandardとpackの復号) |
| 同時要求で増えるworkerの上限 | [並列処理の上限](#並列処理の上限) |
| 比較条件・速度・CPU・割当量 | [検証記録](#検証記録) |

## JSONの符号化と厳密な復号

### 符号化

投稿・原本などの保存用構造体は、型定義から生成した符号化処理でJSONを組み立てます。フィールド順・要素順・HTML escape・不正UTF-8の置換・nilと空配列の区別を保ちます。固定形式のjournalでは、署名イベントと制御操作を一つのバッファへ直接書き、本文・署名を元byteからbase64化します。

生成済みのslice符号化は、128要素以上かつ先頭4要素から見積もった出力が128KiB以上の場合に分担を試みます。処理数は `min(GOMAXPROCS, 推定出力長/64KiB, 要素数/32)` です。各workerが私的な領域へ書き、全処理の終了後に元の順序で連結します。先頭4要素の出力も再利用します。

小さい入力、単一コア、サイズ上界の計算、追加worker枠を確保できない場合は逐次処理します。

### 復号と入力検証

厳密な復号では、UTF-8、構文、深さ、重複・未知キー、必須項目、型、数値範囲、nullの扱いを検査します。対応する型では構文走査と型付き復号をまとめ、省略可能boolの補完も同じ処理で行います。

本文・制御WALの操作、証拠イベント、接続観測、投稿captureなどの固定保存型は、128KiB未満・ゼロ値の宛先に限り、生成した専用復号を使います。フィールドごとの反射・map検索と配列長の事前走査を省き、私的候補の全検査成功後だけ宛先へ反映します。Input/Policyの`cap_only=false`の省略も同じ規則で補います。型自体を照合するため、埋込みで昇格したmethodを別型へ適用しません。

大きなsliceは、要素数を調べる走査でbyte境界も集めます。128要素以上・128KiB以上の配列について、構文・深さ・Unicodeを先に検査し、型検査と値の構築を要素ごとの専有領域へ分担します。小さい配列や枠不足では逐次処理します。

汎用経路の独自の `UnmarshalJSON` とmapなどの標準復号は、本文全体の検査に成功してから元の順序で実行します。末尾が不正なら呼び出さず、途中失敗した私的な復号先も公開しません。既存値へのmergeや特殊タグなど、最適化の対象外の型は従来の逐次経路を使います。専用復号の生成は、既知の純粋なスカラーと省略bool以外の独自callbackを含む型を拒否します。

実装は [jsonencode](../internal/jsonencode/array.go)、[符号化生成器](../tools/jsonencodegen/main.go)、[復号生成器](../tools/jsondecodegen/main.go)、[専用復号reader](../internal/strictjson/typed.go)、[汎用strictjson](../internal/strictjson/decode_checked.go)を参照してください。

## 文字コード変換

UTF-8とShift_JISの変換は固定表の直接参照とASCIIの一括コピーで処理します。文字変換表、変換不能文字、不正入力の受理条件は[閲覧と専ブラ向け通信](features/reading.md#閲覧と専ブラ向け通信)に従います。

非ASCIIを含む128KiB以上の入力では、文字境界で区切り、CPU数と64KiB単位の入力長に応じて最大4workerへ分担します。エンコード・デコードで追加worker枠を共有し、同時変換数も考慮します。枠がなければ呼出元で処理します。

Shift_JISの長いlead候補列で境界をすぐ確定できない場合は逐次処理へ戻します。分担した復号で不正入力を検出した場合も全体を逐次検査し、元のエラー位置と受理条件を保ちます。実装は [textcodec](../internal/textcodec/parallel.go)を参照してください。

## Zstandardの符号化

HTTP配信と保存は独自実装のZstandardを使います。配信は `Accept-Encoding` に応じてidentity・gzip・Zstandardを選び、保存方式とは独立しています。DAT差分の206応答はidentityです。対象ごとの保存形式は[圧縮範囲](architecture.md#ログ関連の圧縮範囲)を参照してください。

配信用の圧縮は文字列の探索結果を共有し、列ごとに符号化表の精度を比較します。HTTP要求内で補助workerを増やさず、資源管理で決めた生成枠を使います。

保存用のlevel 1/6/9は独自圧縮器の探索方針です。外部のZstandard CLIの圧縮レベル番号とは対応しません。level 9は16KiB未満で4候補、16KiB以上で符号化表の精度を自動選択する3候補を比較します。最小出力を選び、同じ長さなら先行候補を使います。32KiB以上・複数候補・複数CPUの場合は、一つの圧縮器内で最大2workerへ分担します。

圧縮で小さくならないWAL・snapshotの列は、各形式の非圧縮表現を使います。署名やhashを結び付ける対象は、[保存形式の規則](architecture.md#walとsnapshot)に従います。実装は [zstdencode](../internal/zstdencode/encoder.go)を参照してください。

## Zstandardとpackの復号

単一frameの展開では、Huffman literal用の追加配列を出力末尾で代用します。未消費literalを上書きしない条件と出力上限を検査します。頻出する表の深さ6〜11には定数shift・固定長表の生成実装を使い、入力境界では汎用のbit読取りへ戻します。

packの全復元とDAT範囲読取りは、対象ブロックが複数あり、展開長の合計が128KiB以上の場合に、独立したZstandard frameの展開・レコード検証を最大4workerへ分担します。全workerの検証を待ち、元の順序で結果とエラーを扱います。枠不足では呼出元で処理します。

全復元では全blockの構造検査後に投稿・DATの意味を一度検証します。DAT範囲読取りでは、選んだblock内の全投稿を検証し、要求区間を最終出力へ直接コピーします。文字コードの検証だけが必要な場合は文字列を生成しません。圧縮前後のCRC、展開長、frame終端などの検査も維持します。

実装は [zstddecode](../internal/zstddecode/decode.go)、[packの分担処理](../internal/store/pack_parallel.go)を参照してください。

## 並列処理の上限

以下の処理数には呼出元を含みます。追加workerの枠は処理系ごとに管理し、全処理共通の一つの枠ではありません。

| 処理 | 一処理の上限 | 同時要求で共有する追加worker枠 |
| --- | --- | --- |
| JSONの配列符号化・復号 | CPU数と入力サイズに応じる | 符号化・復号の合計で `GOMAXPROCS−1` |
| UTF-8・Shift_JISの変換 | 最大4worker、CPU数・入力長にも従う | 両方向で最大3。実行中の変換数も考慮 |
| packのframe展開・検証 | 最大4worker、CPU数・block数にも従う | 全要求で `min(3, GOMAXPROCS−1)` |
| 保存圧縮の候補比較 | 最大2worker | 圧縮器ごとの補助1。呼出側の処理枠も適用 |

JSONは追加枠をまとめて即時確保し、確保できない場合は待たずに逐次処理します。分担したworkerの内側でJSON配列の分担を重ねません。投稿候補の準備・署名・制御WALの検証にもそれぞれ上限があり、[投稿の保存手順](architecture.md#返信をまとめて保存する)とメモリ予約に従います。

## 検証記録

| 対象 | 条件・結果 |
| --- | --- |
| JSON | [固定形式の符号化](testing/posting-json.md)・[生成符号化と構文検査](testing/posting-json-second.md)・[型検査と復号](testing/posting-json-third.md)・[専用復号と単一スレッド投稿](testing/posting-json-typed.md)・[一件内の並列化](testing/json-single-parallel.md) |
| 文字コード | [単体の変換・総CPU・割当量](testing/textcodec-parallel.md)・[実HTTP投稿](testing/textcodec-posting.md) |
| 圧縮 | [gzipレベル9との比較](testing/high-compression.md)・[WALの圧縮範囲](testing/posting-io-mitigation.md) |
| 復号 | [独立frameの分担](testing/zstd-decode-parallel.md)・[単一frameの処理削減](testing/zstd-decode-efficiency.md)・[表参照の追加改善](testing/zstd-decode-tuning.md)・[pack全体](testing/pack-read-efficiency.md) |

単体の経過時間、総CPU時間、割当量、実HTTPの処理量と遅延は別の指標です。単体の高速化から投稿全体や本番負荷の改善率を推定しません。過去の試行・不採用候補は[検証記録の一覧](testing/measurements.md)から確認できます。
