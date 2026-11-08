# 回線分類と標準カタログ

国内の携帯・固定系、地域ISP、CATV、IPoE・企業アクセス網の203 ASN、VPN関連7 ASNに、クラウド16・衛星1・学術9・政府機関1を加えた237 ASNを対象にします。自動分類の固定回線は `ﾜｯﾁｮｲ`、分類不明でも事業者キーが判明していれば事業者別の独自呼称、事業者キーが不明・呼称未登録なら `ﾜｶﾗﾝ` です。固定・携帯混在は以下の独自呼称です。

| 混在回線の事業者 | 投稿の呼称 | ID末尾 |
| --- | --- | --- |
| OCN | `ｵｼﾏｾﾞ` | `0` |
| KDDI | `ｱｳｱｳﾏｾﾞ` | `0` |
| SoftBank | `ﾔﾜﾗｶﾏｾﾞ` | `0` |
| IIJ | `ｲｲｼﾞｬﾝ` | `0` |
| OPTAGE | `ｵﾌﾟﾏｾﾞ` | `0` |
| BIGLOBE | `ﾃﾞｶﾁｷｭｰ` | `0` |

これらはOimoBBS独自の掲示板風呼称です。事業者名そのものは投稿の呼称に使いません。混在で事業者キーが空、または対応する呼称が未登録なら `ﾜｯﾁｮﾏｾﾞ / 0` です。分類不明でも同じ事業者キーには同じ呼称を使います。固定回線は事業者によらず `ﾜｯﾁｮｲ` です。確認済みDNSによる携帯・MVNO等の分類と、DNS異常時の`h/H`表示を優先します。

取得済みの旧自動表でも、新規投稿とIP確認には補正後の呼称を使います。標準取得元・カテゴリーの保存済み呼称は、次回の自動更新または「今すぐ更新」で補正します。独自取得元・カテゴリーの保存設定と、共通・板別の手動CIDR上書きは保持します。過去の投稿は再生成しません。

| 調べたいこと | 参照先 |
| --- | --- |
| 管理画面で更新状況や編集対象を探す | [回線分類の操作](admin-guide.md#回線分類を確認する) |
| 自動取得と既存設定の扱い | [初回と既存サイト](#初回と既存サイト) |
| 毎日・毎週・毎月の実行日時を設定する | [更新の予定](#更新の予定) |
| 分類が示す範囲・誤判定への対応 | [判定の範囲](#判定の範囲) |
| 学術・企業・クラウド・衛星の表示 | [特殊な分類と表示](#特殊な分類と表示) |
| DNS補完の条件・優先順位・照会上限 | [DNS補完の共通条件](#dns補完の共通条件) |
| DNSが逆引き不能・不整合な場合 | [逆引きの特殊表示](#逆引きの特殊表示) |
| 固定回線のホスト名による補完 | [固定回線のDNS補完](#固定回線のdns補完) |
| 携帯・公衆Wi-Fiのホスト名による補完 | [携帯・公衆Wi-FiのDNS補完](#携帯公衆wi-fiのdns補完) |
| クラウド・VPSのホスト名による補完 | [クラウド・VPSのDNS補完](#クラウドvpsのdns補完) |
| 登録済みの事業者とASN | [取得元一覧](#取得元一覧)・[VPN事業者](#vpn事業者共有基盤) |

## 分類不明の事業者別呼称

標準のunknown 87 ASNを79個の事業者キーで区別します。呼称はOimoBBS独自のもので、回線種別は `unknown` のままです。事業者名から固定・携帯・VPNなどを推測する変更ではありません。同じ事業者の複数ASNは同じ呼称になり、契約ブランドまでは確定しません。キーが空・呼称未登録の場合と、分類が衝突してキーを外した場合は `ﾜｶﾗﾝ / 0` です。

| 事業者（管理用） | キー | 投稿の呼称 |
| --- | --- | --- |
| Dream Wave Shizuoka Co. Ltd. | `across` | `ﾕﾒﾉﾅﾐ` |
| Air Internet Service Co. Ltd. | `air` | `ｿﾗﾉﾐﾁ` |
| アルテリア / VECTANT / UCOM | `arteria` | `ｱﾙｱﾙ` |
| Densan Co. Ltd. | `avisnet` | `ｱﾋﾞｱﾋﾞｰ` |
| BBIX / BB.excite系 | `bbix` | `ﾋﾞﾋﾞｸｽ` |
| BEKKOAME INTERNET INC. | `bekkoame` | `ｱﾒﾁｬﾝ` |
| BIGLOBE | `biglobe` | `ﾃﾞｶﾁｷｭｰ` |
| KISTEM Co. Ltd. | `biwalobe` | `ﾋﾞﾜﾋﾞﾜｰ` |
| Check Point | `checkpoint` | `ﾐﾊﾘﾊﾞﾝ` |
| Tonami System Solutions Co. Ltd. | `coralnet` | `ｻﾝｺﾞﾉﾜ` |
| Cyberzone / Surfshark系 | `cyberzone` | `ｻｰﾌｧｰ` |
| TOYOTA SYSTEMS CORPORATION | `d-cruisenet` | `ｸﾙｰｽﾞﾝ` |
| D.C.N. Corporation | `dcn` | `ﾃﾞｼﾃﾞｼｰ` |
| DODO K.K. | `dodo` | `ﾄﾞｰﾄﾞｰ` |
| Dolphin | `dolphin` | `ｲﾙｶｰ` |
| DOVA Corporation | `dova` | `ﾄﾞﾊﾞﾄﾞﾊﾞｰ` |
| EDION Corporation | `edion` | `ｶﾃﾞﾝﾃﾞﾝ` |
| EditNet Incorporated | `editnet` | `ｶｷｶｷｰ` |
| OPTAGE Inc. | `finder` | `ﾐﾂｹﾀｰ` |
| Canon IT Solutions Inc. | `fine` | `ｵｹﾞﾝｷｰ` |
| Hokuden Information System Service Co. Ltd. | `fitweb` | `ﾌｨｯﾄｯﾄ` |
| NRI SecureTechnologies Ltd. | `fnc` | `ｶｷﾞﾉﾓﾘ` |
| FreeBit / DTI / hi-ho系 | `freebit` | `ﾀﾀﾞﾉｶｹﾗ` |
| NTT DOCOMO BUSINESS Inc | `gofors` | `ﾐｶｶﾋﾞｼﾞ` |
| ITEC HANKYU HANSHIN CO. LTD. | `hanshin` | `ﾄﾗﾄﾗｰ` |
| HARENET INC. | `harenet` | `ﾊﾚﾊﾞﾚｰ` |
| HOKKAIDO TELECOMMUNICATIONS NETWORK Co. Inc. | `hotnet` | `ﾎｶﾎｶﾈｯﾄ` |
| Hokuriku Telecommunication Network Co. | `htcn` | `ﾎｸﾎｸﾂｳ` |
| OTNet Co. Inc. | `ii-okinawa` | `ﾅﾝｸﾙｰ` |
| Ishikawa Computer Center Co. LTD. | `incl` | `ｲｼﾉｶﾜ` |
| FUJITSU LIMITED | `infoweb` | `ﾌｼﾞﾌｼﾞ` |
| Advanced Software Technology & Management Research Institute of KYOTO | `ip-kyoto` | `ﾐﾔｺﾉﾐﾁ` |
| Naganoken Kyodou Densan Co.Ltd. | `janis` | `ｼﾅﾉﾉﾜ` |
| JETINTERNET Corporation | `jetinternet` | `ﾋﾞｭｰﾝ` |
| JPIX / JPNE系 | `jpne` | `ｼﾞｪﾋﾟﾋﾟ` |
| Kamoike.net LLP | `kamoike-net` | `ｶﾓﾉｲｹ` |
| M247 | `m247` | `ﾆﾖﾅﾅ` |
| IMS Corporation | `magma` | `ｸﾞﾂｸﾞﾂｰ` |
| Fujitsu Systems Applications & Support Limited | `mediaweb` | `ﾒﾃﾞｨﾒﾃﾞｨ` |
| Minaminihon Information Processing Center Co Ltd | `minc` | `ﾐﾅﾐﾅﾐ` |
| Mirai Communication Network Inc. | `mirai` | `ﾐﾗｲﾍｺﾞｰ` |
| mitene internet co. ltd. | `mitene` | `ﾐﾃﾐﾃｰ` |
| Mullvad VPN | `mullvad` | `ﾓｸﾞﾗｰ` |
| Global Network Core Co. Ltd. | `ndac` | `ｾｶｲﾉｼﾝ` |
| Netforest Inc. | `netforest` | `ﾓﾘﾉﾅｶ` |
| GMO NetIRD Inc. | `netird` | `ｸﾏﾉﾐﾁ` |
| NSK Co. Ltd. | `nsk` | `ﾆｽｺﾆｽｺ` |
| NTTPC / InfoSphere | `nttpc` | `ﾐｶｶﾋﾟｼｰ` |
| OBIS | `obis` | `ｵﾋﾞｵﾋﾞｰ` |
| Oedo Telecom Inc | `oedo` | `ｴﾄﾞｯｺｰ` |
| PacketHub / NordVPN系 | `packethub` | `ﾊﾟｹﾓﾘ` |
| Phoenix Communications Inc. | `phoenix` | `ﾌｼﾁｮｰ` |
| Proton / Proton VPN系 | `proton` | `ﾖｳｼｸﾝ` |
| 楽天 / FUSION / xpass | `rakuten` | `ﾗｸﾗｸﾃﾝ` |
| Japan Communication Inc. | `rmgr-mix` | `ﾂｳｼﾝﾎﾞ` |
| SaiNet | `sainet-as` | `ｻｲｻｲｰ` |
| Super Godzilla Communications GK | `sgcom` | `ｶｲｼﾞｭｰ` |
| Niigata Communication Service | `shibata` | `ｺﾒﾄﾞｺﾛ` |
| NetComBB Co. Ltd. | `sni-jp` | `ﾈｺﾑｺﾑ` |
| SoftBank / ODN | `softbank` | `ﾔﾜﾗｶﾏｾﾞ` |
| SoftEther Corporation | `softether` | `ﾔﾜﾗｶﾄﾝﾈﾙ` |
| SUZUYO SHINWART CORPORATION | `ss` | `ｽｽﾞﾉｵﾄ` |
| STNet Incorporated | `stcn` | `ｼｺｸﾉﾜ` |
| SUN FIELD INTERNET LIMITED | `sunfield` | `ﾋﾅﾀﾊﾞﾀｹ` |
| SYNAPSE Co. Ltd. | `synapse` | `ｼﾅﾌﾟﾌﾟ` |
| TAM Co. Ltd. | `tam` | `ﾀﾑﾀﾑｰ` |
| Tokyo Broadcasting System Television Inc. | `tbs-net` | `ﾃﾚﾋﾞｯｺ` |
| Community Network Center Inc. | `tdnc` | `ﾂﾅｶﾞﾙﾜ` |
| NDS Co. Ltd. | `tikitiki` | `ﾁｷﾁｷｰ` |
| Tsukuba Internet Service Corporation | `tins-net` | `ﾂｸﾂｸﾊﾞ` |
| TOHKnet Co. Inc. | `tohknet` | `ﾄｰﾎｸﾎｸ` |
| TOKAI / TNC | `tokai` | `ｳﾐﾉﾐﾁ` |
| transix / インターネットマルチフィード | `transix` | `ﾄﾗﾝﾄﾗﾝ` |
| UNIADEX LTD. | `u-netsurf` | `ﾅﾐﾉﾘﾕｰ` |
| Value Core Inc. | `vciu-net` | `ﾈｳﾁﾉｼﾝ` |
| Wire and Wireless Co. Ltd. | `wi2` | `ﾜｲﾜｲﾄﾞｺ` |
| Gunma Internet Co .ltd | `wind` | `ｶｾﾞﾏｶｾ` |
| Wingtechnology Communications Inc. | `wintech-com` | `ﾂﾊﾞｻﾉﾜ` |
| NTT-ME Corporation | `xephion` | `ｾﾞﾌｨﾌｨ` |

## 初回と既存サイト

未設定サイトの初回起動で標準取得元を登録し、国コード・日本IP・既知VPNと合わせて自動取得します。登録・APIキーは不要です。管理画面「回線分類」で取得状況を確認できます。

既存サイトの分類は、通常の自動更新や「今すぐ更新」で見直しを反映します。専用の更新操作は不要です。

| 操作・状態 | 更新の動作 |
| --- | --- |
| 自動更新が有効 | 保存済みの間隔または日時の予定に従って取得。予定前の確認では設定も分類表も変更しない |
| 今すぐ更新・管理APIの更新要求 | 自動更新の停止状態を維持したまま、今回だけ取得する |
| 全業者の標準取得元を追加して更新 | 不足する標準取得元・カテゴリーを追加し、自動更新を有効にする。指定済みの予定に従って取得する |
| 自動更新が停止中 | 自動取得しない。再起動だけでは再開しない |
| 取得に失敗 | 前回成功した分類表を使い続ける。手動上書きは保持する |

### 更新の予定

管理画面「回線分類」→「自動更新の設定」で、更新方式と開始時刻を指定して保存します。日時はすべて日本時間です。画面上部で次回予定・前回の成功・前回の取得を確認できます。

| 更新方式 | 設定例・動作 |
| --- | --- |
| 間隔を指定 | 1〜168時間ごと。従来どおり、設定変更後は取得を開始する |
| 毎日 | 毎朝04:00など、1日1回の時刻を指定 |
| 毎週 | 月曜日04:00など、曜日と時刻を指定 |
| 毎月 | 1日04:00、月末04:00など、日付と時刻を指定。31日などが存在しない月は月末に実行 |

時刻指定の新規設定・規則変更・停止からの再開は保存時から有効です。すでに過ぎた時刻は次の回まで待ち、保存だけでは取得を始めません。同じ規則の再保存や再起動で開始日時を先延ばしにはしません。起動時に当日・当週・当月の予定を過ぎていて未実行なら、その回を取得します。確認は約1分ごとで、指定時刻から約1分以内を目安に開始します。

時刻指定では取得の成功・失敗に関係なく各回1回です。失敗時は次の予定、または「今すぐ更新」で再実行します。間隔指定の失敗は従来どおり1時間後に再試行します。「今すぐ更新」を予定前に実行しても次の予定は維持し、予定後に実行した場合はその回の取得として扱います。手動更新は停止状態・規則を変更しません。

時刻指定を初めて保存したサイトはreader108以降が必要です。既存の間隔設定はそのまま利用できます。管理APIの設定では`schedule`省略時に現在の予定を保持し、明示的な`null`で間隔指定へ戻します。暦指定は`frequency`（`daily`・`weekly`・`monthly`）、`time`（`HH:MM`）、`weekday`（日曜0〜土曜6）、`day`（月末0・1〜31）、`starts_at_ns`（入力時`"0"`、保存時にサーバーが確定）をすべて指定します。`next_update`は次回予定のRFC3339文字列で、停止中は空です。

### 標準分類の見直しと手動上書き

取得を始める際に、見直し対象の28 ASNの取得元と標準の事業者カテゴリーを上書きします。対象の名前・回線区分・表示名・ID末尾・プロバイダ識別キー・カテゴリーの説明は、編集済みでも標準値に戻ります。対象外の取得元・カテゴリーと、サービス固有のカテゴリーは変更しません。

**共通・板別の手動IP/CIDR上書きと、国・VPNの手動上書きは保持します。** 更新の予定と自動更新の停止状態も維持します。個別のIP範囲の誤判定を修正するときは、取得元の標準値を変更するのではなく、手動上書きを使ってください。

標準設定の見直しを先に保存し、新しい分類表は取得成功後に閲覧・投稿制限へ反映します。取得失敗時は旧表を保持し、過去の投稿は再生成しません。回線区分が変わると、その区分に設定した許可・拒否条件も変わります。

## 国の重複

閲覧・投稿制限の国条件では、国内事業者と確認できるIPを登録国が国外・不明でもJPとして評価します。元の登録国データは変更しません。対象と他の拒否条件の扱いは[閲覧制限の判定](features/reading.md#条件と判定の優先順位)を参照してください。

同じIP範囲が複数の国に登録されていても、分類表全体の更新は止めません。

| 同じ範囲の登録内容 | 国判定 |
| --- | --- |
| 同じ国の重複 | その国 |
| 異なる国が重複し、日本を含まない | 不明 |
| 日本と他国が重複 | 日本を優先 |

不明の範囲を、より広いIP範囲の国や「日本表に非掲載なので国外」という判定で埋めません。異なる長さの範囲は従来どおり最長一致で照合します。日本のIP表に掲載された範囲は日本を優先し、管理者の明示上書きは自動判定より優先します。次の取得で重複がなくなれば通常の国判定に戻ります。国が不明でも、回線業者・既知VPNの判定は独立して行います。国の判定を必要とする制限では、従来どおり不明を許可判定にしません。

重複を含む国表の保存後は最低reader101が必要です。保存済みの正常な表を変換する作業は不要です。

## 判定の範囲

標準カタログの未分類は87 ASNです。見直しで補完した28 ASN（固定推定25・固定と携帯の混在2・学術網1）の根拠と、分類を見送った対象は[見直しと検証の記録](testing/network-catalogue-review.md)を参照してください。

ASNの公開経路から推定します。同じ事業者の複数ASNには同じプロバイダ識別キーを使います。固定と携帯（MVNOを含む）の混在が確認済みのASNは「固定・携帯混在」（`mixed`）、用途が未確認の企業網は「不明」（`unknown`）です。共有上流・IPoEでは契約サービス名を確定できず、別ブランドでも同じ上流回線として表示する場合があります。確認できた範囲は共通または板別の上書きで修正してください。

取得元は[JPNICのASN一覧](https://www.nic.ad.jp/ja/ip/as-numbers.txt)と[ipverseの事業者情報](https://github.com/ipverse/as-metadata)を照合し、[ASNごとの公開IP範囲](https://github.com/ipverse/as-ip-blocks)が取得できるものを選んでいます。経路を取得できないASNは標準取得元から除外します。

VPN業者は[X4BNetのVPN向けASN一覧](https://github.com/X4BNet/lists_vpn/blob/main/input/vpn/ASN.txt)と事業者情報を照合します。PacketHub / NordVPN系、Cyberzone / Surfshark系、Proton、Mullvad、Check Point、M247の公開経路を取得し、既知VPN判定や国外表示にもプロバイダキーを補完します。ASN全域をVPN扱いにはせず、VPN該当性は従来の既知VPNリストで判定します。VPN検出範囲そのものを広げる変更ではありません。共有基盤では利用中のVPNブランドを保証しません。

## 特殊な分類と表示

| 区分 | 名前欄の呼称 | ID末尾 | 自動判定の根拠 |
| --- | --- | --- | --- |
| 大学・学術網 | `ｶﾞｯｸｼ` | `6` | 対象ASN、正引き確認済みのAC.JPホスト |
| 学校 | `ﾎﾞﾝﾎﾞﾝ` | `7` | 正引き確認済みのED.JPホスト |
| 官公庁 | `ｺﾑｲｰﾝ` | `G` | 対象ASN、正引き確認済みのGO.JPホスト |
| 企業内回線 | `ｼｬﾁｰｸ` | `C` | 管理者が確認した範囲の手動上書き |
| クラウド・VPS | `ｸﾓﾉｳｴ` | `V` | 対象事業者ASN、正引き確認済みの専用ホスト。Virtual/VPSのV |
| 衛星回線 | `ｳﾁｭｰ` | `U` | Starlink ASN。UniverseのU |

学術・学校・官公庁・企業内の呼称と末尾は[5ch公式WikiのBBS_SLIP](https://info.5ch.io/index.php/BBS_SLIP)を参照しています。`ｸﾓﾉｳｴ`と`ｳﾁｭｰ`はOimoBBS独自の5ch風呼称です。企業のCO.JPドメイン全体を企業内回線とは判定しません。機関の網・確認済みドメインを推定する区分で、投稿者の所属・職業・所在地を証明するものではありません。DNSの対象は[JPRSの属性型ドメインの対象](https://jprs.jp/about/jp-dom/spec/)に従います。

既知VPN・板別および共通の手動上書きは、特殊用途の自動表示より優先します。自動取得表で特殊用途が判明した回線は、国外でも`ｸﾓﾉｳｴ / V`などを表示します。国コードによる接続許可・拒否は独立して有効です。通常の国外回線は国コード、既知VPNは`ｺﾝﾆﾁﾜ / 8`を使い、事業者キーを補完します。

自動取得表の同一prefixが複数の取得元に含まれる場合、種別・呼称・末尾が一致すればその分類を保ち、異なる事業者キーは空にします。種別・呼称・末尾のいずれかが食い違う場合は、そのprefixを「回線種別が不明」（`ﾜｶﾗﾝ / 0`・事業者キーなし）として保持します。取得順で一方を採用したり、より広いprefixの分類で埋めたりせず、他の正常な範囲も更新します。不明化した範囲の回線規制は「回線種別が不明」の許可設定に従います。国・既知VPNの判定と手動上書きは独立して維持します。形式不正・空集合・容量超過では従来どおり更新全体を中止します。

NifMo・LIBMO・LinksMate・SORACOM・トーンモバイル・ワイヤレスゲート・公衆Wi-Fi・機内Wi-Fi・船舶用衛星などの5ch風プリセットも用意します。プリセット追加だけでは自動判定されません。専用のIP範囲などを確認してから上書きに使います。船舶用SafeComNetの既存呼称は`ﾀﾆｯｸ / S`です。

追加したASNは、Starlink、さくらインターネット、Hetzner、OVHcloud、DigitalOcean、Vultr、Akamai/Linode、Scaleway、Contabo、AWS、Google Cloud、Microsoft、Oracle、Alibaba、SINET、東京大学、NCA5、HEPNET-J、SuperCSI、九州大学、APAN-JP、WIDE/AI3、科学技術振興機構です。同一事業者の複数ASNは一つのプロバイダキーへ束ねます。

## DNS補完の共通条件

逆引きしたホスト名を正引きし、接続元と同じIPが返った場合だけ、下記の専用ホスト名から回線種別を補完します。ISPや親ドメイン全体の用途を推測する処理ではありません。共有上流・IPoEでは、プロバイダキーが同じでも契約ブランドは確定しません。

分類と表示は、次の順で採用します。国・既知VPNによる許可・拒否は独立して判定します。

1. 板別の手動上書き
2. 共通の手動上書き
3. 既知VPN
4. 自動取得表の特殊用途（クラウド・衛星・学術網など）
5. 登録国による国外表示
6. 逆引き・正引きで確認したサービス
7. 通常の自動取得表
8. 回線種別が不明

自動取得表の用途が「不明」でも、専用ホスト名が確認できれば個々のIPを補完できます。取得元一覧の区分はASN全体を示すため、この補完で一覧の「不明」が変わることはありません。

### 照会とキャッシュ

| 項目 | 動作・上限 |
| --- | --- |
| 取得方式 | OS標準DNS、または固定のGoogle Public DNS over HTTPS。Googleから別取得先へ切り替えない |
| 正引きの種類 | IPv4はA、IPv6はAAAAだけ。IPv4-mapped IPv6はIPv4として扱う |
| 複数のPTR | 既知サービスを先に確認。各区分内は回答順を維持し、同じ名前は大文字小文字・末尾ドットを正規化して1回だけ照会 |
| 照会の上限 | 全体1秒、初回の呼出元待機750ms、同時4照会、処理待ちを含め64件 |
| 回答の上限 | PTR16名、正引き結果32件 |
| キャッシュ | 最大1024 IP。確認済み名は10分、確認できなかった結果は30秒 |
| 設定保存時 | DNS取得方式が同じなら確認結果を維持。旧設定の未指定とOS標準DNSは同じ方式として扱う |
| 実行場所 | 投稿ワーカーの外で取得。判定時は有効なキャッシュだけを参照 |

必要な側の正引きが失敗・不一致なら、サービス分類には採用しません。不要なA/AAAAへの照会や、無関係なPTRへの照会待ちで、確認可能なサービスを取りこぼすことを防ぎます。有効なPTR名は、照会順と別に重複のない一覧として観測記録へ残します。

補完はDNS結果を取得した新規投稿・IP確認から適用します。過去のDATは再生成しません。管理画面の「IP確認」で、回線区分・判定根拠・DNS確認結果を確認できます。

## 逆引きの特殊表示

回線種別の「不明」と、DNSの不存在・不整合は別の判定です。[5ch公式Wiki](https://info.5ch.io/index.php/BBS_SLIP)の呼称と詳細ID末尾を参照し、通常の分類へ次の表示を適用します。

| DNSの結果 | 表示 | 詳細ID末尾 |
| --- | --- | --- |
| PTRなし（正常な空回答・NXDOMAIN） | `ｱﾝﾀﾀﾞﾚ` | `h` |
| PTR名が不正、または正引きが元IPに不一致 | 登録国コード（不明は`ZZ`） | `H` |
| 逆引きと正引きが一致 | サービス・ASN・未分類の表示 | 分類どおり |
| 取得待ち・タイムアウト・SERVFAIL・未取得・期限切れ | 従来の表示を維持 | 未分類なら`0` |

手動上書き・既知VPN・自動取得表の特殊用途を優先します。`h/H`は呼称と末尾だけを変更し、規制用の回線種別・プロバイダキー・国・VPN属性は変えません。逆引き不能を拒否する設定はPTR取得の成否で判定し、正引き不一致を同じ拒否条件には含めません。

`h/H`は詳細な回線表示とワッチョイに反映します。`none`は末尾なし、従来端末区分の`checked`は通常`0`です。公開5chの内部判定アルゴリズムではなく、上記の確認可能な条件を本システムの判定基準とします。

## 固定回線のDNS補完

共通の確認条件で、以下を`fixed / ﾜｯﾁｮｲ / 0`に分類します。表の「数字」は数値部分、「ホスト」はドメイン直下の1ラベル、`*`はホスト名の残り部分です。正確なパターンは管理画面のサービス判定対応表で確認できます。

| サービス | プロバイダキー | 対象のホスト名 |
| --- | --- | --- |
| UCOM / アルテリア | `arteria` | `*.ftth.ucom.ne.jp` |
| OCN 光ネクスト | `ocn` | `p数字-ipngn数字.*.ocn.ne.jp` |
| OCN系 フレッツPPPoE | `ocn` | `*.ppp.ocn.ne.jp` |
| IIJ FiberAccess/F | `iij` | `数字.数字.数字.数字.bf.2iij.net` |
| IIJmio フレッツ接続（IIJ4U統合） | `iij` | `数字.数字.数字.数字.dy.iij4u.or.jp` |
| ASAHIネット v6コネクト系 | `asahi-net` | `ホスト.v6connect.net` |
| GMOとくとくBB フレッツ接続 | `gmobb` | `数字-数字-数字-数字.接続先.ap.gmo-isp.jp` |
| GMOとくとくBB フレッツ固定IP | `gmobb` | `数字.数字.数字.数字.ap.gmobb-fix.jp` |
| au one net | `kddi` | `*.ppp-bb.dion.ne.jp` |
| So-net | `sonet` | `*.ap.so-net.ne.jp` |
| NURO 光 | `sonet` | `*.ap.nuro.jp` |

追加判定の根拠と適用範囲：

- OCN系PPPoE：[@niftyの逆引き名変更案内](https://support.nifty.com/cs/suptopics/detail/210318480133/1.htm)。他社ブランドも同じ上流網を使うため、キーは`ocn`とします。
- IIJ FiberAccess/F：[公式Q&A](https://www.iij.ad.jp/biz/faf/)の数値4ラベル形式に限定します。
- IIJmio：[IIJ4U統合時の公式FAQ・項目40](https://www.iijmio.jp/4uunity/qa/)と[数値4ラベル形式の公式例](https://order.partner.iij.jp/static/extrapartnerinfo/hikari-connect/faq/index.html)を参照します。後者のLaITサービスは終了済みで、現在の契約サービス名は確定しません。
- ASAHIネット：[公式設定ガイド](https://asahi-net.jp/support/guide/fixedip/)がIPIP用と案内する`v6connect.net`に限定します。モバイルと共有する`asahi-net.or.jp`全体は対象外です。公式には正引きを登録しない旨もあるため、正引きが一致しないIPには適用しません。
- GMOとくとくBB：[フレッツ接続の変更案内](https://gmobb.jp/news/details/77/)と[固定IPの公式FAQ](https://help.gmobb.jp/faq/faq_detail.html?id=1095)を参照します。前者は2011年の案内のため、現在もその形式が逆引き・正引きで確認できるIPだけに適用します。

## 携帯・公衆Wi-FiのDNS補完

| サービス | 対象のホスト名 | 回線種別 | 呼称・末尾 |
| --- | --- | --- | --- |
| OCNモバイルONE | `p数字-omed数字.地域.ocn.ne.jp` | `mvno` | `ﾜﾝﾄﾝｷﾝ / M` |
| IIJmio系 | `*.vmobile.jp` | `mvno` | `ﾌﾞｰｲﾓ / M` |
| mineo | `*.mineo.jp` | `mvno` | `ｵｲｺﾗﾐﾈｵ / M` |
| b-mobile系 | `*.bmobile.ne.jp` | `mvno` | `ﾍﾞｰｲﾓ / M` |
| ドコモ spモード系 | `*.spmode.ne.jp`、`*.dcmisp.ne.jp` | `mobile` | `ｽﾌﾟｯｯ / d` |
| ドコモ mopera | `*.mopera.net` | `mobile` | `ﾍﾟﾗﾍﾟﾗ / D` |
| au | `*.au-net.ne.jp` | `mobile` | `ｱｳｱｳ / a` |
| SoftBank iPhone系 | `*.panda-world.ne.jp` | `mobile` | `ｻｻｸｯﾃﾛ / p` |
| SoftBank / Y!mobile系 | `*.openmobile.ne.jp` | `mobile` | `ｵｯﾍﾟｹ / r` |
| SoftBank データ通信系 | `*.access-internet.ne.jp` | `mobile` | `ｱ-ｸｾ- / x` |
| Wi2 | `*.wi-fi.wi2.ne.jp` | `wifi` | `ﾜｲﾜｲ / F` |
| docomo Wi-Fi | `*.m-zone.jp` | `wifi` | `ｴﾑｿﾞﾈ / F` |

ドコモの新しい`dcmisp.ne.jp`は[開発者向け公式情報](https://www.docomo.ne.jp/service/developer/smart_phone/spmode/)に基づきます。ahamo・IoT NETも同じドメインを使うため、契約ブランドは確定しません。従来の`spmode.ne.jp`も対象です。

## クラウド・VPSのDNS補完

共通の確認条件で、以下を`hosting / ｸﾓﾉｳｴ / V`に分類します。任意ドメインへ逆引きを変更したIPは、この専用ホスト名による補完の対象外です。

| サービス・キー | 対象のホスト名 | 根拠 |
| --- | --- | --- |
| ServersMan@VPS・`freebit` | `v-数字-数字-数字-数字.ub-freebit.net` | [DTIの逆引き設定案内](https://www-wp.dream.jp/search.php/?cat=39&paged=7) |
| Amazon EC2・`aws` | `ec2-数字-数字-数字-数字.リージョン.compute.amazonaws.com`、`ec2-数字-数字-数字-数字.compute-1.amazonaws.com` | [公式の公開DNS形式](https://docs.aws.amazon.com/whitepapers/latest/aws-fault-isolation-boundaries/globally-scoped-operations-best-practices.html) |
| Microsoft Azure・`microsoft` | `ホスト.リージョン.cloudapp.azure.com`、`ホスト.cloudapp.net` | [公式の逆引き設定](https://learn.microsoft.com/en-us/azure/dns/dns-reverse-dns-for-azure-services) |
| Google Cloud・`gcp` | `数字.数字.数字.数字.bc.googleusercontent.com` | [公式の標準逆引き案内](https://docs.cloud.google.com/compute/docs/instances/create-ptr-record)、[公式サンプルの形式](https://docs.cloud.google.com/chronicle/docs/soar/marketplace-integrations/ssl-labs) |
| さくらのVPS・`sakura` | `ホスト.vs.sakura.ne.jp` | [公式の標準逆引き設定](https://manual.sakura.ad.jp/vps/controlpanel/reverse-hostname.html)、[公式設定例の専用ドメイン](https://manual.sakura.ad.jp/vps/os-reinstall/iso-install/alpine.html) |
| Hetzner・`hetzner` | `static.数字.数字.数字.数字.clients.your-server.de` | [公式の標準PTR形式](https://docs.hetzner.com/networking/dns/record-types/ptr-record/) |
| Akamai / Linode・`linode` | `ホスト.members.linode.com`、`数字-数字-数字-数字.ip.linodeusercontent.com` | [公式の新旧標準逆引き形式](https://techdocs.akamai.com/cloud-computing/docs/configure-rdns-reverse-dns-on-a-compute-instance) |

Google Cloud・さくらは、設定案内と専用ドメインの公式例を組み合わせた判定です。回線用途の分類であり、接続者の本人性・安全性やVPN利用の有無を保証しません。

## 容量と互換性

取得元・表示カテゴリーは各256件、分類表は4万prefix、取得は最大8並列・25秒です。ASN・日本・VPN両family・全世界登録国を共通の取得workerへ投入し、国別JSONは利用可能なコア数に合わせて最大4並列で解析します。archiveの展開は32MiB、登録国表は30万prefixまでです。

新規保存はZstandardです。64KiBを超える設定は`zstd-config-v1`（展開1MiB）、1024行を超える分類表は`zstd-json-v1`（展開6MiB/4万行）で保存します。登録国と日本/VPNの圧縮値も、長さとCRCを持つ`ONZ1`の単一Zstandard frameをbase64化します。割当前に展開長を検査し、破損・非正規base64・連結frame・後続データを拒否します。

回線分類の更新に使う制御操作JSONは最大2MiBです。`network:active`の値は、包みと管理receipt用に128KiBを確保した1920KiBまでです。1MiBを超える操作では`network:active`・`site:state`と、回線設定変更の小さな再送記録（4KiB以下）だけを許可し、他のcollection・通常のJSON入力は従来の1MiB上限を維持します。全取得元が成功して容量内に収まった場合だけ、耐久保存後に公開表を切り替えます。

同じ圧縮前byteの再圧縮と、同じ国・日本/VPN表の索引構築は、それぞれ最大2版のcacheで省きます。変更した入力は完全検査し、管理者の上書きは別に検証・複製します。メモリを増やすとGCの余裕は増えますが、cacheは取得元数やメモリ量に比例して増やしません。

新規のZstandard保存と拡張容量はreader 102以降が必要です。特殊区分はreader 92、DNS特殊表示の新規投稿はreader 93以降です。新codecでの失敗記録も含め、必要なreader境界を同じ制御操作で保存します。旧gzip保存値の読取り経路は削除しました。WAL・snapshotに残る分類値は、監査のハッシュ参照と認証境界を保ってZstandardへ変換してから接続します。失敗時は前回成功表・手動設定を維持します。

実データを固定した計測は[回線分類更新の高速化](testing/network-update-optimization.md)を参照してください。

## 取得元一覧

「固定・携帯混在」は固定と携帯の両用途が確認済みの区分で、個々の接続方式を保証しません。確認済みサービスのホスト名で固定・携帯を識別できる場合は、その分類を優先します。「不明」は用途自体が未確認の区分です。管理画面では名前・ASN・識別キーの検索と回線区分の絞り込みができます。

| 事業者・アクセス網 | プロバイダキー | ASN | 回線区分 |
| --- | --- | --- | --- |
| OCN | `ocn` | AS4713 | 固定・携帯混在 |
| docomo | `docomo` | AS9605 | 携帯推定 |
| 楽天モバイル | `rakuten` | AS138384, AS10012 | 携帯推定 / 不明 |
| KDDI | `kddi` | AS2516 | 固定・携帯混在 |
| SoftBank | `softbank` | AS17676, AS4725, AS18069 | 固定・携帯混在（AS17676）/ 不明 |
| IIJ | `iij` | AS2497 | 固定・携帯混在 |
| OPTAGE | `optage` | AS17511 | 固定・携帯混在 |
| FUJITSU LIMITED | `infoweb` | AS2510 | 不明 |
| NTTPC / InfoSphere | `nttpc` | AS2514 | 不明 |
| BIGLOBE | `biglobe` | AS2518, AS45674 | 固定・携帯混在（AS2518）/ 不明（AS45674） |
| アルテリア / VECTANT / UCOM | `arteria` | AS2519, AS17506, AS17699 | 不明 |
| ソニー / So-net / NURO | `sonet` | AS2527, AS9600 | 固定推定 |
| UNIADEX LTD. | `u-netsurf` | AS4675 | 不明 |
| Canon IT Solutions Inc. | `fine` | AS4678 | 不明 |
| ASAHIネット | `asahi-net` | AS4685 | 固定推定 |
| BEKKOAME INTERNET INC. | `bekkoame` | AS4686 | 不明 |
| エネコム / MEGA EGG | `enecom` | AS4695, AS7670, AS18144 | 固定推定 |
| J:COM / ZAQ | `jcom` | AS4721, AS7686, AS9378, AS9614, AS9617, AS9824, AS18134, AS18136, AS23788, AS23790, AS24276, AS45675 | 固定推定 |
| Dolphin | `dolphin` | AS4723 | 不明 |
| Advanced Software Technology & Management Research Institute of KYOTO | `ip-kyoto` | AS7502 | 不明 |
| Fujitsu Systems Applications & Support Limited | `mediaweb` | AS7505 | 不明 |
| SYNAPSE Co. Ltd. | `synapse` | AS7511 | 不明 |
| TOHKnet Co. Inc. | `tohknet` | AS7516 | 不明 |
| STNet Incorporated | `stcn` | AS7522 | 不明 |
| ITEC HANKYU HANSHIN CO. LTD. | `hanshin` | AS7524 | 不明 |
| HARENET INC. | `harenet` | AS7664 | 不明 |
| Hokuriku Telecommunication Network Co. | `htcn` | AS7668 | 不明 |
| Hokuden Information System Service Co. Ltd. | `fitweb` | AS7672, AS17689 | 固定推定 / 不明 |
| NTT DOCOMO BUSINESS Inc | `gofors` | AS7674 | 不明 |
| TAM Co. Ltd. | `tam` | AS7676 | 不明 |
| QTnet / BBIQ | `qtnet` | AS7679 | 固定推定 |
| HOKKAIDO TELECOMMUNICATIONS NETWORK Co. Inc. | `hotnet` | AS7682 | 不明 |
| TOYOTA SYSTEMS CORPORATION | `d-cruisenet` | AS7687 | 不明 |
| Mirai Communication Network Inc. | `mirai` | AS7690 | 不明 |
| ZTV CO. LTD | `zlan` | AS9351 | 固定推定 |
| Community Network Center Inc. | `tdnc` | AS9354 | 不明 |
| NRI SecureTechnologies Ltd. | `fnc` | AS9357 | 不明 |
| OPTAGE Inc. | `finder` | AS9358 | 不明 |
| EDION Corporation | `edion` | AS9374 | 不明 |
| NTT-ME Corporation | `xephion` | AS9595 | 不明 |
| Niigata Communication Service | `shibata` | AS9601 | 不明 |
| TOYOHASHI CABLE NETWORK INC. | `tees` | AS9615 | 固定推定 |
| catv-tokushima | `tcn` | AS9618 | 固定推定 |
| OTNet Co. Inc. | `ii-okinawa` | AS9621 | 不明 |
| Kurashiki Cable TV | `kct` | AS9622 | 固定推定 |
| Suzuka Cable Co. Ltd | `mecha` | AS9997 | 固定推定 |
| Nagasaki Cable Media Inc. | `ncm` | AS10000 | 固定推定 |
| Mics Network Corporation | `micsnet` | AS10001 | 固定推定 |
| IGAUENO CABLE TELEVISION CO. LTD | `ict` | AS10002 | 固定推定 |
| Ogaki Cable Television Co. Inc. | `oct-net` | AS10003 | 固定推定 |
| TOKAI / TNC | `tokai` | AS10010 | 不明 |
| FreeBit / DTI / hi-ho系 | `freebit` | AS10013 | 不明 |
| Minaminihon Information Processing Center Co Ltd | `minc` | AS10016 | 不明 |
| Matsusaka Cable-TV Station Inc. | `mctv` | AS10019 | 固定推定 |
| STARCAT Co . LTD. | `mediacat` | AS17529 | 固定推定 |
| Nihon Network Service Co .Ltd. | `nns` | AS17530 | 固定推定 |
| NSK Co. Ltd. | `nsk` | AS17534 | 不明 |
| Gunma Internet Co .ltd | `wind` | AS17678 | 不明 |
| 296 BROAD NET Com Inc | `cablenet296` | AS17682 | 固定推定 |
| Wingtechnology Communications Inc. | `wintech-com` | AS17683 | 不明 |
| NDS Co. Ltd. | `tikitiki` | AS17691 | 不明 |
| COMMUNITY NETWORK CENTER INCORPORATED | `ccnet-net` | AS17698 | 固定推定 |
| Netforest Inc. | `netforest` | AS17931 | 不明 |
| Cable Television Kani Co. Inc. | `ctk` | AS17936 | 固定推定 |
| miyazaki cabletelevision network Co. LTD | `mcn-net01` | AS17939 | 固定推定 |
| EditNet Incorporated | `editnet` | AS17948 | 不明 |
| SaiNet | `sainet-as` | AS17950 | 不明 |
| Densan Co. Ltd. | `avisnet` | AS17955 | 不明 |
| SOUTH TOKYO CABLETELEVISION | `cts` | AS17957 | 固定推定 |
| Kasaoka Cable Vision Co LTD. | `kcv` | AS17958 | 固定推定 |
| mitene internet co. ltd. | `mitene` | AS17961 | 不明 |
| Dream Wave Shizuoka Co. Ltd. | `across` | AS18068 | 不明 |
| ちゅピCOM | `chupicom` | AS18075, AS18283 | 固定推定 |
| Yamaguchi Cable Vision Co. Ltd | `c-able` | AS18077 | 固定推定 |
| Kintetsu Cable Network Co. Ltd. | `kcn` | AS18081 | 固定推定 |
| IMS Corporation | `magma` | AS18090 | 不明 |
| Kyushu Tele Communications Company | `csf` | AS18092 | 固定推定 |
| Tokyo Cable Network. INC | `tcn-as` | AS18094 | 固定推定 |
| D.C.N. Corporation | `dcn` | AS18097 | 不明 |
| Ishikawa Computer Center Co. LTD. | `incl` | AS18121 | 不明 |
| コミュファ / CTC | `ctc` | AS18126 | 固定推定 |
| OKAYAMA NETWORK INC. | `oni` | AS18129 | 固定推定 |
| BTV CO. LTD. | `btv` | AS18135 | 固定推定 |
| KISTEM Co. Ltd. | `biwalobe` | AS18142 | 不明 |
| NetComBB Co. Ltd. | `sni-jp` | AS18150 | 不明 |
| EHIME CATV CO. LTD. | `e-catv` | AS18260 | 固定推定 |
| 秋田ケーブルテレビ | `cna` | AS18266, AS23783 | 固定推定 |
| Naganoken Kyodou Densan Co.Ltd. | `janis` | AS18268 | 不明 |
| Utsunomiya Cable TV Corporation | `ucatv` | AS18274 | 固定推定 |
| ケーブルテレビ / CC9 | `cc9` | AS18278 | 固定推定 |
| Tokoname New-TV Corporation | `tac-net` | AS18281 | 固定推定 |
| Tonami System Solutions Co. Ltd. | `coralnet` | AS18282 | 不明 |
| Chukai Television Co .Ltd. | `chukai` | AS23624 | 固定推定 |
| UEDA CABLE VISION CO. LTD. | `ucvnet` | AS23627 | 固定推定 |
| Academic newtown Community Cable Service | `accsnet` | AS23628 | 固定推定 |
| Obihiro City Cable Co. Ltd. | `octv` | AS23629 | 固定推定 |
| IMIZU CABLE NETWORK CO. LTD. | `canet` | AS23778 | 固定推定 |
| San-in Cable Vision CO. LTD | `mable` | AS23786 | 固定推定 |
| Watarase Television Co. Ltd | `watvnet` | AS23805 | 固定推定 |
| TOSHIMA CABLE NETWORK CO. LTD | `toshima-net` | AS23808 | 固定推定 |
| JETINTERNET Corporation | `jetinternet` | AS23818 | 不明 |
| HAGI Television Co. Ltd. | `haginet` | AS23822 | 固定推定 |
| Azumino Network Community TV | `anc-net` | AS23827 | 固定推定 |
| NISIOWARI CATV CORPORATION | `clovernet` | AS23831 | 固定推定 |
| Iwakuni Cable Network Corporation | `icntv-net` | AS24251 | 固定推定 |
| Koshinomiyako Network Inc. | `t-catv` | AS24255 | 固定推定 |
| JPIX / JPNE系 | `jpne` | AS24257 | 不明 |
| kanuma cable television Corporation | `bc9` | AS24259 | 固定推定 |
| Iruma CATV co. | `ictv` | AS24271 | 固定推定 |
| Okinawa Cable Network Inc. | `nirai` | AS24277 | 固定推定 |
| SENDAI CATV CO. LTD. | `cat-v` | AS24279 | 固定推定 |
| Kagawa T.V Broadcast Network Co .Ltd | `kbn` | AS24289 | 固定推定 |
| Heart Network Co. LTD | `heartnet` | AS24290 | 固定推定 |
| Cable Media WAIWAI Co. Ltd. | `wai-net` | AS37892 | 固定推定 |
| BBIX / BB.excite系 | `bbix` | AS37904 | 不明 |
| KIBI Cable Television Co. Ltd. | `kbc` | AS37908 | 固定推定 |
| HIMEJI CABLE TELEVISION CORPORATION | `wink-net` | AS38628 | 固定推定 |
| transix / インターネットマルチフィード | `transix` | AS38644, AS55391, AS55392 | 固定推定（AS55391・AS55392）/ 不明（AS38644） |
| Koga Cable TV Co. Ltd. | `kgc-net` | AS45672 | 固定推定 |
| Isahaya Cable Media Co. Ltd | `icv` | AS45677 | 固定推定 |
| Minamikyusyu CableTV Net Inc. | `mct-internet` | AS45687 | 固定推定 |
| KCV Communications Co. Ltd. | `kcv-hitanet` | AS55376 | 固定推定 |
| CITY-CABLE SHUNAN Corporation | `ccsnet` | AS55381 | 固定推定 |
| Japan Communication Inc. | `rmgr-mix` | AS55387 | 不明 |
| Miyagi Cable TV Co. Ltd | `marinet` | AS58645 | 固定推定 |
| Warabi Cable Vision Co. Ltd. | `catvwink` | AS58650 | 固定推定 |
| IMABARI CATV CORPORATION | `icknet` | AS59093 | 固定推定 |
| Soka University | `sokau-as` | AS59104 | 大学・学術網 |
| Hachinohe Cable Television Co. | `htv-net` | AS59107 | 固定推定 |
| KATCH NETWORK INC. | `katch-net` | AS59108 | 固定推定 |
| Tsukuba Internet Service Corporation | `tins-net` | AS59120 | 不明 |
| YAKAGE CABLE TELEVISION | `yctnet` | AS63775 | 固定推定 |
| Omaezaki Cable Television Co.Ltd | `maotv` | AS63782 | 固定推定 |
| Iwami Cablevision Co. Ltd. | `iwami-net` | AS131907 | 固定推定 |
| HONJYO CABLE VISION CO. LTD. | `hctv-net` | AS131911 | 固定推定 |
| Hamamatsu Cable Television .Inc | `winde` | AS131915 | 固定推定 |
| Tokyo Bay Network Co. Ltd. | `baynet` | AS131916 | 固定推定 |
| SHONAN CABLE NETWORK | `scn-net` | AS131918 | 固定推定 |
| Cable Television Saiki Co. Ltd. | `cts-net` | AS131926 | 固定推定 |
| Yamanashi CATV Co . ltd | `fruitsnet` | AS131929 | 固定推定 |
| Tokyo Broadcasting System Television Inc. | `tbs-net` | AS131930 | 不明 |
| Aomori Cable TV Co. Ltd. | `actv-net` | AS131931 | 固定推定 |
| TAMA Television Co. Ltd | `ttv-net` | AS131933 | 固定推定 |
| Joetsu Cable Vision | `jcv` | AS131937 | 固定推定 |
| Asahikawa Cable Television Co. Ltd. | `potato-net` | AS131952 | 固定推定 |
| Kawaguchiko cable television Inc | `lcnet` | AS131954 | 固定推定 |
| Kyoutou Cable Net Co Ltd | `kcnet` | AS131955 | 固定推定 |
| Tama Cable Network Co. Ltd. | `t-net` | AS131958 | 固定推定 |
| Uenohara Broadband Communications Inc. | `ubc` | AS131982 | 固定推定 |
| suo cablenet corporation | `scntv-net` | AS131983 | 固定推定 |
| ITOCHU Cable Systems Corp. | `bb4u-net` | AS131986 | 固定推定 |
| Takehara Cable Network Co Ltd | `tanet` | AS131988 | 固定推定 |
| Cable Television TOYAMA Inc. | `cttnet` | AS150359 | 固定推定 |
| OMURA CABLE TELEVISION K.K. | `octp-net` | AS151387 | 固定推定 |
| Takaoka cable network | `tcnet` | AS152867 | 固定推定 |
| Air Internet Service Co. Ltd. | `air` | AS7503 | 不明 |
| its communications Inc. | `itscom` | AS9365 | 固定推定 |
| Phoenix Communications Inc. | `phoenix` | AS10004 | 不明 |
| Global Network Core Co. Ltd. | `ndac` | AS18070 | 不明 |
| Niigata Communication Service | `shibata` | AS23633 | 不明 |
| OBIS | `obis` | AS23642 | 不明 |
| CTB Media Inc. | `ctb` | AS23780 | 固定推定 |
| SUN FIELD INTERNET LIMITED | `sunfield` | AS23785 | 不明 |
| GMO NetIRD Inc. | `netird` | AS37906 | 不明 |
| Value Core Inc. | `vciu-net` | AS38633 | 不明 |
| DOVA Corporation | `dova` | AS45680 | 不明 |
| DODO K.K. | `dodo` | AS45691 | 不明 |
| DODO K.K. | `dodo` | AS49671 | 不明 |
| FAMILY NET JAPAN INCORPORATED | `cyberhome` | AS59125 | 固定推定 |
| NCT CO. LTD. | `nct` | AS59126 | 固定推定 |
| Kamoike.net LLP | `kamoike-net` | AS63774 | 不明 |
| DODO K.K. | `dodo` | AS63801 | 不明 |
| DOVA Corporation | `dova` | AS63804 | 不明 |
| Wire and Wireless Co. Ltd. | `wi2` | AS131160 | 不明 |
| Oedo Telecom Inc | `oedo` | AS131913 | 不明 |
| Goto tv | `goto-tv` | AS131943 | 固定推定 |
| Super Godzilla Communications GK | `sgcom` | AS138652 | 不明 |
| SUZUYO SHINWART CORPORATION | `ss` | AS146986 | 不明 |
| SoftEther Corporation | `softether` | AS150363 | 不明 |

## VPN事業者・共有基盤

| 事業者・アクセス網 | プロバイダキー | ASN | 回線区分 |
| --- | --- | --- | --- |
| M247 | `m247` | AS9009 | 不明 |
| PacketHub / NordVPN系 | `packethub` | AS136787 | 不明 |
| PacketHub / NordVPN系 | `packethub` | AS207137 | 不明 |
| Cyberzone / Surfshark系 | `cyberzone` | AS209854 | 不明 |
| Proton / Proton VPN系 | `proton` | AS208172 | 不明 |
| Mullvad VPN | `mullvad` | AS216025 | 不明 |
| Check Point | `checkpoint` | AS398391 | 不明 |

## 固定・携帯混在の設定

回線分類の取得元・カテゴリー・CIDR上書きで「固定・携帯混在」を選べます。投稿・閲覧の回線許可と条件規制でも独立して指定でき、固定・携帯・不明の拒否には含まれません。既存の取得元・分類・上書きは自動で変更しません。保存済みの取得元を変更する場合は、その行の分類を編集してください。混在分類を保存するとreader85以降が必要です。投稿表示は冒頭の事業者別呼称、事業者キーが不明・呼称未登録なら `ﾜｯﾁｮﾏｾﾞ`、ID末尾は `0` です。
