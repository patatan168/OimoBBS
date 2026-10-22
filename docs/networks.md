# 国内回線・VPN業者の標準カタログ

国内の携帯・固定系、地域ISP、CATV、IPoE・企業アクセス網の204 ASN、VPN関連7 ASNに、クラウド16・衛星1・学術8・政府機関1を加えた237 ASNを対象にします。固定回線の投稿表示は `ﾜｯﾁｮｲ` です。

| 調べたいこと | 参照先 |
| --- | --- |
| 管理画面で更新状況や編集対象を探す | [回線分類の操作](admin-guide.md#回線分類を確認する) |
| 自動取得と既存設定の扱い | [初回と既存サイト](#初回と既存サイト) |
| 分類が示す範囲・誤判定への対応 | [判定の範囲](#判定の範囲) |
| 学術・企業・クラウド・衛星の表示 | [特殊な分類と表示](#特殊な分類と表示) |
| DNSが逆引き不能・不整合な場合 | [逆引きの特殊表示](#逆引きの特殊表示) |
| 固定回線のホスト名による補完 | [固定回線のDNS補完](#固定回線のdns補完) |
| 登録済みの事業者とASN | [取得元一覧](#取得元一覧)・[VPN事業者](#vpn事業者共有基盤) |

## 初回と既存サイト

未設定サイトの初回起動で標準取得元を登録し、国コード・日本IP・既知VPNと合わせて自動取得します。APIキーは不要です。管理画面「回線分類」で取得状況を確認します。

既存サイトでは「全業者の標準取得元を追加して更新」で不足分を追加します。手動設定と更新間隔を維持します。取得失敗時は前回成功表と手動上書きを保持し、停止した自動更新は再起動だけでは再開しません。

## 国の重複

同じIP範囲が複数の国に登録されていても、分類表全体の更新は止めません。

| 同じ範囲の登録内容 | 国判定 |
| --- | --- |
| 同じ国の重複 | その国 |
| 異なる国が重複し、日本を含まない | 不明 |
| 日本と他国が重複 | 日本を優先 |

不明の範囲を、より広いIP範囲の国や「日本表に非掲載なので国外」という判定で埋めません。異なる長さの範囲は従来どおり最長一致で照合します。日本のIP表に掲載された範囲は日本を優先し、管理者の明示上書きは自動判定より優先します。次の取得で重複がなくなれば通常の国判定に戻ります。国が不明でも、回線業者・既知VPNの判定は独立して行います。国の判定を必要とする制限では、従来どおり不明を許可判定にしません。

重複を含む国表の保存後は最低reader101が必要です。保存済みの正常な表を変換する作業は不要です。切り戻しは[保存形式の互換性](operations.md#保存形式の互換性)を参照してください。

## 判定の範囲

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
| クラウド・VPS | `ｸﾓﾉｳｴ` | `V` | 対象事業者ASN。Virtual/VPSのV |
| 衛星回線 | `ｳﾁｭｰ` | `U` | Starlink ASN。UniverseのU |

学術・学校・官公庁・企業内の呼称と末尾は[5ch公式WikiのBBS_SLIP](https://info.5ch.io/index.php/BBS_SLIP)を参照しています。`ｸﾓﾉｳｴ`と`ｳﾁｭｰ`はOimoBBS独自の5ch風呼称です。企業のCO.JPドメイン全体を企業内回線とは判定しません。機関の網・確認済みドメインを推定する区分で、投稿者の所属・職業・所在地を証明するものではありません。DNSの対象は[JPRSの属性型ドメインの対象](https://jprs.jp/about/jp-dom/spec/)に従います。

既知VPN・板別および共通の手動上書きは、特殊用途の自動表示より優先します。特殊用途が判明した回線は、国外でも`ｸﾓﾉｳｴ / V`などを表示します。国コードによる接続許可・拒否は独立して有効です。通常の国外回線は国コード、既知VPNは`ｺﾝﾆﾁﾜ / 8`を使い、事業者キーを補完します。

クラウドの同一prefixが複数ASNから広告され、種別・呼称・末尾が一致する場合は、事業者キーを空にして曖昧さを保持します。異なる種別・表示の衝突は更新失敗とし、先着順で採用しません。

NifMo・LIBMO・LinksMate・SORACOM・トーンモバイル・ワイヤレスゲート・公衆Wi-Fi・機内Wi-Fi・船舶用衛星などの5ch風プリセットも用意します。プリセット追加だけでは自動判定されません。専用のIP範囲などを確認してから上書きに使います。船舶用SafeComNetの既存呼称は`ﾀﾆｯｸ / S`です。

追加したASNは、Starlink、さくらインターネット、Hetzner、OVHcloud、DigitalOcean、Vultr、Akamai/Linode、Scaleway、Contabo、AWS、Google Cloud、Microsoft、Oracle、Alibaba、SINET、東京大学、NCA5、HEPNET-J、SuperCSI、九州大学、APAN-JP、WIDE/AI3、科学技術振興機構です。同一事業者の複数ASNは一つのプロバイダキーへ束ねます。

## 逆引きの特殊表示

「回線種別が未分類」と「DNSが逆引き不能・不整合」は分けます。[5ch公式Wiki](https://info.5ch.io/index.php/BBS_SLIP)の呼称と詳細ID末尾に合わせ、次の条件で新規投稿へ表示します。

| DNSの結果 | 表示 | 詳細ID末尾 |
| --- | --- | --- |
| PTRが存在しない（正常な空回答・NXDOMAIN） | `ｱﾝﾀﾀﾞﾚ` | `h` |
| PTR名が不正、または正引きが元のIPに一致しない | 登録国コード（不明は`ZZ`） | `H` |
| 逆引きと正引きが一致 | 従来のサービス・ASN・未分類表示 | 従来どおり |
| 取得待ち・タイムアウト・SERVFAIL・未取得・期限切れ | 従来の表示を維持 | 未分類なら`0` |

手動上書き・既知VPN・クラウドや衛星などの特殊用途を優先し、その他の通常分類へDNS特殊表示を適用します。`h/H`は名前欄と末尾だけを変更し、規制用の回線種別・プロバイダキー・国・VPN属性は変えません。逆引き不能を拒否する設定は従来どおりPTR取得の成否で判定し、正引き不一致を同じ拒否条件へ追加しません。

`none`では末尾なし、従来端末区分の`checked`では通常`0`です。`h/H`は詳細な回線表示とワッチョイに反映します。過去のDATは再生成しません。

Google Public DNSとOS標準DNSのどちらでも、確定した不存在と一時障害を区別します。判定は既存の有界DNSキャッシュを参照し、投稿ワーカー内で新たに外部照会しません。管理画面のIP確認には「DNS確認結果」を表示し、PTR取得と正引き一致を別々に確認できます。公開5chの内部判定アルゴリズムは保証せず、上記の確認可能な条件を本システムの判定基準とします。

## 固定回線のDNS補完

逆引きしたホスト名を正引きし、元のIPとの一致を確認した場合だけ、次の固定回線分類を補完します。

| サービス | ホスト名の対象 |
| --- | --- |
| UCOM | `*.ftth.ucom.ne.jp` |
| OCN | `p数字-ipngn数字.*.ocn.ne.jp` |
| au one net | `*.ppp-bb.dion.ne.jp` |
| So-net | `*.ap.so-net.ne.jp` |
| NURO | `*.ap.nuro.jp` |

携帯・公衆Wi-Fiと混在するISP全体を固定回線に変更する処理ではありません。共通・板別の明示上書きと、国・既知VPNの判定を優先します。

## 容量と互換性

取得元・表示カテゴリーは各256件、分類表は4万prefix、取得は最大8並列・25秒です。大きな設定は`gzip-config-v1`で保存し、展開は1MiBまでです。分類表の`gzip-json-v2`は展開6MiB/4万行までを一行ずつ厳密に検査します。制御JSON全体の1MiB上限は維持し、全取得元が成功して容量内に収まった場合だけ公開表へ反映します。

特殊区分と新しい圧縮保存はreader 92以降、DNS特殊表示の新規投稿はreader 93以降です。公開受付開始前にreader境界を同期保存するため、旧バイナリはこの状態を開けません。失敗時は前回成功表・手動設定を維持します。

## 取得元一覧

「固定・携帯混在」は固定と携帯の両用途が確認済みの区分で、個々の接続方式を保証しません。確認済みサービスのホスト名で固定・携帯を識別できる場合は、その分類を優先します。「不明」は用途自体が未確認の区分です。管理画面では名前・ASN・識別キーの検索と回線区分の絞り込みができます。

| 事業者・アクセス網 | プロバイダキー | ASN | 回線区分 |
| --- | --- | --- | --- |
| OCN | `ocn` | AS4713 | 固定・携帯混在 |
| docomo | `docomo` | AS9605 | 携帯推定 |
| 楽天モバイル | `rakuten` | AS138384, AS10012 | 携帯推定 / 不明 |
| KDDI | `kddi` | AS2516 | 固定・携帯混在 |
| SoftBank | `softbank` | AS17676, AS4725, AS18069 | 固定・携帯混在（AS17676）/ 不明 |
| IIJ | `iij` | AS2497 | 不明 |
| OPTAGE | `optage` | AS17511 | 固定・携帯混在 |
| FUJITSU LIMITED | `infoweb` | AS2510 | 不明 |
| NTTPC / InfoSphere | `nttpc` | AS2514 | 不明 |
| BIGLOBE | `biglobe` | AS2518, AS45674 | 不明 |
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
| ZTV CO. LTD | `zlan` | AS9351 | 不明 |
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
| Mics Network Corporation | `micsnet` | AS10001 | 不明 |
| IGAUENO CABLE TELEVISION CO. LTD | `ict` | AS10002 | 固定推定 |
| Ogaki Cable Television Co. Inc. | `oct-net` | AS10003 | 固定推定 |
| TOKAI / TNC | `tokai` | AS10010 | 不明 |
| FreeBit / DTI / hi-ho系 | `freebit` | AS10013 | 不明 |
| Minaminihon Information Processing Center Co Ltd | `minc` | AS10016 | 不明 |
| Matsusaka Cable-TV Station Inc. | `mctv` | AS10019 | 固定推定 |
| STARCAT Co . LTD. | `mediacat` | AS17529 | 不明 |
| Nihon Network Service Co .Ltd. | `nns` | AS17530 | 不明 |
| NSK Co. Ltd. | `nsk` | AS17534 | 不明 |
| Gunma Internet Co .ltd | `wind` | AS17678 | 不明 |
| 296 BROAD NET Com Inc | `cablenet296` | AS17682 | 不明 |
| Wingtechnology Communications Inc. | `wintech-com` | AS17683 | 不明 |
| NDS Co. Ltd. | `tikitiki` | AS17691 | 不明 |
| COMMUNITY NETWORK CENTER INCORPORATED | `ccnet-net` | AS17698 | 不明 |
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
| Kyushu Tele Communications Company | `csf` | AS18092 | 不明 |
| Tokyo Cable Network. INC | `tcn-as` | AS18094 | 固定推定 |
| D.C.N. Corporation | `dcn` | AS18097 | 不明 |
| Ishikawa Computer Center Co. LTD. | `incl` | AS18121 | 不明 |
| コミュファ / CTC | `ctc` | AS18126 | 固定推定 |
| OKAYAMA NETWORK INC. | `oni` | AS18129 | 不明 |
| BTV CO. LTD. | `btv` | AS18135 | 不明 |
| KISTEM Co. Ltd. | `biwalobe` | AS18142 | 不明 |
| NetComBB Co. Ltd. | `sni-jp` | AS18150 | 不明 |
| EHIME CATV CO. LTD. | `e-catv` | AS18260 | 固定推定 |
| 秋田ケーブルテレビ | `cna` | AS18266, AS23783 | 固定推定 |
| Naganoken Kyodou Densan Co.Ltd. | `janis` | AS18268 | 不明 |
| Utsunomiya Cable TV Corporation | `ucatv` | AS18274 | 固定推定 |
| ケーブルテレビ / CC9 | `cc9` | AS18278 | 固定推定 |
| Tokoname New-TV Corporation | `tac-net` | AS18281 | 不明 |
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
| Azumino Network Community TV | `anc-net` | AS23827 | 不明 |
| NISIOWARI CATV CORPORATION | `clovernet` | AS23831 | 固定推定 |
| Iwakuni Cable Network Corporation | `icntv-net` | AS24251 | 固定推定 |
| Koshinomiyako Network Inc. | `t-catv` | AS24255 | 不明 |
| JPIX / JPNE系 | `jpne` | AS24257 | 不明 |
| kanuma cable television Corporation | `bc9` | AS24259 | 固定推定 |
| Iruma CATV co. | `ictv` | AS24271 | 固定推定 |
| Okinawa Cable Network Inc. | `nirai` | AS24277 | 固定推定 |
| SENDAI CATV CO. LTD. | `cat-v` | AS24279 | 固定推定 |
| Kagawa T.V Broadcast Network Co .Ltd | `kbn` | AS24289 | 不明 |
| Heart Network Co. LTD | `heartnet` | AS24290 | 不明 |
| Cable Media WAIWAI Co. Ltd. | `wai-net` | AS37892 | 固定推定 |
| BBIX / BB.excite系 | `bbix` | AS37904 | 不明 |
| KIBI Cable Television Co. Ltd. | `kbc` | AS37908 | 固定推定 |
| HIMEJI CABLE TELEVISION CORPORATION | `wink-net` | AS38628 | 固定推定 |
| transix / インターネットマルチフィード | `transix` | AS38644, AS55391, AS55392 | 不明 |
| Koga Cable TV Co. Ltd. | `kgc-net` | AS45672 | 固定推定 |
| Isahaya Cable Media Co. Ltd | `icv` | AS45677 | 固定推定 |
| Minamikyusyu CableTV Net Inc. | `mct-internet` | AS45687 | 固定推定 |
| KCV Communications Co. Ltd. | `kcv-hitanet` | AS55376 | 不明 |
| CITY-CABLE SHUNAN Corporation | `ccsnet` | AS55381 | 固定推定 |
| Japan Communication Inc. | `rmgr-mix` | AS55387 | 不明 |
| Miyagi Cable TV Co. Ltd | `marinet` | AS58645 | 固定推定 |
| Warabi Cable Vision Co. Ltd. | `catvwink` | AS58650 | 固定推定 |
| IMABARI CATV CORPORATION | `icknet` | AS59093 | 固定推定 |
| Soka University | `sokau-as` | AS59104 | 不明 |
| Hachinohe Cable Television Co. | `htv-net` | AS59107 | 固定推定 |
| KATCH NETWORK INC. | `katch-net` | AS59108 | 不明 |
| Tsukuba Internet Service Corporation | `tins-net` | AS59120 | 不明 |
| YAKAGE CABLE TELEVISION | `yctnet` | AS63775 | 固定推定 |
| Omaezaki Cable Television Co.Ltd | `maotv` | AS63782 | 固定推定 |
| Iwami Cablevision Co. Ltd. | `iwami-net` | AS131907 | 固定推定 |
| HONJYO CABLE VISION CO. LTD. | `hctv-net` | AS131911 | 固定推定 |
| Hamamatsu Cable Television .Inc | `winde` | AS131915 | 固定推定 |
| Tokyo Bay Network Co. Ltd. | `baynet` | AS131916 | 不明 |
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
| Uenohara Broadband Communications Inc. | `ubc` | AS131982 | 不明 |
| suo cablenet corporation | `scntv-net` | AS131983 | 固定推定 |
| ITOCHU Cable Systems Corp. | `bb4u-net` | AS131986 | 固定推定 |
| Takehara Cable Network Co Ltd | `tanet` | AS131988 | 固定推定 |
| Cable Television TOYAMA Inc. | `cttnet` | AS150359 | 固定推定 |
| OMURA CABLE TELEVISION K.K. | `octp-net` | AS151387 | 固定推定 |
| Takaoka cable network | `tcnet` | AS152867 | 固定推定 |
| Air Internet Service Co. Ltd. | `air` | AS7503 | 不明 |
| its communications Inc. | `itscom` | AS9365 | 不明 |
| Phoenix Communications Inc. | `phoenix` | AS10004 | 不明 |
| Global Network Core Co. Ltd. | `ndac` | AS18070 | 不明 |
| Niigata Communication Service | `shibata` | AS23633 | 不明 |
| OBIS | `obis` | AS23642 | 不明 |
| CTB Media Inc. | `ctb` | AS23780 | 不明 |
| SUN FIELD INTERNET LIMITED | `sunfield` | AS23785 | 不明 |
| GMO NetIRD Inc. | `netird` | AS37906 | 不明 |
| Value Core Inc. | `vciu-net` | AS38633 | 不明 |
| DOVA Corporation | `dova` | AS45680 | 不明 |
| DODO K.K. | `dodo` | AS45691 | 不明 |
| DODO K.K. | `dodo` | AS49671 | 不明 |
| FAMILY NET JAPAN INCORPORATED | `cyberhome` | AS59125 | 不明 |
| NCT CO. LTD. | `nct` | AS59126 | 不明 |
| Kamoike.net LLP | `kamoike-net` | AS63774 | 不明 |
| DODO K.K. | `dodo` | AS63801 | 不明 |
| DOVA Corporation | `dova` | AS63804 | 不明 |
| Wire and Wireless Co. Ltd. | `wi2` | AS131160 | 不明 |
| Oedo Telecom Inc | `oedo` | AS131913 | 不明 |
| Goto tv | `goto-tv` | AS131943 | 不明 |
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

回線分類の取得元・カテゴリー・CIDR上書きで「固定・携帯混在」を選べます。投稿・閲覧の回線許可と条件規制でも独立して指定でき、固定・携帯・不明の拒否には含まれません。既存の取得元・分類・上書きは自動で変更しません。保存済みの取得元を変更する場合は、その行の分類を編集してください。混在分類を保存するとreader85以降が必要です。投稿表示の標準ラベルは `ﾜｯﾁｮｲ`、ID末尾は `0` です。
