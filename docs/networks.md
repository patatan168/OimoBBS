# 国内回線・VPN業者の標準カタログ

国内の携帯・固定系、地域ISP、CATV、IPoE・企業アクセス網の204 ASNと、VPN事業者・共有基盤の7 ASNを対象にします。固定回線の投稿表示は `ﾜｯﾁｮｲ` です。

## 初回と既存サイト

未設定サイトの初回起動で標準取得元を登録し、国コード・日本IP・既知VPNと合わせて自動取得します。APIキーは不要です。管理画面「回線分類」で取得状況を確認します。

既存サイトでは「国内・VPN業者の標準取得元を追加して更新」で不足分を追加します。手動設定と更新間隔を維持します。取得失敗時は前回成功表と手動上書きを保持し、停止した自動更新は再起動だけでは再開しません。

## 判定の範囲

ASNの公開経路から推定します。同じ事業者の複数ASNには同じプロバイダ識別キーを使います。固定と携帯（MVNOを含む）の混在が確認済みのASNは「固定・携帯混在」（`mixed`）、用途が未確認の企業網は「不明」（`unknown`）です。共有上流・IPoEでは契約サービス名を確定できず、別ブランドでも同じ上流回線として表示する場合があります。確認できた範囲は共通または板別の上書きで修正してください。

取得元は[JPNICのASN一覧](https://www.nic.ad.jp/ja/ip/as-numbers.txt)と[ipverseの事業者情報](https://github.com/ipverse/as-metadata)を照合し、[ASNごとの公開IP範囲](https://github.com/ipverse/as-ip-blocks)が取得できるものを選んでいます。経路を取得できないASNは標準取得元から除外します。

VPN業者は[X4BNetのVPN向けASN一覧](https://github.com/X4BNet/lists_vpn/blob/main/input/vpn/ASN.txt)と事業者情報を照合します。PacketHub / NordVPN系、Cyberzone / Surfshark系、Proton、Mullvad、Check Point、M247の公開経路を取得し、既知VPN判定や国外表示にもプロバイダキーを補完します。ASN全域をVPN扱いにはせず、VPN該当性は従来の既知VPNリストで判定します。VPN検出範囲そのものを広げる変更ではありません。共有基盤では利用中のVPNブランドを保証しません。

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
