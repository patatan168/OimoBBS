# 標準回線カタログの見直しと検証（2026-11-05）

OimoBBS1.1.1の標準カタログを見直した根拠と、隔離環境での検証結果です。現在の操作手順は[回線分類の仕様](../networks.md)を参照してください。

237 ASNを分類別に棚卸しし、従来の未分類115件を対象に、登録情報と公開サービスを照合しました。既存の分類済み122件は今回変更していません。社名の英語表記や「ISP」という登録だけでは接続方式を確定しません。

| 回線区分 | 見直し前 | 見直し後 |
| --- | ---: | ---: |
| 不明 | 115 | 87 |
| 固定推定 | 90 | 115 |
| 固定・携帯混在 | 4 | 6 |
| 大学・学術網 | 8 | 9 |
| その他 | 20 | 20 |

## 判定の範囲

- CATV・集合住宅の23 ASNは、事業者の光・同軸・宅内LANによる接続サービスを根拠に、従来のCATV分類と同じ「固定推定」へ変更します。ASNの全IPが家庭用回線であることを証明する分類ではありません。法人利用・設備用IP・他用途が含まれる可能性があるため、個別の確認済み範囲は手動上書きを優先します。
- transixのAS55391・AS55392は東西の光アクセス網として固定推定にします。運営者の[ネットワーク構成資料](https://www.janog.gr.jp/meeting/janog50/wp-content/uploads/2022/06/janog50-iqla-shinoda.pdf)と[Peering Asiaの事業者紹介資料](https://2021v.peeringasia.com/files/pa2021v-pp-isp-ott-csp.pdf)を参照しました。同じ事業者のAS38644は変更しません。
- IIJのAS2497・BIGLOBEのAS2518は、運営者のバックボーン説明・固定/MVNOの提供内容から混在に変更します。個々のIPの固定/携帯は従来どおり確認済みDNSで補完します。BIGLOBEの別ASNへは一律に広げません。
- 創価大学のAS59104は大学・学術網にします。利用者の所属を保証するものではありません。
- VPN関連の7 ASNは、事業者の経路全体をVPNと断定せず、不明を維持します。既知VPNリストによる個別の判定を維持します。

ASNの識別は[JPNICのASN一覧](https://www.nic.ad.jp/ja/ip/as-numbers.txt)・[ipverseの事業者情報](https://github.com/ipverse/as-metadata)、ネットワーク用途の補助情報は事業者が登録する[PeeringDB API](https://www.peeringdb.com/apidocs/)を参照しました。PeeringDBのCable/DSL/ISPにはMVNOやVPN関連の網もあるため、その値だけで固定回線にはしていません。

## 分類を変更する28 ASN

| ASN | 事業者 | 見直し後 | 根拠 |
| --- | --- | --- | --- |
| AS2497 | IIJ | 固定・携帯混在 | [固定・MVNOを含むサービス網](https://www.nic.ad.jp/ja/materials/iw/2022/proceedings/c15/c15-hori.pdf) / [事業者登録](https://www.peeringdb.com/api/net?asn=2497) |
| AS2518 | BIGLOBE | 固定・携帯混在 | [固定・MVNOを含むサービス網](https://www.janog.gr.jp/meeting/janog52/wp-content/uploads/2023/06/janog52-east-minami.pdf) / [事業者登録](https://www.peeringdb.com/api/net?asn=2518) |
| AS9351 | ZTV CO. LTD | 固定推定 | [光・ケーブル等の接続サービス](https://www.ztv.co.jp/service/net/index.html) / [事業者登録](https://www.peeringdb.com/api/net?asn=9351) |
| AS9365 | its communications Inc. | 固定推定 | [光・ケーブル等の接続サービス](https://www.itscom.co.jp/service/internet/) / [事業者登録](https://www.peeringdb.com/api/net?asn=9365) |
| AS10001 | Mics Network Corporation | 固定推定 | [光・ケーブル等の接続サービス](https://www.catvmics.ne.jp/service/internet/) / [事業者登録](https://www.peeringdb.com/api/net?asn=10001) |
| AS17529 | STARCAT Co . LTD. | 固定推定 | [光・ケーブル等の接続サービス](https://www.starcat.co.jp/agreement/pdf/internet_hikari_requirement.pdf) |
| AS17530 | Nihon Network Service Co .Ltd. | 固定推定 | [光・ケーブル等の接続サービス](https://www.nns-catv.co.jp/personal/ccnet/) |
| AS17682 | 296 BROAD NET Com Inc | 固定推定 | [光・ケーブル等の接続サービス](https://www.catv296.co.jp/service/internet/price_house/) / [事業者登録](https://www.peeringdb.com/api/net?asn=17682) |
| AS17698 | COMMUNITY NETWORK CENTER INCORPORATED | 固定推定 | [光・ケーブル等の接続サービス](https://www.ccnw.co.jp/service/internet/) |
| AS18092 | Kyushu Tele Communications Company | 固定推定 | [光・ケーブル等の接続サービス](https://csf.ne.jp/internet/) / [事業者登録](https://www.peeringdb.com/api/net?asn=18092) |
| AS18129 | OKAYAMA NETWORK INC. | 固定推定 | [光・ケーブル等の接続サービス](https://www.oninet.ne.jp/service/internet/index.html) / [事業者登録](https://www.peeringdb.com/api/net?asn=18129) |
| AS18135 | BTV CO. LTD. | 固定推定 | [光・ケーブル等の接続サービス](https://portal.btvm.ne.jp/internet-5g10g) / [事業者登録](https://www.peeringdb.com/api/net?asn=18135) |
| AS18281 | Tokoname New-TV Corporation | 固定推定 | [光・ケーブル等の接続サービス](https://www.tac-net.jp/service-guide/ccnc-net/) |
| AS23780 | CTB Media Inc. | 固定推定 | [光・ケーブル等の接続サービス](https://www.ctb.jp/internet) / [事業者登録](https://www.peeringdb.com/api/net?asn=23780) |
| AS23827 | Azumino Network Community TV | 固定推定 | [光・ケーブル等の接続サービス](https://www.anc-tv.co.jp/user/guide/net/pdf/setup_az.pdf) / [事業者登録](https://www.peeringdb.com/api/net?asn=23827) |
| AS24255 | Koshinomiyako Network Inc. | 固定推定 | [光・ケーブル等の接続サービス](https://koshinomiyako.jp/internet/) / [事業者登録](https://www.peeringdb.com/api/net?asn=24255) |
| AS24289 | Kagawa T.V Broadcast Network Co .Ltd | 固定推定 | [光・ケーブル等の接続サービス](https://www.kbn.ne.jp/internet/) / [事業者登録](https://www.peeringdb.com/api/net?asn=24289) |
| AS24290 | Heart Network Co. LTD | 固定推定 | [光・ケーブル等の接続サービス](https://heartnetwork.jp/service/internet/heart-net.html) / [事業者登録](https://www.peeringdb.com/api/net?asn=24290) |
| AS55376 | KCV Communications Co. Ltd. | 固定推定 | [光・ケーブル等の接続サービス](https://www.kcv.jp/archives/info/11402) / [事業者登録](https://www.peeringdb.com/api/net?asn=55376) |
| AS55391 | transix / インターネットマルチフィード | 固定推定 | [光アクセス網](https://www.mfeed.ad.jp/transix/) / [事業者登録](https://www.peeringdb.com/api/net?asn=55391) |
| AS55392 | transix / インターネットマルチフィード | 固定推定 | [光アクセス網](https://www.mfeed.ad.jp/transix/) / [事業者登録](https://www.peeringdb.com/api/net?asn=55392) |
| AS59104 | Soka University | 大学・学術網 | [学内ネットワーク](https://it-support.soka.ac.jp/freshman-2/) |
| AS59108 | KATCH NETWORK INC. | 固定推定 | [光・ケーブル等の接続サービス](https://www.katch.co.jp/service/internet/) |
| AS59125 | FAMILY NET JAPAN INCORPORATED | 固定推定 | [光・ケーブル等の接続サービス](https://www.cyberhome.ne.jp/service/internet/) / [事業者登録](https://www.peeringdb.com/api/net?asn=59125) |
| AS59126 | NCT CO. LTD. | 固定推定 | [光・ケーブル等の接続サービス](https://www.nct9.co.jp/about/service/) / [事業者登録](https://www.peeringdb.com/api/net?asn=59126) |
| AS131916 | Tokyo Bay Network Co. Ltd. | 固定推定 | [光・ケーブル等の接続サービス](https://www.baynet.ne.jp/net/top-net/) / [事業者登録](https://www.peeringdb.com/api/net?asn=131916) |
| AS131943 | Goto tv | 固定推定 | [光・ケーブル等の接続サービス](https://www.city.goto.nagasaki.jp/s014/020/050/20thkinenshi.pdf) / [事業者登録](https://www.peeringdb.com/api/net?asn=131943) |
| AS131982 | Uenohara Broadband Communications Inc. | 固定推定 | [光・ケーブル等の接続サービス](https://www.u-bc.net/support/Internet.html) / [事業者登録](https://www.peeringdb.com/api/net?asn=131982) |

## 不明を維持する87 ASN

以下は今回、ASN全体の接続方式を分類する根拠が不足しているため維持した対象です。登録用途は照合時点の補助情報で、未登録・未記載も含みます。新たな用途の確認済み情報が得られた場合に見直します。

| ASN | 事業者 | 登録用途・維持理由 |
| --- | --- | --- |
| AS2510 | FUJITSU LIMITED | 接続・上流網。固定・携帯・他用途を区別できない |
| AS2514 | NTTPC / InfoSphere | 接続・上流網。固定・携帯・他用途を区別できない |
| AS2519 | アルテリア / VECTANT / UCOM | 接続・上流網。固定・携帯・他用途を区別できない |
| AS4675 | UNIADEX LTD. | 接続・上流網。固定・携帯・他用途を区別できない |
| AS4678 | Canon IT Solutions Inc. | 接続・上流網。固定・携帯・他用途を区別できない |
| AS4686 | BEKKOAME INTERNET INC. | 登録用途の記載なし・個別の用途確認が必要 |
| AS4723 | Dolphin | 登録用途の記載なし・個別の用途確認が必要 |
| AS4725 | SoftBank / ODN | 接続・上流網。固定・携帯・他用途を区別できない |
| AS7502 | Advanced Software Technology & Management Research Institute of KYOTO | ISP登録だけでは固定・携帯・他用途を区別できない |
| AS7503 | Air Internet Service Co. Ltd. | 登録用途の記載なし・個別の用途確認が必要 |
| AS7505 | Fujitsu Systems Applications & Support Limited | 接続・上流網。固定・携帯・他用途を区別できない |
| AS7511 | SYNAPSE Co. Ltd. | ISP登録だけでは固定・携帯・他用途を区別できない |
| AS7516 | TOHKnet Co. Inc. | 接続・上流網。固定・携帯・他用途を区別できない |
| AS7522 | STNet Incorporated | 接続・上流網。固定・携帯・他用途を区別できない |
| AS7524 | ITEC HANKYU HANSHIN CO. LTD. | ISP登録だけでは固定・携帯・他用途を区別できない |
| AS7664 | HARENET INC. | ISP登録だけでは固定・携帯・他用途を区別できない |
| AS7668 | Hokuriku Telecommunication Network Co. | 接続・上流網。固定・携帯・他用途を区別できない |
| AS7672 | Hokuden Information System Service Co. Ltd. | ISP登録だけでは固定・携帯・他用途を区別できない |
| AS7674 | NTT DOCOMO BUSINESS Inc | 登録用途の記載なし・個別の用途確認が必要 |
| AS7676 | TAM Co. Ltd. | 登録用途の記載なし・個別の用途確認が必要 |
| AS7682 | HOKKAIDO TELECOMMUNICATIONS NETWORK Co. Inc. | 接続・上流網。固定・携帯・他用途を区別できない |
| AS7687 | TOYOTA SYSTEMS CORPORATION | 接続・上流網。固定・携帯・他用途を区別できない |
| AS7690 | Mirai Communication Network Inc. | 接続・上流網。固定・携帯・他用途を区別できない |
| AS9009 | M247 | VPN関連・共有基盤。VPN該当性は専用リストで判定 |
| AS9354 | Community Network Center Inc. | ISP登録だけでは固定・携帯・他用途を区別できない |
| AS9357 | NRI SecureTechnologies Ltd. | 登録用途の記載なし・個別の用途確認が必要 |
| AS9358 | OPTAGE Inc. | 登録用途の記載なし・個別の用途確認が必要 |
| AS9374 | EDION Corporation | ISP登録だけでは固定・携帯・他用途を区別できない |
| AS9595 | NTT-ME Corporation | 接続・上流網。固定・携帯・他用途を区別できない |
| AS9601 | Niigata Communication Service | ISP登録だけでは固定・携帯・他用途を区別できない |
| AS9621 | OTNet Co. Inc. | 接続・上流網。固定・携帯・他用途を区別できない |
| AS10004 | Phoenix Communications Inc. | ISP登録だけでは固定・携帯・他用途を区別できない |
| AS10010 | TOKAI / TNC | ISP登録だけでは固定・携帯・他用途を区別できない |
| AS10012 | 楽天 / FUSION / xpass | 登録用途の記載なし・個別の用途確認が必要 |
| AS10013 | FreeBit / DTI / hi-ho系 | 接続・上流網。固定・携帯・他用途を区別できない |
| AS10016 | Minaminihon Information Processing Center Co Ltd | 登録用途の記載なし・個別の用途確認が必要 |
| AS17506 | アルテリア / VECTANT / UCOM | 接続・上流網。固定・携帯・他用途を区別できない |
| AS17534 | NSK Co. Ltd. | ISP登録だけでは固定・携帯・他用途を区別できない |
| AS17678 | Gunma Internet Co .ltd | 登録用途の記載なし・個別の用途確認が必要 |
| AS17683 | Wingtechnology Communications Inc. | 接続・上流網。固定・携帯・他用途を区別できない |
| AS17691 | NDS Co. Ltd. | 登録用途の記載なし・個別の用途確認が必要 |
| AS17699 | アルテリア / VECTANT / UCOM | 登録用途の記載なし・個別の用途確認が必要 |
| AS17931 | Netforest Inc. | ISP登録だけでは固定・携帯・他用途を区別できない |
| AS17948 | EditNet Incorporated | ISP登録だけでは固定・携帯・他用途を区別できない |
| AS17950 | SaiNet | 登録用途の記載なし・個別の用途確認が必要 |
| AS17955 | Densan Co. Ltd. | ISP登録だけでは固定・携帯・他用途を区別できない |
| AS17961 | mitene internet co. ltd. | ISP登録だけでは固定・携帯・他用途を区別できない |
| AS18068 | Dream Wave Shizuoka Co. Ltd. | 登録用途の記載なし・個別の用途確認が必要 |
| AS18069 | SoftBank / ODN | 登録用途の記載なし・個別の用途確認が必要 |
| AS18070 | Global Network Core Co. Ltd. | ISP登録だけでは固定・携帯・他用途を区別できない |
| AS18090 | IMS Corporation | 登録用途の記載なし・個別の用途確認が必要 |
| AS18097 | D.C.N. Corporation | 登録用途の記載なし・個別の用途確認が必要 |
| AS18121 | Ishikawa Computer Center Co. LTD. | ISP登録だけでは固定・携帯・他用途を区別できない |
| AS18142 | KISTEM Co. Ltd. | 登録用途の記載なし・個別の用途確認が必要 |
| AS18150 | NetComBB Co. Ltd. | 接続・上流網。固定・携帯・他用途を区別できない |
| AS18268 | Naganoken Kyodou Densan Co.Ltd. | ISP登録だけでは固定・携帯・他用途を区別できない |
| AS18282 | Tonami System Solutions Co. Ltd. | ISP登録だけでは固定・携帯・他用途を区別できない |
| AS23633 | Niigata Communication Service | 登録用途の記載なし・個別の用途確認が必要 |
| AS23642 | OBIS | 登録用途の記載なし・個別の用途確認が必要 |
| AS23785 | SUN FIELD INTERNET LIMITED | 登録用途の記載なし・個別の用途確認が必要 |
| AS23818 | JETINTERNET Corporation | ISP登録だけでは固定・携帯・他用途を区別できない |
| AS24257 | JPIX / JPNE系 | 登録用途の記載なし・個別の用途確認が必要 |
| AS37904 | BBIX / BB.excite系 | 接続・上流網。固定・携帯・他用途を区別できない |
| AS37906 | GMO NetIRD Inc. | 登録用途の記載なし・個別の用途確認が必要 |
| AS38633 | Value Core Inc. | 登録用途の記載なし・個別の用途確認が必要 |
| AS38644 | transix / インターネットマルチフィード | 接続・上流網。固定・携帯・他用途を区別できない |
| AS45674 | BIGLOBE | 接続・上流網。固定・携帯・他用途を区別できない |
| AS45680 | DOVA Corporation | 接続・上流網。固定・携帯・他用途を区別できない |
| AS45691 | DODO K.K. | ISP登録だけでは固定・携帯・他用途を区別できない |
| AS49671 | DODO K.K. | ISP登録だけでは固定・携帯・他用途を区別できない |
| AS55387 | Japan Communication Inc. | ISP登録だけでは固定・携帯・他用途を区別できない |
| AS59120 | Tsukuba Internet Service Corporation | 登録用途の記載なし・個別の用途確認が必要 |
| AS63774 | Kamoike.net LLP | ISP登録だけでは固定・携帯・他用途を区別できない |
| AS63801 | DODO K.K. | ISP登録だけでは固定・携帯・他用途を区別できない |
| AS63804 | DOVA Corporation | 接続・上流網。固定・携帯・他用途を区別できない |
| AS131160 | Wire and Wireless Co. Ltd. | 接続・上流網。固定・携帯・他用途を区別できない |
| AS131913 | Oedo Telecom Inc | 登録用途の記載なし・個別の用途確認が必要 |
| AS131930 | Tokyo Broadcasting System Television Inc. | コンテンツ配信網。企業内接続元とは断定できない |
| AS136787 | PacketHub / NordVPN系 | VPN関連・共有基盤。VPN該当性は専用リストで判定 |
| AS138652 | Super Godzilla Communications GK | 登録用途の記載なし・個別の用途確認が必要 |
| AS146986 | SUZUYO SHINWART CORPORATION | 登録用途の記載なし・個別の用途確認が必要 |
| AS150363 | SoftEther Corporation | ISP登録だけでは固定・携帯・他用途を区別できない |
| AS207137 | PacketHub / NordVPN系 | VPN関連・共有基盤。VPN該当性は専用リストで判定 |
| AS208172 | Proton / Proton VPN系 | VPN関連・共有基盤。VPN該当性は専用リストで判定 |
| AS209854 | Cyberzone / Surfshark系 | VPN関連・共有基盤。VPN該当性は専用リストで判定 |
| AS216025 | Mullvad VPN | VPN関連・共有基盤。VPN該当性は専用リストで判定 |
| AS398391 | Check Point | VPN関連・共有基盤。VPN該当性は専用リストで判定 |

## 既存サイトへの反映

現在の反映方法と保持する設定は[回線分類の更新](../networks.md#初回と既存サイト)を参照してください。専用ボタンは追加せず、通常の自動・手動更新で反映します。

## 検証

2026-11-05の隔離検証で、次を確認しました。実稼働サイトへの適用は含みません。

- 回線分類関連のrace検査、identity/webuiの試験、対象パッケージのvet、サーバー/edgeのビルドが成功。
- 管理HTTPサーバーへChromiumでログインし、「今すぐ更新」と既存の標準取得元追加から、取得・自動再表示・保存値の確認までを一続きで検査するブラウザー試験を追加。390/1280pxで公開データ22,669範囲の取得成功後まで確認し、3回の更新で警告表示・JavaScript例外・HTTPエラーがいずれも0件。
- 自動更新の実処理で標準分類が反映されること、停止中・更新間隔前には設定も取得も変更しないこと、準備中の手動設定変更を上書きしないことを検査。
- 通常の「今すぐ更新」フォームから対象の編集済み標準値を上書き。取得失敗時の旧表保持、成功後のIPv4/IPv6分類とアクセス制限、手動IP上書きの保持と板別上書きの優先、再起動後の保存状態を確認。
- 公開データを実取得し、237 ASNから22,669範囲を検査。国248,953範囲、日本8,777範囲、既知VPN IPv4 11,063範囲・IPv6 656範囲を合わせて保存・再読込。

主要な再実行コマンド：

```sh
mise exec -- go test -race ./internal/bootstrap -run '^(TestNetwork|TestDomesticNetwork|TestMixedNetwork|TestServiceNetwork|TestSpecialNetwork)' -count=1 -timeout=10m
OIMO_NETWORK_LIVE=1 mise exec -- go test ./internal/bootstrap -run '^TestNetwork(LivePublicFeed|DomesticLiveStartup)$' -count=1 -v -timeout=3m
```

ブラウザー試験は `OIMO_BROWSER_NODE`・`OIMO_PLAYWRIGHT`・`OIMO_CHROMIUM` を設定し、`OIMO_NETWORK_LIVE=1 mise exec -- go test ./internal/bootstrap -run '^TestNetworkCatalogueBrowser$' -count=1 -v -timeout=3m` で公開データの実取得も含めて実行できます。`OIMO_NETWORK_BROWSER_OUTPUT` を指定すると操作後の画面と `result.json` を保存します。
