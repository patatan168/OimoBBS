# 閲覧・専ブラ通信・アクセス制限

公開URLとDATの取得方法、転載禁止、接続元による閲覧・投稿の許可条件を説明します。

[仕様の全体像](../specification.md) · [文書一覧](../README.md)

## 閲覧と専ブラ向け通信

### 公開URL

| 経路 | 内容 |
| --- | --- |
| `/`、`/{board}/` | サイトトップ、板トップ |
| `/bbsmenu.html`、`/bbsmenu.json` | 板メニューとカテゴリー |
| `/{board}/SETTING.TXT` | 板設定 |
| `/{board}/head.txt` | 公開ローカルルール |
| `/{board}/subject.txt` | スレッド一覧 |
| `/{board}/dat/{key}.dat` | DAT本文 |
| `/test/read.cgi/{board}/{key}/...` | Webスレッド閲覧 |
| `/test/bbs.cgi` | 専ブラからの投稿 |

### 文字コードと本文

専ブラ向け本文は固定の文字変換表を使う `sjis-compat-v1`、Web入力はUTF-8です。DATはETag、条件付き取得、HEAD、Rangeに対応します。

### 条件付き取得・差分・圧縮

公開配信はidentity（圧縮なし）、gzip、Zstandardに対応します。Brotli配信は提供しません。DATのRangeは圧縮していないDATのバイト位置を使い、有効な単一範囲をGETし、identityを許可している場合に差分を返します。保存用packやgzip・Zstandardの圧縮後バイト位置ではありません。

DATの差分応答（206）は常にidentityで返し、`Content-Encoding` を付けません。クライアントがidentityを禁止した場合は圧縮した206へ置き換えません。保存側のZstandard圧縮から復元した、元のDATバイト列に対してRangeを適用します。

ETagは取得する表現に対応した値を使います。同じ本文でもidentity・gzip・ZstandardのETagを混同しません。保存の圧縮・整理だけでは、対応する表現の本文やETagを変更しません。

既存行の削除・置換後は、古いDATの末尾へ新しい差分を足す取得を成立させません。古い本文を持つクライアントは全文を取り直します。閲覧拒否の検査は304（本文を送り直さない応答）よりも優先します。

## 転載禁止と専ブラ閲覧専用

### 転載禁止

転載禁止は板単位で設定します。共通規約の既定文では、それ以外の板への投稿は、投稿者が権利を持つ範囲で転載・再配信を許可します。著作権の帰属と掲示板運営に必要な利用許諾の個別案内は、転載禁止板だけに表示します。ローカルルール・投稿確認に案内を出し、robots、X-Robots-Tag、既知クローラーの拒否を適用します。

### 専ブラ閲覧専用

専ブラ閲覧専用の板はサイトトップと板メニューに表示します。サイト検索の板選択・結果から除外し、指定検索は404です。板トップは一覧・ローカルルール・専ブラ登録の案内を提供します。

専ブラ閲覧専用ではWebスレッド閲覧とWeb投稿を403で拒否します。UAやHTTPメソッド、Range、条件付き取得でも回避できません。DAT・subject・設定・ローカルルール・共通CGI投稿は維持します。クローラー制限も適用します。転載禁止の同意は独立した設定に従います。

### 閲覧制限との違い

| 機能 | 板一覧・メニュー | Webスレッド | DAT・共通CGI |
| --- | --- | --- | --- |
| 専ブラ閲覧専用 | 掲載を維持 | 閲覧・Web投稿を403で拒否 | 通常の許可条件に従って維持 |
| 接続元の閲覧制限 | 許可されない板を除外 | 許可されない接続を403で拒否 | 許可されない接続を403で拒否 |
| 転載禁止 | 公開案内に条件を表示 | 転載禁止の案内とクローラー制限 | 投稿確認とクローラー制限を適用 |

専ブラ閲覧専用でも、接続元の閲覧制限を免除しません。転載禁止と専ブラ閲覧専用はアクセス認証ではなく、DATの取得や利用者によるコピーそのものを防ぐ機能ではありません。

## 閲覧と投稿の許可

### 設定の適用範囲

閲覧設定は「掲示板全体」「板ごと」「管理画面のアクセス」の3つを独立して保存します。初期値はOFFです。板の閲覧には掲示板全体と板の両方の条件を満たす必要があります。管理画面には管理用の設定だけを適用します。

閲覧できない接続元は、スレッド作成・返信・CAP投稿・受理済み投稿の再送も拒否します。閲覧できる接続元にも、既存の投稿制限・Cookie・CAP資格の条件を適用します。投稿だけが禁止されている場合は閲覧できます。受理済みの投稿自体は閲覧設定の変更で削除しません。

### ローカルIP・自己IPの扱い

ローカルIP（プライベート・リンクローカル）と自己IP（ループバック）の閲覧許可は別項目です。許可・拒否・従来の回線条件に従うを選択でき、旧設定は従来条件のまま読み込みます。明示的な許可は回線・国・VPN・逆引き条件だけを免除し、IP/CIDR・クローラー・UAおよび掲示板全体の拒否は解除しません。

### 条件と判定の優先順位

| 条件 | 指定と判定 |
| --- | --- |
| 許可IP/CIDR | 空なら限定なし。指定した場合はリスト内だけ許可。最大256件 |
| 拒否IP/CIDR | 一致した接続を拒否。許可IPに含まれていても拒否。最大256件 |
| 回線種別 | 対象種別の許可・拒否。板別では板の手動分類も適用 |
| 登録国・日本限定 | 国分類表で判定。必要な表が未取得なら拒否 |
| 既知VPN | VPN分類表で判定。必要な表が未取得なら拒否 |
| 逆引き不可 | 逆引きによるホスト情報を取得できない接続の扱い |
| 既知クローラー | 対象のクローラーを拒否 |
| User-Agent | 大文字小文字を区別しない部分一致。最大64件、各256byte |

許可IPリストは入口の範囲を限定する設定です。その範囲に含まれていても、ほかの拒否条件を満たせば拒否します。

#### 標準クローラーの判定

管理画面の常時拒否、閲覧設定の「既知クローラーを拒否」、転載禁止・専ブラ閲覧専用の板は、同じ標準判定を使います。HTTPのUser-Agentを大文字小文字を区別せず照合します。管理画面は追加の接続制限がOFFでも拒否します。公開側ではそれぞれの制限が有効な範囲に適用し、通常の板を一律に非公開にはしません。

2026-10-19に公開資料を確認し、従来の22識別子に次の35識別子を加え、計57識別子としています。Googlebot・GoogleOther・Applebot・Baiduspider・SemrushBotなどは、同じ名前を含む派生UAも対象です。

| 分類 | 追加したHTTP UAの識別子 | 確認資料 |
| --- | --- | --- |
| Google | `Storebot-Google`、`Google-CloudVertexBot` | [Googleのクローラー一覧](https://developers.google.com/crawling/docs/crawlers-fetchers/google-common-crawlers) |
| Mistral | `MistralAI-User`、`MistralAI-Index`、`MistralAI-Training` | [Mistralの公開UA](https://docs.mistral.ai/robots) |
| Ai2 | `AI2Bot` | [Ai2の巡回案内](https://allenai.org/crawler) |
| Meta | `meta-externalagent`、`meta-externalfetcher`、`meta-webindexer` | [Metaのクローラー資料](https://developers.facebook.com/documentation/sharing/webmasters/web-crawlers) |
| DuckDuckGo | `DuckAssistBot` | [DuckAssistBotの公開UA](https://duckduckgo.com/duckduckgo-help-pages/results/duckassistbot) |
| その他の検索 | `MojeekBot`、`Qwantbot`、`Yeti/`、`Yahoo! Slurp`、`SeznamBot` | [Mojeek](https://www.mojeek.com/bot.html)、[Qwant](https://help.qwant.com/hc/en-us/articles/51146433634833-The-Qwant-bot-QwantBot-and-the-robots-txt-file)、[NAVER](https://searchadvisor.naver.com/guide/seo-basic-firewall)、[Yahoo](https://help.yahoo.com/kb/search-for-desktop/sln22600.html)、[Seznam](https://o-seznam.cz/napoveda/vyhledavani/en/seznambot-crawler/) |
| Yandexの検索・関連収集 | `YandexBlogs`、`YandexImages`、`YandexVideo`、`YandexMedia`、`YandexMobileBot`、`YandexComBot`、`YandexOntoDB`、`YandexVertis`、`YandexVerticals` | [Yandexの公開UA一覧](https://yandex.com/support/webmaster/en/robot-workings/check-yandex-robots) |
| SEO・被リンク調査 | `AhrefsBot`、`AhrefsSiteAudit`、`SemrushBot`、`SiteAuditBot`、`SplitSignalBot`、`RyteBot`、`MJ12bot`、`DotBot`、`BLEXBot`、`DataForSeoBot`、`serpstatbot` | [Ahrefs](https://ahrefs.com/robot)、[Semrush](https://www.semrush.com/bot/)、[Majestic](https://www.mj12bot.com/)、[Moz](https://moz.com/help/moz-procedures/crawlers/dotbot)、[BLEXBotの観測UA](https://radar.cloudflare.com/bots/directory/blexbot)、[DataForSEO](https://dataforseo.com/dataforseo-bot)、[Serpstat](https://serpstatbot.com/) |

`Yeti/`と`Yahoo! Slurp`は、一般のアプリ名への誤一致を避けるため、公開UAの特徴まで含めて照合します。`bot`・`spider`・`crawler`という一般語だけでは拒否せず、通常のブラウザ・専ブラ・HTTPクライアントをまとめて拒否しません。

Google-Extendedはrobots.txt用の制御名で、独立したHTTP UAではないため、HTTP拒否の識別子として追加しません。UAは自己申告なので、名前を隠す・偽装する収集者や未知のUAをすべて検出するものではありません。未登録のUAは閲覧設定の「拒否するUser-Agentの文字列」に追加できます。

#### 判定例

| 条件 | 結果 |
| --- | --- |
| 全体が拒否、板が許可 | その板の閲覧・投稿を拒否 |
| 全体が許可、板が拒否 | その板の閲覧・投稿を拒否 |
| 全体も板も許可、投稿規制に該当 | 閲覧は許可、投稿は拒否 |
| 許可IPに含まれるが拒否CIDRにも含まれる | 拒否 |
| ローカルIPを明示的に許可、拒否UAに該当 | 拒否 |
| 国の条件を使い、必要な国分類表が未取得 | 拒否 |
| 管理用の条件だけが拒否 | 管理画面を拒否。掲示板は全体・板の条件で別に判定 |

OFFにした閲覧設定は、その設定内の条件を判定しません。他の閲覧設定、投稿規制、認証、専ブラ専用、クローラー制限まで解除する意味ではありません。

### 配信・一覧・送信中の再検査

Webの板・スレッド・投稿フォームと、専ブラのDAT・subject・SETTING・headを制限します。許可されない板はその接続元の公開板一覧・メニュー・検索から除きます。直接取得はGET/HEAD、Range、圧縮、304の応答でも403を返します。条件付きの公開応答は共有キャッシュへ保存させず、帯域待機後・各送信片でも許可を再確認します。配布済みのクライアント内コピーは回収できません。

### 管理画面の制限と復旧

管理画面のアクセス制限は、ログイン前の画面・API・資産も対象にします。許可CIDRを `127.0.0.1/32` に限定すれば、そのIP以外を拒否できます。判定対象は実接続元、またはmTLSで認証した公開入口が確定した利用者IPです。ログイン認証と既存のクローラー拒否を継続し、現在の接続元を拒否する設定の保存は422で防ぎます。

回線変更等で入れなくなった場合は、停止中CLIで管理用制限だけをOFFにできます。[解除手順](../operations.md#管理画面のアクセス制限を解除する)に従い、掲示板の閲覧設定とパスワードは維持します。

| 閲覧設定の操作 | 必要な役割 |
| --- | --- |
| 掲示板全体・管理用の編集 | site_admin |
| 板別の編集 | 担当board_admin以上 |
| 板別の設定閲覧 | 担当board_admin以上 |

保存はCSRF・版比較・再送照会・監査を伴い、reader83以降を宣言します。reader82の旧閲覧設定も読み込めます。
