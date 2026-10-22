// 公開経路を確認したクラウド・衛星・学術網の補完候補。接続者の所属や契約サービスは保証しない。
// 参照: https://www.nic.ad.jp/ja/ip/as-numbers.txt / https://github.com/ipverse/as-ip-blocks
// ｸﾓﾉｳｴ と ｳﾁｭｰ はOimoBBS独自の呼称。その他の特殊表示は5ch BBS_SLIPに合わせる。
package bootstrap

var specialNetworkPresets = []networkPreset{
	{"starlink-as14593", "Starlink（AS14593・事業者網の推定）", "satellite", "ｳﾁｭｰ", "U", 14593},
	{"sakura-as7684", "さくらインターネット（AS7684・事業者網の推定）", "hosting", "ｸﾓﾉｳｴ", "V", 7684},
	{"sakura-as9370", "さくらインターネット（AS9370・事業者網の推定）", "hosting", "ｸﾓﾉｳｴ", "V", 9370},
	{"sakura-as9371", "さくらインターネット（AS9371・事業者網の推定）", "hosting", "ｸﾓﾉｳｴ", "V", 9371},
	{"hetzner-as24940", "Hetzner（AS24940・事業者網の推定）", "hosting", "ｸﾓﾉｳｴ", "V", 24940},
	{"ovh-as16276", "OVHcloud（AS16276・事業者網の推定）", "hosting", "ｸﾓﾉｳｴ", "V", 16276},
	{"digitalocean-as14061", "DigitalOcean（AS14061・事業者網の推定）", "hosting", "ｸﾓﾉｳｴ", "V", 14061},
	{"vultr-as20473", "Vultr / The Constant Company（AS20473・事業者網の推定）", "hosting", "ｸﾓﾉｳｴ", "V", 20473},
	{"linode-as63949", "Akamai / Linode（AS63949・事業者網の推定）", "hosting", "ｸﾓﾉｳｴ", "V", 63949},
	{"scaleway-as12876", "Scaleway（AS12876・事業者網の推定）", "hosting", "ｸﾓﾉｳｴ", "V", 12876},
	{"contabo-as51167", "Contabo（AS51167・事業者網の推定）", "hosting", "ｸﾓﾉｳｴ", "V", 51167},
	{"aws-as16509", "Amazon Web Services（AS16509・事業者網の推定）", "hosting", "ｸﾓﾉｳｴ", "V", 16509},
	{"aws-as14618", "Amazon Web Services（AS14618・事業者網の推定）", "hosting", "ｸﾓﾉｳｴ", "V", 14618},
	{"gcp-as396982", "Google Cloud（AS396982・事業者網の推定）", "hosting", "ｸﾓﾉｳｴ", "V", 396982},
	{"microsoft-as8075", "Microsoft（AS8075・事業者網の推定）", "hosting", "ｸﾓﾉｳｴ", "V", 8075},
	{"oracle-as31898", "Oracle Cloud（AS31898・事業者網の推定）", "hosting", "ｸﾓﾉｳｴ", "V", 31898},
	{"alibaba-as45102", "Alibaba Cloud（AS45102・事業者網の推定）", "hosting", "ｸﾓﾉｳｴ", "V", 45102},
	{"sinet-as2907", "SINET / NII（AS2907・事業者網の推定）", "academic", "ｶﾞｯｸｼ", "6", 2907},
	{"utnet-as2501", "東京大学 UTnet（AS2501・事業者網の推定）", "academic", "ｶﾞｯｸｼ", "6", 2501},
	{"nca5-as2504", "NCA5 / 京都大学（AS2504・事業者網の推定）", "academic", "ｶﾞｯｸｼ", "6", 2504},
	{"hepnet-as2505", "HEPNET-J / 高エネルギー加速器研究機構（AS2505・事業者網の推定）", "academic", "ｶﾞｯｸｼ", "6", 2505},
	{"supercsi-as2506", "SuperCSI / 大阪大学（AS2506・事業者網の推定）", "academic", "ｶﾞｯｸｼ", "6", 2506},
	{"kyushu-u-as2508", "九州大学（AS2508・事業者網の推定）", "academic", "ｶﾞｯｸｼ", "6", 2508},
	{"apan-jp-as7660", "APAN-JP（AS7660・事業者網の推定）", "academic", "ｶﾞｯｸｼ", "6", 7660},
	{"wide-ai3-as4717", "WIDE / AI3（AS4717・事業者網の推定）", "academic", "ｶﾞｯｸｼ", "6", 4717},
	{"jst-as2513", "科学技術振興機構（AS2513・事業者網の推定）", "government", "ｺﾑｲｰﾝ", "G", 2513},
}
