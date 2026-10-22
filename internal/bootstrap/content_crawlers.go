// 検索・AI取得・アーカイブ・SEO収集の公開HTTP UAを、各アクセス制限で共通判定する。
package bootstrap

import "strings"

// knownContentCrawler は明示された収集用UAだけを判定する。UAの偽装や未知の収集者は検出できない。
// bot・spider等の一般語や、HTTP UAを持たないrobots専用トークンでは拒否しない。
// 確認日と公式資料は docs/features/reading.md の「標準クローラーの判定」を参照。
func knownContentCrawler(ua string) bool {
	ua = strings.ToLower(ua)
	for _, name := range [...]string{
		// 検索と検索用リソース。Googlebot・GoogleOther等の派生UAも部分一致で扱う。
		"googlebot", "googleother", "storebot-google", "bingbot", "bingpreview", "duckduckbot",
		"baiduspider", "applebot", "petalbot", "mojeekbot", "qwantbot", "seznambot",
		// YetiとSlurpは一般のアプリ名に近いため、公開UAの特徴まで含める。
		"yeti/", "yahoo! slurp",
		"yandexbot", "yandexblogs", "yandeximages", "yandexvideo", "yandexmedia", "yandexmobilebot",
		"yandexcombot", "yandexontodb", "yandexvertis", "yandexverticals",
		// AI学習・検索・利用者の指示による本文取得。
		"google-cloudvertexbot", "bytespider", "gptbot", "oai-searchbot", "chatgpt-user",
		"claudebot", "claude-searchbot", "claude-user", "ccbot", "amazonbot", "perplexitybot", "perplexity-user",
		"duckassistbot", "mistralai-user", "mistralai-index", "mistralai-training", "ai2bot",
		"meta-externalagent", "meta-externalfetcher", "meta-webindexer",
		// アーカイブと、検索順位・被リンクの調査に使われる収集者。
		"ia_archiver", "archive.org_bot", "ahrefsbot", "ahrefssiteaudit", "semrushbot", "siteauditbot",
		"splitsignalbot", "rytebot", "mj12bot", "dotbot", "blexbot", "dataforseobot", "serpstatbot",
	} {
		if strings.Contains(ua, name) {
			return true
		}
	}
	return false
}
