// 公開UAの収集判定・通常クライアントの非該当・閲覧制限のON/OFFを検証する。
package bootstrap

import (
	"net/netip"
	"strings"
	"testing"
)

// crawlerTestAgents は標準リストとは別に、公開されたHTTP UAの製品名を固定する。
func crawlerTestAgents() []string {
	return []string{
		"Googlebot", "GoogleOther", "bingbot", "bingpreview", "DuckDuckBot", "YandexBot", "Baiduspider", "Applebot", "PetalBot", "Bytespider",
		"GPTBot", "OAI-SearchBot", "ChatGPT-User", "ClaudeBot", "Claude-SearchBot", "Claude-User", "CCBot", "ia_archiver", "archive.org_bot", "Amazonbot", "PerplexityBot", "Perplexity-User",
		"Storebot-Google", "Google-CloudVertexBot", "DuckAssistBot", "MistralAI-User", "MistralAI-Index", "MistralAI-Training", "AI2Bot",
		"meta-externalagent", "meta-externalfetcher", "meta-webindexer", "MojeekBot", "Qwantbot", "Yeti", "Yahoo! Slurp", "SeznamBot",
		"YandexBlogs", "YandexImages", "YandexVideo", "YandexMedia", "YandexMobileBot", "YandexComBot", "YandexOntoDB", "YandexVertis", "YandexVerticals",
		"AhrefsBot", "AhrefsSiteAudit", "SemrushBot", "SiteAuditBot", "SplitSignalBot", "RyteBot", "MJ12bot", "DotBot", "BLEXBot", "DataForSeoBot", "serpstatbot",
	}
}

func TestKnownContentCrawlerAgents(t *testing.T) {
	for _, name := range crawlerTestAgents() {
		t.Run(name, func(t *testing.T) {
			for _, ua := range []string{name + "/1.0", "Mozilla/5.0 (compatible; " + name + "/2.1; +https://example.invalid/crawler)", strings.ToUpper(name) + "/3.0"} {
				if !knownContentCrawler(ua) {
					t.Fatalf("known crawler accepted: %q", ua)
				}
			}
		})
	}
	for _, ua := range []string{
		"", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140.0.0.0 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Android 15; Mobile; rv:142.0) Gecko/142.0 Firefox/142.0",
		"Monazilla/1.00 ChMate/0.8.10", "JaneStyle/5.0", "OleBoardBrowser/1.0", "curl/8.12.0", "Wget/1.25", "python-requests/2.32.0", "Go-http-client/1.1",
		"ExampleBot/1.0", "MySpider/1.0", "SomeCrawler/1.0", "YetiBrowser/1.0", "SlurpReader/1.0", "Mozilla/5.0 YaBrowser/25.1", "SogouMobileBrowser/6.0",
	} {
		if knownContentCrawler(ua) {
			t.Errorf("ordinary or unknown agent rejected: %q", ua)
		}
	}
}

func TestReadingKnownContentCrawlerModes(t *testing.T) {
	allow := true
	for _, mode := range []struct{ enabled, deny bool }{{false, false}, {false, true}, {true, false}, {true, true}} {
		p := defaultReadingPolicy()
		p.Enabled = mode.enabled
		p.DenyCrawlers = mode.deny
		p.AllowLoopbackIP = &allow
		compiled, err := compileReadingPolicy(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range crawlerTestAgents() {
			err := compiled.check(nil, netip.MustParseAddr("127.0.0.1"), name+"/1.0")
			if got, want := err != nil, mode.enabled && mode.deny; got != want {
				t.Fatalf("%s enabled=%v deny=%v: %v", name, mode.enabled, mode.deny, err)
			}
		}
		if err := compiled.check(nil, netip.MustParseAddr("127.0.0.1"), "Monazilla/1.00 ChMate/0.8.10"); err != nil {
			t.Fatal("ordinary reader", err)
		}
	}
}
