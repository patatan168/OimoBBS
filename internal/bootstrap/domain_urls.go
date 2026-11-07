// 投稿中の完全なURLと公開画面でリンク化されるURLを集め、同じ宛先規制へ渡す。
package bootstrap

import (
	"regexp"
	"strings"

	"oimobbs/internal/urlhost"
)

var ruleURLs = regexp.MustCompile(`(?i)https?:[^\s<>"']+`)

// renderedRuleURLs はthread.jsのURL候補と同じ日本語区切り・ECMAScript空白・制御文字で分割する。
// 完全なURLの走査も残すことで、Unicodeドットや専用ブラウザー向け表記の既存判定を維持する。
var renderedRuleURLs = regexp.MustCompile(`(?i)https?://[^\x00-\x20\x7f\x{00a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}<>"'「」『』【】〈〉《》（）、。！？]+`)

// postingURLHosts は正規化した全宛先を重複なしで返す。DNS/HTTP照会は行わない。
func postingURLHosts(body string) []string {
	hosts := []string{}
	seen := map[string]bool{}
	add := func(raw string) {
		host, ok := urlhost.HTTP(raw)
		if ok && host != "" && !seen[host] {
			seen[host] = true
			hosts = append(hosts, host)
		}
	}
	for _, raw := range ruleURLs.FindAllString(body, -1) {
		add(strings.TrimRight(raw, ".,;!?)]}。、）】」』"))
	}
	for _, raw := range renderedRuleURLs.FindAllString(body, -1) {
		add(trimRenderedURL(raw))
	}
	return hosts
}

// trimRenderedURL は画面と同じく文末記号と対応しない閉じ括弧だけを除き、URL内部の括弧を保つ。
func trimRenderedURL(raw string) string {
	pairs := map[byte]byte{')': '(', ']': '[', '}': '{'}
	balance := map[byte]int{'(': 0, '[': 0, '{': 0}
	for i := range len(raw) {
		if _, ok := balance[raw[i]]; ok {
			balance[raw[i]]++
		} else if open, ok := pairs[raw[i]]; ok {
			balance[open]--
		}
	}
	for len(raw) > 0 {
		last := raw[len(raw)-1]
		if strings.ContainsRune(".,!?;:", rune(last)) {
			raw = raw[:len(raw)-1]
			continue
		}
		open, closing := pairs[last]
		if !closing || balance[open] >= 0 {
			break
		}
		balance[open]++
		raw = raw[:len(raw)-1]
	}
	return raw
}
