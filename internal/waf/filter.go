// Package waf は本文を読まず、URLとヘッダーの明確な探索・攻撃パターンを有界に検査する。
package waf

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

const maxInspectionBytes = 16 << 10
const maxQueryFields = 128

var injection = regexp.MustCompile(`(?i)(?:\bunion\s+(?:all\s+)?select\b|\b(?:sleep|pg_sleep|benchmark)\s*\(|\bwaitfor\s+delay\b|<\s*(?:script|iframe|object|embed)\b|javascript\s*:|\bon(?:error|load)\s*=|(?:^|[;&|])\s*(?:curl|wget|bash|sh|cmd\.exe|powershell)\b)`)

var lookupFragment = regexp.MustCompile(`(?i)\$\{(?:(?:lower|upper):|[^{}]*:-)([^{}]*)\}`)

// Inspect は遮断する規則名を返す。空文字は通過。Bodyを読まず、Cookie・認証情報は構文と量だけを検査する。
// SQL/XSS等はURLに限定し、検索語qは正規の/searchでのみ除外する。
func Inspect(r *http.Request) string {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions:
	default:
		return "method"
	}
	if len(r.URL.EscapedPath())+len(r.URL.RawQuery) > maxInspectionBytes {
		return "url_size"
	}
	// 同名・空項目も数え、mapや値配列を確保するParseQueryより前に拒否する。
	// 生の区切りだけを見るため、値に含まれる%26は項目数を増やさない。
	if r.URL.RawQuery != "" && strings.Count(r.URL.RawQuery, "&") >= maxQueryFields {
		return "query_fields"
	}
	if rule := inspectHeaders(r); rule != "" {
		return rule
	}
	path := normalize(r.URL.EscapedPath())
	if badPath(path) {
		return "path"
	}
	// 正規のパスで注入規則に必要な区切りがなければ正規表現を省く。
	if (!strings.HasPrefix(path, "/") || strings.ContainsAny(path, " \t\n\r\f(<:=;&|*")) && hasInjection(path) {
		return "url_injection"
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return "query_encoding"
	}
	for key, values := range query {
		if r.URL.Path == "/search" && key == "q" {
			continue
		}
		if hasInjection(normalize(key)) {
			return "url_injection"
		}
		for _, value := range values {
			if hasInjection(normalize(value)) {
				return "url_injection"
			}
		}
	}
	return ""
}

// hasInjection はSQLコメントを含む値だけを整形して再照合する。
func hasInjection(value string) bool {
	// 注入規則には区切り文字が必要。区切りなしの先頭コマンドだけ別に残す。
	if !strings.ContainsAny(value, " \t\n\r\f(<:=;&|*") && !commandPrefix(value) {
		return false
	}
	if injection.MatchString(value) {
		return true
	}
	if !strings.Contains(value, "/*") {
		return false
	}
	var clean strings.Builder
	for {
		start := strings.Index(value, "/*")
		if start < 0 {
			clean.WriteString(value)
			break
		}
		clean.WriteString(value[:start])
		end := strings.Index(value[start+2:], "*/")
		if end < 0 {
			clean.WriteString(value[start:])
			break
		}
		clean.WriteByte(' ')
		value = value[start+2+end+2:]
	}
	return injection.MatchString(clean.String())
}

// commandPrefix は先頭だけで成立する既知コマンドの候補を選ぶ。
// 非ASCIIの先頭はUnicodeの大小文字同一視を取りこぼさないよう正規表現へ渡す。
func commandPrefix(value string) bool {
	if len(value) == 0 {
		return false
	}
	var word string
	switch value[0] {
	case 'c', 'C':
		return len(value) >= 4 && strings.EqualFold(value[:4], "curl") || len(value) >= 7 && strings.EqualFold(value[:7], "cmd.exe")
	case 'w', 'W':
		word = "wget"
	case 'b', 'B':
		word = "bash"
	case 's', 'S':
		word = "sh"
	case 'p', 'P':
		word = "powershell"
	default:
		return value[0] >= 128
	}
	if len(value) < len(word) {
		return false
	}
	for _, ch := range value[:len(word)] {
		if ch >= 128 {
			return true
		}
	}
	return strings.EqualFold(value[:len(word)], word)
}

// hasJNDILookup は既知の大小文字変換・既定値による難読化を最大4段まで展開する。
// 外部参照や環境変数の評価はせず、検査量はヘッダー上限に従う。
func hasJNDILookup(value string) bool {
	value = strings.ToLower(value)
	for range 4 {
		if strings.Contains(value, "${jndi:") {
			return true
		}
		next := lookupFragment.ReplaceAllString(value, "$1")
		if next == value {
			return false
		}
		value = next
	}
	return strings.Contains(value, "${jndi:")
}

// normalize は最大3回のpercent復号で多重エンコードを照合する。復号不能なら元の表現を維持する。
func normalize(value string) string {
	for range 3 {
		next, err := url.PathUnescape(value)
		if err != nil || next == value {
			break
		}
		value = next
	}
	return value
}

// badPath はOSの区切り差と大小文字を吸収し、経路移動と秘密ファイルの探索を拒否する。
func badPath(value string) bool {
	start := 0
	for end := 0; end <= len(value); end++ {
		if end < len(value) {
			if value[end] < 32 || value[end] == 127 {
				return true
			}
			if value[end] != '/' && value[end] != '\\' {
				continue
			}
		}
		part := value[start:end]
		if secretPathPart(part) {
			return true
		}
		switch {
		case part == ".", part == "..", strings.EqualFold(part, ".git"), strings.EqualFold(part, ".svn"), strings.EqualFold(part, ".hg"), strings.EqualFold(part, ".ssh"), strings.EqualFold(part, ".aws"), strings.EqualFold(part, ".env"):
			return true
		case len(part) >= 5 && part[4] == '.' && strings.EqualFold(part[:4], ".env"):
			return true
		}
		start = end + 1
	}
	return false
}

// secretPathPart は公開用途のない認証・設定ファイルと代表的な退避名を拒否する。
func secretPathPart(part string) bool {
	if len(part) == 0 {
		return false
	}
	switch part[0] {
	case '.', 'i', 'I', 'w', 'W':
	default:
		return false
	}
	switch strings.ToLower(part) {
	case ".docker", ".kube", ".npmrc", ".netrc", ".htpasswd", ".ds_store", "id_rsa", "id_ed25519":
		return true
	}
	if strings.EqualFold(part, ".env~") || strings.EqualFold(part, "wp-config.php") {
		return true
	}
	const config = "wp-config.php"
	return len(part) > len(config) && (part[len(config)] == '.' || part[len(config)] == '~') && strings.EqualFold(part[:len(config)], config)
}
