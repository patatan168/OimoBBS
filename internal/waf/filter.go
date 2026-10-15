// Package waf は本文を読まず、URLとヘッダーの明確な探索・攻撃パターンを有界に検査する。
package waf

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

const maxInspectionBytes = 16 << 10

var injection = regexp.MustCompile(`(?i)(?:\bunion\s+(?:all\s+)?select\b|\b(?:sleep|benchmark)\s*\(|<\s*(?:script|iframe)\b|javascript\s*:|\bon(?:error|load)\s*=|(?:^|[;&|])\s*(?:curl|wget|bash|sh|cmd\.exe|powershell)\b)`)

// Inspect は遮断する規則名を返す。空文字は通過。Body・Cookie・認証情報は読み取らない。
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
	path := normalize(r.URL.EscapedPath())
	if badPath(path) {
		return "path"
	}
	// 正規のパスで注入規則に必要な区切りがなければ正規表現を省く。
	if (!strings.HasPrefix(path, "/") || strings.ContainsAny(path, " \t\n\r\f(<:=;&|")) && injection.MatchString(path) {
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
		if injection.MatchString(normalize(key)) {
			return "url_injection"
		}
		for _, value := range values {
			if injection.MatchString(normalize(value)) {
				return "url_injection"
			}
		}
	}
	size := 0
	for name, values := range r.Header {
		if strings.EqualFold(name, "Cookie") || strings.EqualFold(name, "Authorization") {
			continue
		}
		size += len(name)
		for _, value := range values {
			size += len(value)
			if size > maxInspectionBytes {
				return "header_size"
			}
			if strings.Contains(value, "${") && strings.Contains(strings.ToLower(value), "${jndi:") {
				return "header_injection"
			}
		}
	}
	return ""
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
