// ヘッダーの禁止byte・有界な検査量・宣言本文長を、本文を受信せず照合する。
package waf

import (
	"net/http"
	"strconv"
	"strings"
)

// MaxRequestBodyBytes はWAFで許す宣言本文長の全体上限。各入口のより小さい上限も適用する。
const MaxRequestBodyBytes = 256 << 10
const maxUserAgentBytes = 1024
const maxHeaderFields = 128

// inspectHeaders はCookie・Authorizationにも構文と量の上限だけを適用する。
// 値の攻撃パターン検査からは従来通り除外し、本文や認証情報の解析・保存を行わない。
func inspectHeaders(r *http.Request) string {
	if r.ContentLength < -1 || r.ContentLength > MaxRequestBodyBytes {
		return "content_length"
	}
	if len(r.Header) > maxHeaderFields {
		return "header_fields"
	}
	size, fields, agentBytes, lengths := 0, 0, 0, 0
	for name, values := range r.Header {
		fields += max(1, len(values))
		if fields > maxHeaderFields {
			return "header_fields"
		}
		if len(name) > maxInspectionBytes-size {
			return "header_size"
		}
		if len(values) == 0 {
			size += len(name)
		}
		agent := strings.EqualFold(name, "User-Agent")
		length := strings.EqualFold(name, "Content-Length")
		secret := strings.EqualFold(name, "Cookie") || strings.EqualFold(name, "Authorization")
		for _, value := range values {
			if len(name) > maxInspectionBytes-size || len(value) > maxInspectionBytes-size-len(name) {
				return "header_size"
			}
			size += len(name) + len(value)
			if agent {
				agentBytes += len(value)
				if agentBytes > maxUserAgentBytes {
					return "user_agent_size"
				}
			}
			if forbiddenHeaderByte(value) {
				return "header_control"
			}
			if length {
				lengths++
				if lengths != 1 || !validContentLength(value, r.ContentLength) || len(r.TransferEncoding) != 0 {
					return "content_length"
				}
			}
			if !secret && strings.Contains(value, "${") && hasJNDILookup(value) {
				return "header_injection"
			}
		}
	}
	return ""
}

// forbiddenHeaderByte はHTTPで許されるHTABと非ASCIIのopaque byteを残す。
func forbiddenHeaderByte(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] < 32 && value[i] != '\t' || value[i] == 127 {
			return true
		}
	}
	return false
}

// validContentLength はOWS以外を補正せず、十進の宣言値とGoが解釈した長さを照合する。
func validContentLength(raw string, length int64) bool {
	raw = strings.Trim(raw, " \t")
	if raw == "" {
		return false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < '0' || raw[i] > '9' {
			return false
		}
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	return err == nil && value == length && value <= MaxRequestBodyBytes
}
