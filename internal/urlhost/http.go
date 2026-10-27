// Package urlhost は投稿規制用にHTTP/HTTPSの宛先だけを正規化する。外部通信は行わない。
package urlhost

import (
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

// HTTP はURL文字列から比較用のASCIIホストを返す。解析不能な宛先ではfalseを返す。
// 特殊URLの区切り、percent復号、UTS #46・NFC・Punycode、IPv4の別表記を扱う。
// パス・クエリの解析やDNS解決はせず、ホストの入力は4096byteまでに制限する。
func HTTP(raw string) (string, bool) {
	if strings.ContainsAny(raw, "\t\r\n") {
		raw = strings.Map(func(r rune) rune {
			if r == '\t' || r == '\r' || r == '\n' {
				return -1
			}
			return r
		}, raw)
	}
	scheme, rest, ok := strings.Cut(raw, ":")
	if !ok || !strings.EqualFold(scheme, "http") && !strings.EqualFold(scheme, "https") {
		return "", false
	}
	rest = strings.TrimLeft(rest, "/\\")
	if end := strings.IndexAny(rest, "/\\?#"); end >= 0 {
		rest = rest[:end]
	}
	if at := strings.LastIndexByte(rest, '@'); at >= 0 {
		rest = rest[at+1:]
	}
	if len(rest) == 0 || len(rest) > 4096 {
		return "", false
	}
	if rest[0] == '[' {
		return ipv6Host(rest)
	}
	if colon := strings.LastIndexByte(rest, ':'); colon >= 0 {
		if !validPort(rest[colon+1:]) {
			return "", false
		}
		rest = rest[:colon]
	}
	host, err := url.PathUnescape(rest)
	if err != nil || !utf8.ValidString(host) || host == "" {
		return "", false
	}
	host, ok = asciiDomain(host)
	if !ok {
		return "", false
	}
	if normalized, numeric := ipv4Host(host); numeric {
		return normalized, normalized != ""
	}
	return strings.TrimSuffix(host, "."), true
}

func ipv6Host(authority string) (string, bool) {
	end := strings.IndexByte(authority, ']')
	if end < 0 {
		return "", false
	}
	if suffix := authority[end+1:]; suffix != "" && (!strings.HasPrefix(suffix, ":") || !validPort(suffix[1:])) {
		return "", false
	}
	ip, err := netip.ParseAddr(authority[1:end])
	if err != nil || !ip.Is6() || ip.Zone() != "" {
		return "", false
	}
	if ip.Is4In6() {
		bytes := ip.As16()
		return "[::ffff:" + strconv.FormatUint(uint64(bytes[12])<<8|uint64(bytes[13]), 16) + ":" + strconv.FormatUint(uint64(bytes[14])<<8|uint64(bytes[15]), 16) + "]", true
	}
	return "[" + ip.String() + "]", true
}

func validPort(raw string) bool {
	if raw == "" {
		return true
	}
	for _, c := range raw {
		if c < '0' || c > '9' {
			return false
		}
	}
	_, err := strconv.ParseUint(raw, 10, 16)
	return err == nil
}

// ipv4Host は末尾が数値の宛先をIPv4としてのみ解釈し、不正な数値をDNS名へ戻さない。
func ipv4Host(host string) (string, bool) {
	parts := strings.Split(strings.TrimSuffix(host, "."), ".")
	last := parts[len(parts)-1]
	_, numeric := ipv4Number(last)
	if !numeric && !decimal(last) && !hexadecimal(last) {
		return "", false
	}
	if len(parts) > 4 {
		return "", true
	}
	var value uint64
	for i, part := range parts {
		n, ok := ipv4Number(part)
		if !ok {
			return "", true
		}
		if i == len(parts)-1 {
			if n >= uint64(1)<<(8*(5-len(parts))) {
				return "", true
			}
			value += n
		} else {
			if n > 255 {
				return "", true
			}
			value += n << (8 * (3 - i))
		}
	}
	return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)}).String(), true
}

func ipv4Number(raw string) (uint64, bool) {
	if raw == "" {
		return 0, false
	}
	base := 10
	if len(raw) >= 2 && raw[0] == '0' {
		base, raw = 8, raw[1:]
		if raw[0] == 'x' || raw[0] == 'X' {
			base, raw = 16, raw[1:]
		}
	}
	if raw == "" {
		return 0, true
	}
	for _, c := range raw {
		if !(c >= '0' && c <= '9' || base == 16 && (c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F')) {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(raw, base, 64)
	return n, err == nil
}

func hexadecimal(raw string) bool {
	if len(raw) < 3 || raw[0] != '0' || raw[1] != 'x' && raw[1] != 'X' {
		return false
	}
	for _, c := range raw[2:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func decimal(raw string) bool {
	if raw == "" {
		return false
	}
	for _, c := range raw {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
