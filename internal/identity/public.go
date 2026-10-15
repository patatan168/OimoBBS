// 日IDとSLIPの用途分離HMACを生成する。
package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/netip"
	"oimobbs/internal/domain"
	"strconv"
	"strings"
	"time"
)

// MAC は長さ付きのdomainと各fieldにHMAC-SHA256を適用する。
func MAC(key []byte, domainName string, fields ...[]byte) domain.Hash {
	h := hmac.New(sha256.New, key)
	for _, v := range append([][]byte{[]byte(domainName)}, fields...) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(v)))
		_, _ = h.Write(n[:])
		_, _ = h.Write(v)
	}
	var out domain.Hash
	copy(out[:], h.Sum(nil))
	return out
}

// CanonicalIP はIPv4-mappedを正規化し、family付きIPを返す。
func CanonicalIP(ip netip.Addr) ([]byte, error) {
	if !ip.IsValid() || ip.Zone() != "" {
		return nil, errors.New("invalid IP")
	}
	ip = ip.Unmap()
	family := byte(6)
	if ip.Is4() {
		family = 4
	}
	return append([]byte{family}, ip.AsSlice()...), nil
}

// DailyID は板UUID/JST日付/完全IPから公開8文字を生成する。
func DailyID(key []byte, board domain.ID, now time.Time, ip netip.Addr) (string, error) {
	raw, e := CanonicalIP(ip)
	if e != nil {
		return "", e
	}
	h := MAC(key, "oimo/id/v1", board[:], []byte(now.In(domain.JST).Format("2006-01-02")), raw)
	return base64.StdEncoding.EncodeToString(h[:])[:8], nil
}

// Slip はAABB-CCDDを生成する。AA/DDだけ木曜始まりで更新し、BB/CCは板内で固定する。
// providerは運営の分類キー、anonymousIDは署名と失効を検証済みのCookie IDだけを渡す。
func Slip(netKey, uaKey []byte, board domain.ID, now time.Time, ip netip.Addr, provider string, anonymousID domain.ID, ua string) (string, error) {
	if anonymousID == (domain.ID{}) || !ValidProvider(provider) || len(netKey) != 32 || len(uaKey) != 32 {
		return "", errors.New("invalid slip identity")
	}
	ip = ip.Unmap()
	if _, err := CanonicalIP(ip); err != nil {
		return "", err
	}
	bits := 64
	if ip.Is4() {
		bits = 24
	}
	raw, _ := CanonicalIP(netip.PrefixFrom(ip, bits).Masked().Addr())
	seconds := now.Unix() + 9*3600
	days := seconds / 86400
	if seconds < 0 && seconds%86400 != 0 {
		days--
	}
	week := days / 7
	if days < 0 && days%7 != 0 {
		week--
	}
	period := []byte(strconv.FormatInt(week, 10))
	aa := MAC(netKey, "oimo/slip-net/v2", board[:], period, raw)
	bb := MAC(netKey, "oimo/slip-provider/v2", board[:], []byte(provider))
	cc := MAC(uaKey, "oimo/slip-anonymous/v2", board[:], anonymousID[:])
	dd := MAC(uaKey, "oimo/slip-ua/v2", board[:], period, []byte(ClassifyUA(ua)))
	part := func(h domain.Hash) string { return base64.RawURLEncoding.EncodeToString(h[:])[:2] }
	return part(aa) + part(bb) + "-" + part(cc) + part(dd), nil
}

// ClassifyUA はコメントを除き、最大8個のASCII product/majorを抽出する。
func ClassifyUA(ua string) string {
	var fields []string
	depth := 0
	size := 0
	for i := 0; i < len(ua) && len(fields) < 8; {
		c := ua[i]
		if c == '(' {
			depth++
			i++
			continue
		}
		if c == ')' {
			if depth > 0 {
				depth--
			}
			i++
			continue
		}
		if depth > 0 || !product(c) {
			i++
			continue
		}
		start := i
		for i < len(ua) && product(ua[i]) {
			i++
		}
		name := ua[start:i]
		if i >= len(ua) || ua[i] != '/' {
			continue
		}
		i++
		start = i
		for i < len(ua) && ua[i] >= '0' && ua[i] <= '9' {
			i++
		}
		if i == start {
			continue
		}
		major := strings.TrimLeft(ua[start:i], "0")
		if major == "" {
			major = "0"
		}
		s := strings.ToLower(name) + "/" + major
		if size+len(s)+len(fields) > 256 {
			break
		}
		fields = append(fields, s)
		size += len(s)
		for i < len(ua) && ua[i] != ' ' && ua[i] != '(' {
			i++
		}
	}
	if len(fields) == 0 {
		return "unknown"
	}
	return strings.Join(fields, " ")
}
func product(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-' || b == '_' || b == '.'
}
