// mailの独立したキャップ制御語を取り除き、秘密を通常入力へ渡さない。
package postinput

import (
	"encoding/base64"
	"encoding/json"
	"oimobbs/internal/compat"
	"oimobbs/internal/domain"
	"strconv"
	"strings"
)

// ExtractCap はmail内の完全な一語 #cap:固定ID:secret を抽出する。
// ID・秘密の正規形と重複を検査し、制御語のないmail、ID、秘密を返す。秘密を保存してはならない。
func ExtractCap(mail string) (string, *domain.ID, string, error) {
	if !strings.Contains(strings.ToLower(mail), "#cap:") {
		return mail, nil, "", nil
	}
	if _, e := compat.Normalize(mail, false, false); e != nil || len(mail) > 256 {
		return "", nil, "", ErrInput
	}
	var id *domain.ID
	var secret string
	rest := []string{}
	for _, word := range strings.Fields(mail) {
		if !strings.Contains(strings.ToLower(word), "#cap:") {
			rest = append(rest, word)
			continue
		}
		parts := strings.Split(word, ":")
		if id != nil || len(parts) != 3 || parts[0] != "#cap" {
			return "", nil, "", ErrInput
		}
		var value domain.ID
		raw, e := base64.RawURLEncoding.DecodeString(parts[2])
		if json.Unmarshal([]byte(strconv.Quote(parts[1])), &value) != nil || value == (domain.ID{}) || value.String() != parts[1] || e != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != parts[2] {
			clear(raw)
			return "", nil, "", ErrInput
		}
		clear(raw)
		id = &value
		secret = parts[2]
	}
	if id == nil {
		return "", nil, "", ErrInput
	}
	return strings.Join(rest, " "), id, secret, nil
}
