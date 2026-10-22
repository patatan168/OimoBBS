// 標準ライブラリーだけで認証アプリ互換のHMAC-SHA1・6桁・30秒TOTPを検証する。
package adminauth

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"time"
)

// TOTPSecretBytes は認証アプリに登録するランダム共有鍵の長さ（160bit）。
const TOTPSecretBytes = 20

// VerifyTOTP は前後1区間を固定回数照合する。成功時は次回の最小区間を返す。
// 呼出元は返値を耐久保存してから認証を許可し、同一・過去区間の再利用を防ぐ。
func VerifyTOTP(secret []byte, code string, minStep uint64, now time.Time) (uint64, bool) {
	if len(secret) != TOTPSecretBytes || len(code) != 6 || now.Unix() < 0 {
		return 0, false
	}
	for _, c := range []byte(code) {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	current := uint64(now.Unix() / 30)
	var next uint64
	matched := false
	for _, delta := range []int64{-1, 0, 1} {
		step := uint64(int64(current) + delta)
		candidate := totpCode(secret, step, 6)
		equal := subtle.ConstantTimeCompare([]byte(code), []byte(candidate)) == 1
		if equal && int64(current)+delta >= 0 && step >= minStep {
			next = step + 1
			matched = true
		}
	}
	return next, matched
}

// totpCode はRFC4226の動的切出しを行う。SHA1は署名用途ではなく標準TOTPのHMACにのみ使う。
func totpCode(secret []byte, counter uint64, digits int) string {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], counter)
	mac := hmac.New(sha1.New, secret)
	mac.Write(raw[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 15
	value := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	modulus := uint32(1000000)
	if digits == 8 {
		modulus = 100000000
	}
	return fmt.Sprintf("%0*d", digits, value%modulus)
}
