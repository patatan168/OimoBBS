// 用途別の永続HMAC鍵をサイトmasterから導出する。
package identity

import (
	"errors"
	"oimobbs/internal/domain"
	"strconv"
)

// DeriveKey は32byte master、ASCII用途、非ゼロ鍵IDをLP形式で用途分離する。
// Ed25519署名鍵はこの関数で導出せず、独立した乱数seedを使用する。
func DeriveKey(master []byte, purpose string, id uint32) (domain.Hash, error) {
	if len(master) != 32 || id == 0 || len(purpose) == 0 || len(purpose) > 64 {
		return domain.Hash{}, errors.New("invalid key derivation input")
	}
	for _, c := range purpose {
		if !(c >= 'a' && c <= 'z' || c == '_') {
			return domain.Hash{}, errors.New("invalid key purpose")
		}
	}
	return MAC(master, "oimo/key/v1", []byte(purpose), []byte(strconv.FormatUint(uint64(id), 10))), nil
}
