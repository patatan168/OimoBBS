// 小さいobjectのキーは本文参照で保持し、大きいobjectだけmapへ移す。
package strictjson

import "bytes"

// keySet は一つの検証中だけ使う。借りた本文を呼出し後に保持しない。
type keySet struct {
	small [32][]byte
	count int
	large map[string]struct{}
}

// add は復号後の同名キーがあればfalseを返す。
// 線形比較は32件までとし、多数の外部キーでも二乗時間へ増えない。
func (s *keySet) add(key []byte) bool {
	if s.large != nil {
		if _, found := s.large[string(key)]; found {
			return false
		}
		s.large[string(key)] = struct{}{}
		return true
	}
	for _, prior := range s.small[:s.count] {
		if bytes.Equal(prior, key) {
			return false
		}
	}
	if s.count < len(s.small) {
		s.small[s.count] = key
		s.count++
		return true
	}
	s.large = make(map[string]struct{}, len(s.small)+1)
	for _, prior := range s.small {
		s.large[string(prior)] = struct{}{}
	}
	s.large[string(key)] = struct{}{}
	return true
}
