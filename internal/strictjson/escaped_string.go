// JSON文字列のescapeを検査しながら復号し、標準JSONへの二度目の走査を省く。
package strictjson

import "unicode/utf8"

// decodedEscapedString は引用符の内側から読み、検査済みの区間とescapeの復号値を接続する。
// 外側のscannerが本文全体のUTF-8を検査する。失敗した候補は呼出元へ公開しない。
func (s *checkedScanner) decodedEscapedString(capacity int) ([]byte, error) {
	out := make([]byte, 0, capacity)
	start := s.pos
	for s.pos < len(s.body) {
		c := s.body[s.pos]
		if c == '"' {
			out = append(out, s.body[start:s.pos]...)
			s.pos++
			return out, nil
		}
		if c < 0x20 {
			return nil, errSyntax
		}
		if c != '\\' {
			s.pos++
			continue
		}
		out = append(out, s.body[start:s.pos]...)
		value, err := s.checkedEscapeValue()
		if err != nil {
			return nil, err
		}
		out = utf8.AppendRune(out, value)
		start = s.pos
	}
	return nil, errSyntax
}
