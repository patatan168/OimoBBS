// 構文検査後の本文を走査し、重複キーと深さをtokenの生成なしで検査する。
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
)

// keyScanner は構文検査を通過済みの本文だけを扱う。一つの検証内で参照を完結させる。
type keyScanner struct {
	body     []byte
	pos      int
	selected map[string]json.RawMessage
}

// space は構文検査済みJSONの空白だけを読み飛ばす。
func (s *keyScanner) space() {
	for s.pos < len(s.body) {
		switch s.body[s.pos] {
		case ' ', '\t', '\r', '\n':
			s.pos++
		default:
			return
		}
	}
}

// quoted は文字列終端へ進め、キーの場合だけescapeを復号する。
// 値文字列はキー照合へ使わず、内容のコピーやtokenを作らない。
// escapeのないキーはbodyを借りるため、呼出元は検証の外へ保持しない。
func (s *keyScanner) quoted(key bool) ([]byte, error) {
	start := s.pos
	s.pos++
	end := s.pos + bytes.IndexByte(s.body[s.pos:], '"')
	escaped := bytes.IndexByte(s.body[s.pos:end], '\\') >= 0
	if escaped {
		for s.body[s.pos] != '"' {
			if s.body[s.pos] == '\\' {
				s.pos++
			}
			s.pos++
		}
	} else {
		s.pos = end
	}
	s.pos++
	if escaped {
		if err := unicodeEscapes(s.body[start:s.pos]); err != nil {
			return nil, err
		}
	}
	if !key {
		return nil, nil
	}
	if !escaped {
		return s.body[start+1 : s.pos-1], nil
	}
	var decoded string
	err := json.Unmarshal(s.body[start:s.pos], &decoded)
	return []byte(decoded), err
}

// container はobjectごとに独立したキー集合を持ち、配列も深さ上限へ含める。
// 構文とUTF-8は呼出元で検証済み。Unicode escapeと同名キーは文字列の走査時に拒否する。
func (s *keyScanner) container(depth int) error {
	if depth > 16 {
		return errors.New("JSON depth")
	}
	object := s.body[s.pos] == '{'
	s.pos++
	var keys keySet
	for {
		s.space()
		if s.body[s.pos] == '}' || s.body[s.pos] == ']' {
			s.pos++
			return nil
		}
		var key []byte
		if object {
			var err error
			key, err = s.quoted(true)
			if err != nil {
				return err
			}
			if !keys.add(key) {
				return errors.New("duplicate or invalid key")
			}
			s.space()
			s.pos++ // colon
			s.space()
		}
		start := s.pos
		switch s.body[s.pos] {
		case '{', '[':
			if err := s.container(depth + 1); err != nil {
				return err
			}
		case '"':
			if _, err := s.quoted(false); err != nil {
				return err
			}
		default:
			for s.body[s.pos] != ',' && s.body[s.pos] != '}' && s.body[s.pos] != ']' {
				s.pos++
			}
		}
		if depth == 1 && s.selected != nil {
			if _, wanted := s.selected[string(key)]; wanted {
				s.selected[string(key)] = bytes.TrimSpace(s.body[start:s.pos])
			}
		}
		s.space()
		if s.body[s.pos] == ',' {
			s.pos++
		}
	}
}
