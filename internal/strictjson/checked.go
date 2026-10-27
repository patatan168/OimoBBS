// 構文と厳密な値検査を一回で走査し、大きな無escape文字列をbyte探索で読み飛ばす。
package strictjson

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"unicode/utf8"
)

var errSyntax = errors.New("invalid JSON")

// checkedScanner は私的入力の構文境界を確認する。strict=falseでもUnicodeと深さを検査し、
// 型付き復号が後から照合するキー集合だけを作らない。本文と可変状態は共有しない。
type checkedScanner struct {
	keyScanner
	strict    bool
	rootField func([]byte, []byte) error
}

// checkedObject は全入力を検査し、成功時だけ構文検査済みの先頭走査器を返す。
// fieldsは最上位値の元byteだけを借り、失敗時の部分結果は呼出元で破棄する。
func checkedObject(b []byte, limit int, strict bool, fields map[string]json.RawMessage, rootField func([]byte, []byte) error) (keyScanner, error) {
	if limit < 0 || limit > 8<<20 || len(b) > limit || !utf8.Valid(b) {
		return keyScanner{}, errors.New("JSON size or UTF-8")
	}
	initial := keyScanner{body: b, selected: fields}
	initial.space()
	if initial.pos == len(b) || b[initial.pos] != '{' {
		return keyScanner{}, errSyntax
	}
	s := checkedScanner{keyScanner: initial, strict: strict, rootField: rootField}
	if err := s.checkedContainer(1); err != nil {
		return keyScanner{}, err
	}
	s.space()
	if s.pos != len(b) {
		return keyScanner{}, errSyntax
	}
	return initial, nil
}

// checkedContainer は閉じ括弧・colon・commaを検査し、末尾commaを許さない。
func (s *checkedScanner) checkedContainer(depth int) error {
	if depth > 16 {
		return errors.New("JSON depth")
	}
	object := s.body[s.pos] == '{'
	close := byte(']')
	if object {
		close = '}'
	}
	s.pos++
	s.space()
	if s.pos == len(s.body) {
		return errSyntax
	}
	if s.body[s.pos] == close {
		s.pos++
		return nil
	}
	var keys keySet
	for {
		var key []byte
		if object {
			var err error
			key, err = s.checkedString(s.strict || depth == 1 && (s.selected != nil || s.rootField != nil))
			if err != nil {
				return err
			}
			if s.strict && !keys.add(key) {
				return errors.New("duplicate or invalid key")
			}
			s.space()
			if s.pos == len(s.body) || s.body[s.pos] != ':' {
				return errSyntax
			}
			s.pos++
			s.space()
		}
		start := s.pos
		if err := s.checkedValue(depth); err != nil {
			return err
		}
		if depth == 1 && s.selected != nil {
			if _, wanted := s.selected[string(key)]; wanted {
				s.selected[string(key)] = s.body[start:s.pos]
			}
		}
		if depth == 1 && s.rootField != nil {
			if err := s.rootField(key, s.body[start:s.pos]); err != nil {
				return err
			}
		}
		s.space()
		if s.pos == len(s.body) {
			return errSyntax
		}
		if s.body[s.pos] == close {
			s.pos++
			return nil
		}
		if s.body[s.pos] != ',' {
			return errSyntax
		}
		s.pos++
		s.space()
		// 次反復の文字列/値検査で、末尾commaと入力の切れを拒否する。
	}
}

func (s *checkedScanner) checkedValue(depth int) error {
	if s.pos == len(s.body) {
		return errSyntax
	}
	switch s.body[s.pos] {
	case '{', '[':
		return s.checkedContainer(depth + 1)
	case '"':
		_, err := s.checkedString(false)
		return err
	case 't':
		return s.checkedLiteral("true")
	case 'f':
		return s.checkedLiteral("false")
	case 'n':
		return s.checkedLiteral("null")
	default:
		return s.checkedNumber()
	}
}

func (s *checkedScanner) checkedLiteral(text string) error {
	if !bytes.HasPrefix(s.body[s.pos:], []byte(text)) {
		return errSyntax
	}
	s.pos += len(text)
	return nil
}

// checkedNumber はJSONの数値文法だけを検査する。整数の正規表記と値域は型付き復号に残す。
func (s *checkedScanner) checkedNumber() error {
	if s.body[s.pos] == '-' {
		s.pos++
	}
	if s.pos == len(s.body) {
		return errSyntax
	}
	if s.body[s.pos] == '0' {
		s.pos++
	} else {
		if s.body[s.pos] < '1' || s.body[s.pos] > '9' {
			return errSyntax
		}
		s.digits()
	}
	if s.pos < len(s.body) && s.body[s.pos] == '.' {
		s.pos++
		if !s.digits() {
			return errSyntax
		}
	}
	if s.pos < len(s.body) && (s.body[s.pos] == 'e' || s.body[s.pos] == 'E') {
		s.pos++
		if s.pos < len(s.body) && (s.body[s.pos] == '+' || s.body[s.pos] == '-') {
			s.pos++
		}
		if !s.digits() {
			return errSyntax
		}
	}
	return nil
}

func (s *checkedScanner) digits() bool {
	start := s.pos
	for s.pos < len(s.body) && s.body[s.pos] >= '0' && s.body[s.pos] <= '9' {
		s.pos++
	}
	return s.pos > start
}

// hasControl はUTF-8検査済みの列から0x20未満のbyteだけを探す。
// 8byteの各桁の借り下がりと最上位bitを使い、非ASCII byteを制御文字と混同しない。
func hasControl(b []byte) bool {
	for len(b) >= 8 {
		x := binary.LittleEndian.Uint64(b)
		if (x-0x2020202020202020)&^x&0x8080808080808080 != 0 {
			return true
		}
		b = b[8:]
	}
	for _, c := range b {
		if c < 0x20 {
			return true
		}
	}
	return false
}

// checkedString は通常のbase64/ASCII列をvector探索し、escapeがある列だけ詳細検査する。
func (s *checkedScanner) checkedString(key bool) ([]byte, error) {
	if s.pos == len(s.body) || s.body[s.pos] != '"' {
		return nil, errSyntax
	}
	start := s.pos
	s.pos++
	end := bytes.IndexByte(s.body[s.pos:], '"')
	if end < 0 {
		return nil, errSyntax
	}
	end += s.pos
	plain := s.body[s.pos:end]
	if bytes.IndexByte(plain, '\\') < 0 {
		if hasControl(plain) {
			return nil, errSyntax
		}
		s.pos = end + 1
		if key {
			return plain, nil
		}
		return nil, nil
	}
	for s.pos < len(s.body) {
		c := s.body[s.pos]
		if c == '"' {
			s.pos++
			if !key {
				return nil, nil
			}
			var decoded string
			if err := json.Unmarshal(s.body[start:s.pos], &decoded); err != nil {
				return nil, err
			}
			return []byte(decoded), nil
		}
		if c < 0x20 {
			return nil, errSyntax
		}
		if c == '\\' {
			if err := s.checkedEscape(); err != nil {
				return nil, err
			}
		} else {
			s.pos++
		}
	}
	return nil, errSyntax
}

// checkedEscape は正しいUnicode pairだけを許し、NULと単独surrogateを拒否する。
func (s *checkedScanner) checkedEscape() error {
	s.pos++
	if s.pos == len(s.body) {
		return errSyntax
	}
	switch s.body[s.pos] {
	case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
		s.pos++
		return nil
	case 'u':
		if s.pos+5 > len(s.body) {
			return errSyntax
		}
		n, err := checkedHex4(s.body[s.pos+1 : s.pos+5])
		if err != nil || n == 0 || n >= 0xdc00 && n <= 0xdfff {
			return errSyntax
		}
		s.pos += 5
		if n < 0xd800 || n > 0xdbff {
			return nil
		}
		if s.pos+6 > len(s.body) || s.body[s.pos] != '\\' || s.body[s.pos+1] != 'u' {
			return errSyntax
		}
		low, err := checkedHex4(s.body[s.pos+2 : s.pos+6])
		if err != nil || low < 0xdc00 || low > 0xdfff {
			return errSyntax
		}
		s.pos += 6
		return nil
	default:
		return errSyntax
	}
}

// checkedHex4 は符号やprefixを受け付けず、Unicode escapeの4桁を直接照合する。
func checkedHex4(raw []byte) (uint64, error) {
	if len(raw) != 4 {
		return 0, errSyntax
	}
	var n uint64
	for _, c := range raw {
		var v byte
		switch {
		case c >= '0' && c <= '9':
			v = c - '0'
		case c >= 'a' && c <= 'f':
			v = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			v = c - 'A' + 10
		default:
			return 0, errSyntax
		}
		n = n<<4 | uint64(v)
	}
	return n, nil
}

// Schema は種別選択専用にschema文字列を返す。通常の有界JSONだけを高速走査する。
// それ以外は標準復号へ戻し、未知形式を別validatorへ委譲する従来の選択条件を保つ。
// 重複キー・Unicode・深さ・完全型は最終のDecode/Validateで必ず検査する。保存許可の代用にはしない。
func Schema(raw []byte) (string, error) {
	var schema string
	_, err := checkedObject(raw, MaxBytes, false, nil, func(key, value []byte) error {
		if !bytes.EqualFold(key, []byte("schema")) {
			return nil
		}
		if value[0] == 'n' {
			return nil
		}
		if value[0] != '"' {
			// 型の異なる種別は従来と同じ標準型エラーとして拒否する。
			var invalid string
			return json.Unmarshal(value, &invalid)
		}
		// 構文検査済みの通常ASCII種別を、反射やinterfaceへの退避なしで取り出す。
		field := keyScanner{body: value}
		text, err := field.quoted(true)
		if err == nil {
			schema = string(text)
		}
		return err
	})
	if err != nil {
		var marker struct {
			Schema string `json:"schema"`
		}
		if err := json.Unmarshal(raw, &marker); err != nil {
			return "", err
		}
		return marker.Schema, nil
	}
	return schema, nil
}
