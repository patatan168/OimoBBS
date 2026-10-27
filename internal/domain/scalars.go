// Package domain は保存型と時刻の業務不変条件を定義する。
package domain

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"time"
)

// U64 は正規十進JSON文字列として保存する非負整数。
type U64 uint64

func (v U64) MarshalJSON() ([]byte, error) {
	b := strconv.AppendUint(append(make([]byte, 0, 22), '"'), uint64(v), 10)
	return append(b, '"'), nil
}
func (v *U64) UnmarshalJSON(b []byte) error {
	s, e := scalarText(b)
	if e != nil {
		return e
	}
	n, e := strconv.ParseUint(string(s), 10, 64)
	if e != nil || !canonicalDecimal(s, false) {
		return errors.New("noncanonical U64")
	}
	*v = U64(n)
	return nil
}

// Time は正規十進JSON文字列のUnixナノ秒。
type Time int64

func (v Time) MarshalJSON() ([]byte, error) {
	b := strconv.AppendInt(append(make([]byte, 0, 22), '"'), int64(v), 10)
	return append(b, '"'), nil
}
func (v *Time) UnmarshalJSON(b []byte) error {
	s, e := scalarText(b)
	if e != nil {
		return e
	}
	n, e := strconv.ParseInt(string(s), 10, 64)
	if e != nil || !canonicalDecimal(s, true) {
		return errors.New("noncanonical Time")
	}
	*v = Time(n)
	return nil
}

// ID は全ゼロを許さない128bit識別子。
type ID [16]byte

func NewID() ID {
	var id ID
	for id == (ID{}) {
		_, _ = rand.Read(id[:])
	}
	return id
}
func (id ID) String() string { return hex.EncodeToString(id[:]) }
func (id ID) MarshalJSON() ([]byte, error) {
	if id == (ID{}) {
		return nil, errors.New("zero ID")
	}
	return marshalHex(id[:]), nil
}
func (id *ID) UnmarshalJSON(b []byte) error {
	s, e := scalarText(b)
	if e != nil {
		return e
	}
	var next ID
	if !decodeLowerHex(next[:], s) {
		return errors.New("invalid ID")
	}
	if next == (ID{}) {
		return errors.New("zero ID")
	}
	*id = next
	return nil
}

// Hash は32byteの検査値またはHMAC。
type Hash [32]byte

func (h Hash) String() string               { return hex.EncodeToString(h[:]) }
func (h Hash) MarshalJSON() ([]byte, error) { return marshalHex(h[:]), nil }
func (h *Hash) UnmarshalJSON(b []byte) error {
	s, e := scalarText(b)
	if e != nil {
		return e
	}
	var next Hash
	if !decodeLowerHex(next[:], s) {
		return errors.New("invalid hash")
	}
	*h = next
	return nil
}

// scalarText は正規ASCII表記を入力から借用し、エスケープ等は標準JSONへ委ねる。
// 戻り値はこの呼出し元の検査中だけ使用し、保持しない。
func scalarText(b []byte) ([]byte, error) {
	if len(b) >= 2 && b[0] == '"' && b[len(b)-1] == '"' {
		text := b[1 : len(b)-1]
		plain := true
		for _, c := range text {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c == '-') {
				plain = false
				break
			}
		}
		if plain {
			return text, nil
		}
	}
	var text string
	if e := json.Unmarshal(b, &text); e != nil {
		return nil, e
	}
	return []byte(text), nil
}

// canonicalDecimal はParseInt/ParseUint成功後に正規十進表記だけを許す。
func canonicalDecimal(text []byte, signed bool) bool {
	if len(text) == 0 {
		return false
	}
	if signed && text[0] == '-' {
		text = text[1:]
		if len(text) == 0 || text[0] == '0' {
			return false
		}
	}
	return text[0] >= '0' && text[0] <= '9' && (len(text) == 1 || text[0] != '0')
}

func marshalHex(value []byte) []byte {
	b := make([]byte, 2+hex.EncodedLen(len(value)))
	b[0], b[len(b)-1] = '"', '"'
	hex.Encode(b[1:len(b)-1], value)
	return b
}

// decodeLowerHex は検査用の局所配列へ復号し、大文字を拒否する。
func decodeLowerHex(dst, text []byte) bool {
	if len(text) != hex.EncodedLen(len(dst)) {
		return false
	}
	for _, c := range text {
		if c >= 'A' && c <= 'F' {
			return false
		}
	}
	_, e := hex.Decode(dst, text)
	return e == nil
}

var JST = time.FixedZone("JST", 9*60*60)

// SixMonths はJSTの月末を丸め、同時刻の6暦月後を返す。
func SixMonths(t time.Time) time.Time {
	t = t.In(JST)
	y, m, d := t.Date()
	last := time.Date(y, m+7, 0, 0, 0, 0, 0, JST).Day()
	if d > last {
		d = last
	}
	return time.Date(y, m+6, d, t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), JST)
}
