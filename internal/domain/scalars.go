// Package domain は保存型と時刻の業務不変条件を定義する。
package domain

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

// U64 は正規十進JSON文字列として保存する非負整数。
type U64 uint64

func (v U64) MarshalJSON() ([]byte, error) { return json.Marshal(strconv.FormatUint(uint64(v), 10)) }
func (v *U64) UnmarshalJSON(b []byte) error {
	var s string
	if e := json.Unmarshal(b, &s); e != nil {
		return e
	}
	n, e := strconv.ParseUint(s, 10, 64)
	if e != nil || strconv.FormatUint(n, 10) != s {
		return errors.New("noncanonical U64")
	}
	*v = U64(n)
	return nil
}

// Time は正規十進JSON文字列のUnixナノ秒。
type Time int64

func (v Time) MarshalJSON() ([]byte, error) { return json.Marshal(strconv.FormatInt(int64(v), 10)) }
func (v *Time) UnmarshalJSON(b []byte) error {
	var s string
	if e := json.Unmarshal(b, &s); e != nil {
		return e
	}
	n, e := strconv.ParseInt(s, 10, 64)
	if e != nil || strconv.FormatInt(n, 10) != s {
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
	return json.Marshal(id.String())
}
func (id *ID) UnmarshalJSON(b []byte) error {
	var s string
	if e := json.Unmarshal(b, &s); e != nil {
		return e
	}
	v, e := hex.DecodeString(s)
	if e != nil || len(v) != 16 || strings.ToLower(s) != s {
		return errors.New("invalid ID")
	}
	var next ID
	copy(next[:], v)
	if next == (ID{}) {
		return errors.New("zero ID")
	}
	*id = next
	return nil
}

// Hash は32byteの検査値またはHMAC。
type Hash [32]byte

func (h Hash) String() string               { return hex.EncodeToString(h[:]) }
func (h Hash) MarshalJSON() ([]byte, error) { return json.Marshal(h.String()) }
func (h *Hash) UnmarshalJSON(b []byte) error {
	var s string
	if e := json.Unmarshal(b, &s); e != nil {
		return e
	}
	v, e := hex.DecodeString(s)
	if e != nil || len(v) != 32 || strings.ToLower(s) != s {
		return errors.New("invalid hash")
	}
	copy(h[:], v)
	return nil
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
