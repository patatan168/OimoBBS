// 投稿操作の省略・生JSON・整数表記を含め、生成JSONを標準実装と照合する。
package domain

import (
	"bytes"
	"encoding/json"
	"testing"
)

func checkDomainJSON(t testing.TB, s string, n uint64, on bool) {
	t.Helper()
	h := Hash{3}
	id := ID{1}
	rev := U64(n)
	p := Post{Number: uint32(n), Name: s, Body: s, Created: Time(n), Private: &Private{SourceIP: s, CapID: &id, RateKeys: []RateKey{{id, 1, h, 1}}}}
	a := Append{[]Post{p}}
	c := Create{Title: s, Created: Time(n), Expires: Time(-1), Policy: Policy{CapOnly: on, Commands: []string{s}}, Posts: a.Posts}
	op := Operation{Type: s, Revision: rev, Committed: Time(n), Versions: Versions{Cap: &rev}, Actor: Actor{ID: &id, Request: &h, Idempotency: &h}, Dedup: &Dedup{Subject: h, RequestID: &h}, Payload: json.RawMessage(s)}
	for _, tc := range []struct {
		v    any
		fast func() ([]byte, error)
	}{{a, func() ([]byte, error) { return MarshalAppend(a) }}, {c, func() ([]byte, error) { return MarshalCreate(c) }}, {op, func() ([]byte, error) { return MarshalOperation(op) }}} {
		want, we := json.Marshal(tc.v)
		got, ge := tc.fast()
		if (we == nil) != (ge == nil) || we == nil && !bytes.Equal(want, got) {
			t.Fatalf("operation mismatch %v %v\n%s\n%s", we, ge, want, got)
		}
	}
}
func TestGeneratedDomainJSON(t *testing.T) {
	for _, s := range []string{"日本語<&>\n", ` { "a" : "<>&" } `, `null`, `{"x":1,"x":2}`, ""} {
		for _, on := range []bool{false, true} {
			checkDomainJSON(t, s, ^uint64(0), on)
		}
	}
	for _, a := range []Append{{}, {Posts: []Post{}}} {
		want, _ := json.Marshal(a)
		got, e := MarshalAppend(a)
		if e != nil || !bytes.Equal(want, got) {
			t.Fatal("nil/empty posts changed")
		}
	}
}
func FuzzGeneratedDomainJSON(f *testing.F) {
	f.Add(`{"x":"日本語<&>"}`, uint64(1), true)
	f.Fuzz(func(t *testing.T, s string, n uint64, on bool) { checkDomainJSON(t, s, n, on) })
}
