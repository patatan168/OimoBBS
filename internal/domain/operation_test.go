// 設計の業務fixtureを厳密型で読み込み、改変を拒否する。
package domain

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"oimobbs/internal/strictjson"
	"oimobbs/internal/textcodec"
	"os"
	"testing"
)

func TestCreateFixture(t *testing.T) {
	b, e := os.ReadFile("../../docs/design/fixtures/wal-v1-create.json")
	if e != nil {
		t.Fatal(e)
	}
	var f struct {
		Operation json.RawMessage `json:"operation"`
		DAT       string          `json:"dat_hex"`
	}
	if e = json.Unmarshal(b, &f); e != nil {
		t.Fatal(e)
	}
	o, e := ParseOperation(f.Operation)
	if e != nil {
		t.Fatal(e)
	}
	dat, _ := hex.DecodeString(f.DAT)
	s, e := Apply(nil, o, dat)
	if e != nil {
		t.Fatal(e)
	}
	if s.After.PostCount != 1 {
		t.Fatal(s.After)
	}
	o.After.PostCount = 2
	if _, e = Apply(nil, o, dat); e == nil {
		t.Fatal("invalid after accepted")
	}
	for _, bad := range [][]byte{bytes.Replace(f.Operation, []byte(`"revision": "1"`), []byte(`"revision": "01"`), 1), bytes.Replace(f.Operation, []byte(`"user_count": 1`), []byte(`"user_count": 1e0`), 1)} {
		if _, e = ParseOperation(bad); e == nil {
			t.Fatal("noncanonical accepted")
		}
	}
}
func TestScalars(t *testing.T) {
	for _, v := range []string{`{"n":"-0"}`, `{"n":"01"}`, `{"n":1}`, `{"n":"18446744073709551616"}`} {
		var dst struct {
			N U64 `json:"n"`
		}
		if strictjson.Decode([]byte(v), &dst) == nil {
			t.Fatal(v)
		}
	}
}

func TestRedactionPreservesNumbersAndRejectsOldBody(t *testing.T) {
	b, e := os.ReadFile("../../docs/design/fixtures/wal-v1-create.json")
	if e != nil {
		t.Fatal(e)
	}
	var f struct {
		Operation json.RawMessage `json:"operation"`
		DAT       string          `json:"dat_hex"`
	}
	_ = json.Unmarshal(b, &f)
	create, e := ParseOperation(f.Operation)
	if e != nil {
		t.Fatal(e)
	}
	dat, _ := hex.DecodeString(f.DAT)
	old, e := Apply(nil, create, dat)
	if e != nil {
		t.Fatal(e)
	}
	post := old.Posts[0]
	post.Visibility = "aboon"
	post.Name = "あぼーん"
	post.Mail = ""
	post.Body = "あぼーん"
	post.Identity = Identity{DateText: "あぼーん"}
	line, _ := textcodec.Encode("あぼーん<><>あぼーん<>あぼーん<>example\n", false)
	post.DATLength = uint32(len(line))
	payload, _ := json.Marshal(Redact{Posts: []Post{post}})
	id, key, h := NewID(), uint32(1), Hash{}
	after := old.After
	after.DATBytes = U64(len(line))
	after.DATGeneration = 2
	after.LegacyRangeDisabled = true
	op := Operation{Type: "redact", Revision: 2, Committed: create.Committed, Versions: Versions{Site: 1, Board: 1, Thread: 1}, Actor: Actor{Kind: "admin", ID: &id, Reason: "moderation", Request: &h, Idempotency: &h, KeyID: &key}, After: after, Payload: payload}
	next, e := Apply(old, op, line)
	if e != nil {
		t.Fatal(e)
	}
	if next.After.PostCount != 1 || old.Posts[0].Body != "hello" || next.Posts[0].Body != "あぼーん" {
		t.Fatal("number or immutable state")
	}
	bad := bytes.Replace(line, []byte("<>example"), []byte("<>private"), 1)
	post.DATLength = uint32(len(bad))
	op.Payload, _ = json.Marshal(Redact{Posts: []Post{post}})
	op.After.DATBytes = U64(len(bad))
	if _, e = Apply(old, op, bad); e == nil {
		t.Fatal("unexpected title accepted")
	}
}
