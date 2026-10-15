// WALへ保存する前の単独レス上限がpackのJSON・DAT・外枠上限と一致することを検証する。
package domain

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestStoredPostPackSizeBoundary(t *testing.T) {
	raw, e := os.ReadFile("../../docs/design/fixtures/wal-v1-create.json")
	if e != nil {
		t.Fatal(e)
	}
	var f struct {
		Operation json.RawMessage `json:"operation"`
		DAT       string          `json:"dat_hex"`
	}
	if e = json.Unmarshal(raw, &f); e != nil {
		t.Fatal(e)
	}
	op, e := ParseOperation(f.Operation)
	if e != nil {
		t.Fatal(e)
	}
	dat, e := hex.DecodeString(f.DAT)
	if e != nil {
		t.Fatal(e)
	}
	var c Create
	if e = json.Unmarshal(op.Payload, &c); e != nil {
		t.Fatal(e)
	}
	p := c.Posts[0]
	p.Body = ""
	j, e := json.Marshal(p)
	if e != nil {
		t.Fatal(e)
	}
	size := MaxStoredPostBytes - len(j) - len(dat) - 32
	for _, extra := range []int{-1, 0, 1} {
		p.Body = strings.Repeat("x", size+extra)
		c.Posts[0] = p
		op.Payload, _ = json.Marshal(c)
		_, e = Apply(nil, op, dat)
		if (e == nil) != (extra <= 0) {
			t.Fatalf("boundary %+d: %v", extra, e)
		}
	}
}
