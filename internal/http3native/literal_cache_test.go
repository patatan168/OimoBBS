// 公開header符号列の再利用でwireが変わらず、秘密情報と履歴の容量が漏れないことを検証する。
package http3native

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestLiteralCachePreservesWireAndOwnership(t *testing.T) {
	q := newQPACK(nil, nil)
	f := Field{"etag", `"unchanged"`}
	want := literal(nil, f)
	for range 3 {
		got := q.appendLiteral(nil, f)
		if !bytes.Equal(got, want) {
			t.Fatalf("wire=%x want=%x", got, want)
		}
		clear(got)
	}
	if len(q.literals) != 1 {
		t.Fatalf("cache entries=%d", len(q.literals))
	}
	for _, name := range []string{"authorization", "proxy-authorization", "cookie", "set-cookie", "x-secret"} {
		q.appendLiteral(nil, Field{name, "secret"})
	}
	if len(q.literals) != 1 {
		t.Fatal("cached a private header")
	}
	for i := range 1000 {
		q.appendLiteral(nil, Field{"etag", fmt.Sprintf("%0512d", i)})
		if len(q.literals) > 64 || q.literalBytes > 8<<10 {
			t.Fatalf("unbounded cache: entries=%d bytes=%d", len(q.literals), q.literalBytes)
		}
	}
}

func TestDecodedValueCacheBoundsAndPrivacy(t *testing.T) {
	q := newQPACK(nil, nil)
	decode := func(name, value string, indexable bool) string {
		t.Helper()
		encoded := appendString(nil, 0, 7, 0x80, value)
		r := &fieldReader{Reader: bytes.NewReader(encoded[1:]), data: encoded[1:]}
		got, err := q.readValue(encoded[0], r, name, indexable)
		if err != nil || got != value || r.Len() != 0 {
			t.Fatalf("decode=%q error=%v", got, err)
		}
		clear(encoded)
		return got
	}
	value := "OimoBBS public conditional request"
	decode("user-agent", value, true)
	decode("user-agent", value, true)
	if len(q.values) != 1 {
		t.Fatal("public value was not reused")
	}
	for _, name := range []string{":path", "cookie", "authorization", "proxy-authorization", "x-secret"} {
		decode(name, "private-data-to-avoid-retaining", true)
	}
	decode("user-agent", "never-index-this-public-field", false)
	decode("user-agent", strings.Repeat("a", 513), true)
	if len(q.values) != 1 {
		t.Fatal("cached private, never-index, or oversized value")
	}
	for i := range 1000 {
		decode("user-agent", fmt.Sprintf("value%03d%s", i, strings.Repeat("a", 120)), true)
		if len(q.values) > 32 || q.valueBytes > 4096 {
			t.Fatal("decoded value cache exceeded its bound")
		}
	}
}

func TestShortDynamicResponseAvoidsFeedbackOverhead(t *testing.T) {
	q := newQPACK(nil, nil)
	if err := q.configure(4096, 16); err != nil {
		t.Fatal(err)
	}
	fields := []Field{{":status", "304"}, {"etag", `"short"`}, {"date", "Tue, 03 Nov 2026 00:00:00 GMT"}}
	block, err := q.encode(0, fields)
	if err != nil || block[0] != 0 || q.tx.count != 0 || len(q.sections) != 0 {
		t.Fatalf("short response requires feedback: %x %v", block, err)
	}
	got, err := newQPACK(nil, nil).decode(t.Context(), 0, block)
	if err != nil || fmt.Sprint(got) != fmt.Sprint(fields) {
		t.Fatalf("static fallback: %v %v", got, err)
	}
}
