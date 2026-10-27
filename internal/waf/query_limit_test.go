// クエリの解析前に項目数を制限し、拒否時の追加割当と本文読取りを防ぐ。
package waf

import (
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInspectQueryFieldLimit(t *testing.T) {
	for _, tc := range []struct{ name, query, want string }{
		{"empty", "", ""},
		{"128-distinct", queryFields(128), ""},
		{"129-distinct", queryFields(129), "query_fields"},
		{"128-repeated", strings.Repeat("a=1&", 127) + "a=1", ""},
		{"129-repeated", strings.Repeat("a=1&", 128) + "a=1", "query_fields"},
		{"empty-segments", strings.Repeat("&", 128), "query_fields"},
		{"encoded-separators", "q=" + strings.Repeat("%26", 256), ""},
		{"search-text", "q=UNION+SELECT%26%3Cscript%3E", ""},
		{"invalid-encoding", "a=%zz", "query_encoding"},
		{"injection-within-limit", strings.Repeat("a=1&", 127) + "x=UNION+SELECT", "url_injection"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/search?"+tc.query, nil)
			if got := Inspect(r); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestInspectQueryRejectionHasNoAllocations(t *testing.T) {
	request := httptest.NewRequest("POST", "/test/bbs.cgi?"+queryFields(129), strings.NewReader("unchanged"))
	if got := Inspect(request); got != "query_fields" {
		t.Fatal(got)
	}
	allocations := testing.AllocsPerRun(100, func() {
		if got := Inspect(request); got != "query_fields" {
			panic(got)
		}
	})
	if allocations != 0 {
		t.Fatalf("rejected query allocated: %v", allocations)
	}
	body, err := io.ReadAll(request.Body)
	if err != nil || string(body) != "unchanged" {
		t.Fatal("body read or modified", err)
	}
}

func queryFields(count int) string {
	var query strings.Builder
	for i := 0; i < count; i++ {
		if i > 0 {
			query.WriteByte('&')
		}
		fmt.Fprintf(&query, "p%d=1", i)
	}
	return query.String()
}
