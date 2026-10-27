// 新圧縮方式の展開一致・総容量・交渉・条件判定・差分の非圧縮を検査する。
package compat

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"oimobbs/internal/testutil"
)

// decodeCoding は製品の圧縮結果を独立したdecoderで元byteへ戻す。
func decodeCoding(t *testing.T, coding string, body []byte) []byte {
	t.Helper()
	var reader io.Reader
	switch coding {
	case "gzip":
		r, e := gzip.NewReader(bytes.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		defer r.Close()
		reader = r
	case "zstd":
		raw, e := testutil.DecodeZstd(body)
		if e != nil {
			t.Fatal(e)
		}
		return raw

	default:
		return body
	}
	raw, e := io.ReadAll(reader)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}

func TestCompressionSharedBudgetAndVersions(t *testing.T) {
	cache := NewCompressionCache(1<<20, 2)
	body := []byte(strings.Repeat("日本語 response<>0123456789\n", 2000))
	var wg sync.WaitGroup
	for i := range 300 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			coding := []string{"gzip", "zstd"}[i%2]
			encoded, e := cache.Compress(t.Context(), coding, "same-tag", body)
			if e != nil {
				t.Error(e)
				return
			}
			if !bytes.Equal(decodeCoding(t, coding, encoded), body) {
				t.Error("roundtrip")
			}
		}()
	}
	wg.Wait()
	if got := cache.Status(); got.Builds != 2 || got.Entries != 2 || got.Used > got.Limit || got.Pending != 0 {
		t.Fatal(got)
	}
	next := append(bytes.Clone(body), []byte("next\n")...)
	for _, coding := range []string{"gzip", "zstd"} {
		encoded, e := cache.Compress(t.Context(), coding, "next", next)
		if e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(decodeCoding(t, coding, encoded), next) {
			t.Fatal("stale version")
		}
		again, e := NewCompressionCache(0, 1).Compress(t.Context(), coding, "next", next)
		if e != nil || !bytes.Equal(encoded, again) {
			t.Fatal("nondeterministic encoding", e)
		}
	}
	small := NewCompressionCache(4096, 1)
	for i := range 100 {
		_, e := small.Compress(t.Context(), []string{"gzip", "zstd"}[i%2], strings.Repeat("k", i+1), body)
		if e != nil {
			t.Fatal(e)
		}
	}
	if got := small.Status(); got.Used > got.Limit || got.Entries >= 100 {
		t.Fatal(got)
	}
}

// TestCompressionKeyNamespaces は同じ公開版のHTML・gzip・zstdを混同せず再取得できることを確認する。
func TestCompressionKeyNamespaces(t *testing.T) {
	c := NewCompressionCache(1<<20, 1)
	body := bytes.Repeat([]byte("same version body\n"), 30)
	for range 2 {
		rendered, err := c.Render(t.Context(), "same", func() ([]byte, error) { return body, nil })
		if err != nil || !bytes.Equal(rendered, body) {
			t.Fatal("render", err)
		}
		for _, coding := range []string{"gzip", "zstd"} {
			encoded, err := c.Compress(t.Context(), coding, "same", body)
			if err != nil || !bytes.Equal(decodeCoding(t, coding, encoded), body) {
				t.Fatal(coding, err)
			}
		}
	}
	if s := c.Status(); s.Builds != 3 || s.Hits != 3 || s.Entries != 3 || s.Used > s.Limit {
		t.Fatal(s)
	}
}

func TestCompressionNegotiationAndConditions(t *testing.T) {
	body := []byte(strings.Repeat("response 日本語\n", 2000))
	for _, tc := range []struct {
		accept, coding, rangeHeader string
		status                      int
		feed                        bool
	}{
		{"zstd,gzip", "zstd", "", 200, false},
		{"br,zstd,gzip", "zstd", "", 200, false},
		{"br,zstd,gzip", "zstd", "", 200, true},
		{"zstd;q=0,br,gzip", "gzip", "", 200, false},
		{"zstd;q=0,br,gzip", "gzip", "", 200, true},
		{"zstd;q=0.5,gzip;q=1", "gzip", "", 200, false},
		{"identity;q=0.1,zstd;q=0.5,gzip;q=0.2", "zstd", "", 200, false},
		{"zstd;q=0.5,identity;q=1", "", "", 200, false},
		{"zstd;q=0,gzip;q=0,identity;q=0", "", "", 406, false},
		{"br,identity;q=0", "", "", 406, false},
		{"br,identity;q=0", "", "", 406, true},
		{"br,gzip", "gzip", "", 200, true},
		{"br", "", "", 200, true},
		{"*;q=1", "zstd", "", 200, false},
		{"zstd,*;q=0", "zstd", "", 200, false},
		{"zstd;q=0,*;q=0", "", "", 406, false},
		{"zstd;q=2", "", "", 400, false},
		{"zstd,br,gzip", "", "bytes=10-", 206, false},
		{"zstd,identity;q=0", "zstd", "bytes=10-", 200, false},
	} {
		t.Run(tc.accept+tc.rangeHeader+strings.Repeat("f", boolInt(tc.feed)), func(t *testing.T) {
			cache := NewCompressionCache(1<<20, 2)
			p := Representation{DAT: body, DisableRange: tc.feed, Compress: cache.Compress, ETagIdentity: `"i"`, ETagGzip: `"g"`, ETagZstd: `"z"`}
			request := httptest.NewRequest("GET", "/dat", nil)
			request.Header.Set("Accept-Encoding", tc.accept)
			request.Header.Set("Range", tc.rangeHeader)
			response := httptest.NewRecorder()
			ServeDAT(response, request, p)
			if response.Code != tc.status || response.Header().Get("Content-Encoding") != tc.coding {
				t.Fatal(response.Code, response.Header())
			}
			if tc.status == 200 && !bytes.Equal(decodeCoding(t, tc.coding, response.Body.Bytes()), body) {
				t.Fatal("body mismatch")
			}
			if tc.status == 206 && (!bytes.Equal(response.Body.Bytes(), body[10:]) || cache.Status().Builds != 0) {
				t.Fatal("range compression")
			}
			if tc.status != 200 {
				return
			}
			builds := cache.Status().Builds
			for _, method := range []string{"GET", "HEAD"} {
				r := httptest.NewRequest(method, "/dat", nil)
				r.Header.Set("Accept-Encoding", tc.accept)
				r.Header.Set("If-None-Match", response.Header().Get("ETag"))
				w := httptest.NewRecorder()
				ServeDAT(w, r, p)
				if w.Code != 304 || w.Body.Len() != 0 || cache.Status().Builds != builds {
					t.Fatal("conditional compression", w.Code)
				}
			}
			calls := 0
			p.Compress = func(context.Context, string, string, []byte) ([]byte, error) { calls++; return nil, nil }
			r := httptest.NewRequest("HEAD", "/dat", nil)
			r.Header.Set("Accept-Encoding", tc.accept)
			w := httptest.NewRecorder()
			ServeDAT(w, r, p)
			if calls != 0 || w.Body.Len() != 0 || w.Code != 200 {
				t.Fatal("HEAD compression")
			}
		})
	}
}
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// 空本文を強制圧縮した場合も有効なframeとし、小本文・window境界で展開一致を検査する。
func TestCompressionEmptyAndWindowBoundary(t *testing.T) {
	for _, size := range []int{0, 1, 199, 200, 1 << 20} {
		body := bytes.Repeat([]byte("r"), size)
		cache := NewCompressionCache(1<<20, 1)
		for _, coding := range []string{"gzip", "zstd"} {
			encoded, e := cache.Compress(t.Context(), coding, "version", body)
			if e != nil || len(encoded) == 0 || !bytes.Equal(decodeCoding(t, coding, encoded), body) {
				t.Fatal(size, coding, e)
			}
		}
	}
}

// TestRenderedRepresentationSharing は本文生成の共有と圧縮との名前空間・予算の共用を確認する。
func TestRenderedRepresentationSharing(t *testing.T) {
	cache := NewCompressionCache(64<<10, 2)
	raw := bytes.Repeat([]byte("<p>response</p>"), 1000)
	var calls atomic.Int32
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body, err := cache.Render(t.Context(), "page", func() ([]byte, error) { calls.Add(1); return raw, nil })
			if err != nil || !bytes.Equal(body, raw) {
				t.Error("render", err)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatal("duplicate page generation", calls.Load())
	}
	compressed, err := cache.Compress(t.Context(), "gzip", "page", raw)
	if err != nil || !bytes.Equal(decodeCoding(t, "gzip", compressed), raw) {
		t.Fatal("namespace collision", err)
	}
	if got := cache.Status(); got.Entries != 2 || got.Builds != 2 || got.Used > got.Limit {
		t.Fatal("shared budget", got)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := cache.Render(cancelled, "page", func() ([]byte, error) { t.Error("cancelled callback"); return nil, nil }); err != context.Canceled {
		t.Fatal(err)
	}
	tiny := NewCompressionCache(1, 1)
	for range 2 {
		if _, err := tiny.Render(t.Context(), "page", func() ([]byte, error) { return raw, nil }); err != nil {
			t.Fatal(err)
		}
	}
	if got := tiny.Status(); got.Entries != 0 || got.Used != 0 || got.Builds != 2 {
		t.Fatal("oversized page retained", got)
	}
}
