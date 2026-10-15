// 圧縮共有・有界保持・取消と、更新確認時に圧縮しないことを検証する。
package compat

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCompressionCacheConcurrentAndVersions(t *testing.T) {
	c := NewCompressionCache(1<<20, 2)
	body := []byte(strings.Repeat("日本語<>reply 0123456789\n", 1000))
	var wg sync.WaitGroup
	results := make([][]byte, 1000)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var err error
			results[i], err = c.Gzip(context.Background(), `"version1"`, body)
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	c.mu.Lock()
	builds := c.builds
	c.mu.Unlock()
	if builds != 1 {
		t.Fatalf("builds=%d", builds)
	}
	var baseline bytes.Buffer
	writer, _ := gzip.NewWriterLevel(&baseline, 6)
	_, _ = writer.Write(body)
	_ = writer.Close()
	expected := compressGzip(body)
	if len(expected) > baseline.Len() {
		t.Fatal("compression size regressed")
	}
	for _, result := range results {
		if !bytes.Equal(result, expected) {
			t.Fatal("gzip profile changed")
		}
	}
	next := append(bytes.Clone(body), []byte("next\n")...)
	result, err := c.Gzip(context.Background(), `"version2"`, next)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(result))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(reader)
	reader.Close()
	if err != nil || !bytes.Equal(raw, next) {
		t.Fatal("stale result", err)
	}
}

func TestCompressionCacheBoundsAndCancellation(t *testing.T) {
	c := NewCompressionCache(4096, 1)
	for i := range 100 {
		_, err := c.Gzip(context.Background(), strings.Repeat("x", i+1), []byte(strings.Repeat("data", 1000)))
		if err != nil {
			t.Fatal(err)
		}
	}
	if c.used > c.limit || c.order.Len() >= 100 {
		t.Fatal("cache not bounded", c.used, c.order.Len())
	}
	worker, e := c.acquireWorker(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Gzip(ctx, "cancel", []byte("abc")); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	done := make(chan error, 1)
	go func() { _, err := c.Gzip(ctx, "wait", []byte("abc")); done <- err }()
	for c.Status().Pending == 0 {
		if ctx.Err() != nil {
			t.Fatal("compression wait not reached")
		}
		runtime.Gosched()
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	c.releaseWorker(worker)
	if len(c.flights) != 0 {
		t.Fatal("cancelled flight retained")
	}
	tiny := NewCompressionCache(1, 1)
	if _, err := tiny.Gzip(context.Background(), "large", []byte("abc")); err != nil || tiny.used != 0 {
		t.Fatal("oversize cache", err)
	}
}

func TestCompressionCachePendingLimit(t *testing.T) {
	c := NewCompressionCache(4096, 2)
	for i := range 64 {
		c.flights[compressionKey{"gzip", strings.Repeat("x", i+1)}] = &compressionFlight{done: make(chan struct{})}
	}
	if _, err := c.Gzip(context.Background(), "overload", []byte("body")); !errors.Is(err, ErrCompressionCapacity) {
		t.Fatal(err)
	}
}

func TestLazyGzipConditionalAndHEAD(t *testing.T) {
	calls := 0
	p := Representation{DAT: []byte(strings.Repeat("test\n", 1000)), ETagIdentity: `"i"`, ETagGzip: `"g"`, Compress: func(context.Context, string, string, []byte) ([]byte, error) { calls++; return []byte("gzip"), nil }}
	for _, method := range []string{"GET", "HEAD"} {
		r := httptest.NewRequest(method, "/", nil)
		r.Header.Set("Accept-Encoding", "gzip")
		r.Header.Set("If-None-Match", `"g"`)
		w := httptest.NewRecorder()
		ServeDAT(w, r, p)
		if w.Code != 304 || w.Body.Len() != 0 || w.Header().Get("Content-Length") != "" {
			t.Fatal("conditional", w)
		}
	}
	r := httptest.NewRequest("HEAD", "/", nil)
	r.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	ServeDAT(w, r, p)
	if w.Code != 200 || w.Body.Len() != 0 || w.Header().Get("Content-Length") != "" || calls != 0 {
		t.Fatal("HEAD compression", calls, w)
	}
	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Range", "bytes=4995-")
	r.Header.Set("Accept-Encoding", "gzip")
	w = httptest.NewRecorder()
	ServeDAT(w, r, p)
	if w.Code != 206 || w.Body.String() != "test\n" || calls != 0 {
		t.Fatal("range compression", w)
	}
}

func BenchmarkDATDelivery(b *testing.B) {
	body := []byte(strings.Repeat("name<>sage<>2026 ID:abcd<>実況 reply 0123456789<>title\n", 4500))
	for _, mode := range []string{"full-gzip-original", "full-gzip-shared", "range-original-copy", "range-shared", "304-original-copy", "304-shared"} {
		b.Run(mode, func(b *testing.B) {
			cache := NewCompressionCache(1<<20, 2)
			p := Representation{DAT: body, ETagIdentity: `"i"`, ETagGzip: `"g"`}
			if strings.Contains(mode, "shared") {
				p.Compress = cache.Compress
				_, _ = cache.Gzip(context.Background(), `"g"`, body)
			}
			r := httptest.NewRequest("GET", "/", nil)
			if strings.HasPrefix(mode, "full") {
				r.Header.Set("Accept-Encoding", "gzip")
			}
			if strings.HasPrefix(mode, "range") {
				r.Header.Set("Range", "bytes=250000-")
			}
			if strings.HasPrefix(mode, "304") {
				r.Header.Set("If-None-Match", `"i"`)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				representation := p
				if strings.Contains(mode, "original") {
					representation.DAT = bytes.Clone(body)
				}
				w := httptest.NewRecorder()
				ServeDAT(w, r, representation)
			}
		})
	}
}

// TestSmallFeedCompression は小さい一覧の圧縮と、更新確認・差分での圧縮省略を確認する。
func TestSmallFeedCompression(t *testing.T) {
	for _, size := range []int{199, 200, 571, 992} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			cache := NewCompressionCache(1<<20, 1)
			body := bytes.Repeat([]byte("a"), size)
			p := Representation{DAT: body, ETagIdentity: `"i"`, ETagGzip: `"g"`, Compress: cache.Compress}
			request := httptest.NewRequest("GET", "/dat", nil)
			request.Header.Set("Accept-Encoding", "gzip")
			response := httptest.NewRecorder()
			ServeDAT(response, request, p)
			if response.Code != 200 {
				t.Fatal(response.Code)
			}
			if size < 200 {
				if response.Header().Get("Content-Encoding") != "" || !bytes.Equal(response.Body.Bytes(), body) {
					t.Fatal("tiny feed compressed")
				}
			} else {
				if response.Header().Get("Content-Encoding") != "gzip" || response.Body.Len() >= size {
					t.Fatal("small feed not reduced")
				}
				reader, err := gzip.NewReader(bytes.NewReader(response.Body.Bytes()))
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := io.ReadAll(reader)
				reader.Close()
				if err != nil || !bytes.Equal(decoded, body) {
					t.Fatal("compressed content changed", err)
				}
			}
			builds := cache.Status().Builds
			request.Header.Set("If-None-Match", response.Header().Get("ETag"))
			conditional := httptest.NewRecorder()
			ServeDAT(conditional, request, p)
			if conditional.Code != 304 || conditional.Body.Len() != 0 || cache.Status().Builds != builds {
				t.Fatal("conditional compressed or sent body")
			}
			request.Header.Del("If-None-Match")
			request.Header.Set("Range", fmt.Sprintf("bytes=%d-", size-1))
			delta := httptest.NewRecorder()
			ServeDAT(delta, request, p)
			if delta.Code != 206 || delta.Header().Get("Content-Encoding") != "" || delta.Body.String() != "a" || cache.Status().Builds != builds {
				t.Fatal("range not preserved")
			}
		})
	}
}

// 圧縮profileがlevel6より大きくならず、再利用後も同じbyteを生成することを検査する。
func TestGzipProfileSizeAndDeterminism(t *testing.T) {
	worker := &compressionWorker{}
	for _, size := range []int{199, 16383, 16384, 200000} {
		body := bytes.Repeat([]byte("reply 日本語<><>0123456789\n"), size/16+1)[:size]
		var baseline bytes.Buffer
		writer, _ := gzip.NewWriterLevel(&baseline, 6)
		_, _ = writer.Write(body)
		_ = writer.Close()
		result := worker.compress(body)
		if len(result) > baseline.Len() || size < 16384 && !bytes.Equal(result, baseline.Bytes()) {
			t.Fatalf("size=%d profile regressed", size)
		}
		reader, err := gzip.NewReader(bytes.NewReader(result))
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := io.ReadAll(reader)
		_ = reader.Close()
		if err != nil || !bytes.Equal(decoded, body) {
			t.Fatal("roundtrip", err)
		}
		_ = worker.compress([]byte("different input"))
		if !bytes.Equal(result, worker.compress(body)) {
			t.Fatal("nondeterministic profile")
		}
	}
}
