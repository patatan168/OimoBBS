// 固定CSS/JSの表現別キャッシュ検証と圧縮本文を検査する。
package webui

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http/httptest"
	"testing"

	"oimobbs/internal/testutil"
)

func TestAssetCompressionAndConditional(t *testing.T) {
	for path, p := range publicAssets {
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("Accept-Encoding", "gzip")
		w := httptest.NewRecorder()
		if !ServeAsset(w, req) || w.Code != 200 || w.Header().Get("Content-Encoding") != "gzip" {
			t.Fatal(path, w.Code)
		}
		reader, err := gzip.NewReader(w.Body)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(reader)
		reader.Close()
		if err != nil || !bytes.Equal(body, p.DAT) {
			t.Fatal("asset mismatch", path, err)
		}
		req.Header.Set("If-None-Match", w.Header().Get("ETag"))
		w = httptest.NewRecorder()
		ServeAsset(w, req)
		if w.Code != 304 || w.Body.Len() != 0 || w.Header().Get("Content-Length") != "" {
			t.Fatal("asset conditional", path)
		}
		req = httptest.NewRequest("HEAD", path, nil)
		w = httptest.NewRecorder()
		ServeAsset(w, req)
		if w.Code != 200 || w.Body.Len() != 0 || w.Header().Get("ETag") == p.ETagGzip {
			t.Fatal("asset HEAD", path)
		}
	}
}

// 版付きURLだけが長期保存でき、alias・失敗・未知の版が混ざらないことを確認する。
func TestVersionedAssetCaching(t *testing.T) {
	for name, path := range versionedAssetPaths {
		p := publicAssets[path]
		want := fmt.Sprintf("/web/assets/%x/%s", sha256.Sum256(p.DAT), name)
		if path != want {
			t.Fatal("asset URL is not bound to content", path)
		}
		for _, coding := range []string{"identity", "gzip", "zstd"} {
			r := httptest.NewRequest("GET", path, nil)
			r.Header.Set("Accept-Encoding", coding)
			w := httptest.NewRecorder()
			ServeAsset(w, r)
			if w.Code != 200 || w.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
				t.Fatal(path, coding, w.Code, w.Header())
			}
			body := w.Body.Bytes()
			if coding == "gzip" {
				g, err := gzip.NewReader(bytes.NewReader(body))
				if err != nil {
					t.Fatal(err)
				}
				body, err = io.ReadAll(g)
				g.Close()
				if err != nil {
					t.Fatal(err)
				}
			} else if coding == "zstd" {
				var err error
				body, err = testutil.DecodeZstd(body)
				if err != nil {
					t.Fatal(err)
				}
			}
			if !bytes.Equal(body, p.DAT) {
				t.Fatal("versioned body mismatch")
			}
			t.Logf("%s %s bytes=%d", name, coding, w.Body.Len())
			r.Header.Set("If-None-Match", w.Header().Get("ETag"))
			w = httptest.NewRecorder()
			ServeAsset(w, r)
			if w.Code != 304 || w.Body.Len() != 0 || w.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
				t.Fatal("versioned revalidation", path)
			}
		}
		r := httptest.NewRequest("GET", "/web/assets/"+name, nil)
		w := httptest.NewRecorder()
		ServeAsset(w, r)
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-cache" || !bytes.Equal(w.Body.Bytes(), p.DAT) {
			t.Fatal("mutable alias became immutable")
		}
		r = httptest.NewRequest("GET", path, nil)
		r.Header.Set("Accept-Encoding", "gzip")
		ctx, cancel := context.WithCancel(r.Context())
		cancel()
		w = httptest.NewRecorder()
		ServeAsset(w, r.WithContext(ctx))
		if w.Code != 503 || w.Header().Get("Cache-Control") != "no-cache" {
			t.Fatal("failure cached", w.Code, w.Header())
		}
	}
	w := httptest.NewRecorder()
	ServeAsset(w, httptest.NewRequest("GET", "/web/assets/unknown/ui.js", nil))
	if w.Code != 404 || w.Header().Get("Cache-Control") == "public, max-age=31536000, immutable" {
		t.Fatal("unknown version served")
	}
}
