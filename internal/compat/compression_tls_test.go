// 実TLS HTTPで新しい圧縮表現の本文、旧ETagからの更新、304と非圧縮Rangeを確認する。
package compat

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"oimobbs/internal/testutil"
	"testing"
)

func TestCompressionTLSRepresentationUpgrade(t *testing.T) {
	raw := testutil.DATFixture("mixed")
	cache := NewCompressionCache(1<<20, 2)
	tag := `"fixture` + ZstdETagSuffix + `"`
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ServeDAT(w, r, Representation{DAT: raw, ETagIdentity: `"fixture-identity"`, ETagZstd: tag, Compress: cache.Compress})
	}))
	defer server.Close()
	client := server.Client()
	for _, tc := range []struct {
		name, condition, span string
		status                int
	}{
		{"old representation", `"fixture-zstd-v7"`, "", http.StatusOK},
		{"same representation", tag, "", http.StatusNotModified},
		{"DAT delta", "", "bytes=100-", http.StatusPartialContent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), "GET", server.URL+"/dat", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Accept-Encoding", "zstd")
			req.Header.Set("If-None-Match", tc.condition)
			req.Header.Set("Range", tc.span)
			response, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || response.StatusCode != tc.status {
				t.Fatal(response.Status, err)
			}
			switch tc.status {
			case http.StatusOK:
				if response.Header.Get("ETag") != tag || response.Header.Get("Content-Encoding") != "zstd" || !bytes.Equal(decodeCoding(t, "zstd", body), raw) {
					t.Fatal("compressed representation mismatch")
				}
			case http.StatusNotModified:
				if len(body) != 0 {
					t.Fatal("304 contains body")
				}
			case http.StatusPartialContent:
				if response.Header.Get("Content-Encoding") != "" || !bytes.Equal(body, raw[100:]) {
					t.Fatal("identity range mismatch")
				}
			}
		})
	}
	if status := cache.Status(); status.Builds != 1 {
		t.Fatal("conditional and range rebuilt compressed body", status)
	}
}
