// 圧縮非対応のGET/HEADを本文生成前に拒否し、q値・複数行・ワイルドカードを検査する。
package compat

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequireCompressedRead(t *testing.T) {
	for _, tc := range []struct {
		header []string
		status int
	}{
		{nil, 406}, {[]string{""}, 406}, {[]string{"identity"}, 406}, {[]string{"br, deflate"}, 406},
		{[]string{"gzip"}, 200}, {[]string{"zstd"}, 200}, {[]string{"GZIP;q=0.1, identity;q=1"}, 200},
		{[]string{"gzip;q=0,zstd;q=0"}, 406}, {[]string{"gzip;q=0.001"}, 200},
		{[]string{"*"}, 200}, {[]string{"*;q=0"}, 406}, {[]string{"gzip;q=0,*;q=1"}, 200},
		{[]string{"gzip;q=0,zstd;q=0,*;q=1"}, 406}, {[]string{"zstd;q=0.5,*;q=0"}, 200},
		{[]string{"br", "gzip"}, 200}, {[]string{"gzip;q=0", "zstd;q=0"}, 406},
		{[]string{"gzip;q=2"}, 400}, {[]string{"gzip, br;q=oops"}, 400},
		{[]string{"gzip;q=-1"}, 400}, {[]string{"gzip", "zstd;q=2"}, 400},
	} {
		for _, method := range []string{"GET", "HEAD"} {
			t.Run(method+strings.Join(tc.header, "|"), func(t *testing.T) {
				r := httptest.NewRequest(method, "https://example.test/", nil)
				r.Header["Accept-Encoding"] = tc.header
				r.Header.Set("Content-Encoding", "gzip")
				w := httptest.NewRecorder()
				w.Header().Set("Vary", "Origin")
				accepted := RequireCompressedRead(w, r)
				if accepted != (tc.status == 200) || w.Code != tc.status {
					t.Fatal(accepted, w.Code, tc.status)
				}
				if !strings.Contains(strings.Join(w.Header().Values("Vary"), ","), "Accept-Encoding") || w.Header().Get("Vary") != "Origin" {
					t.Fatal("Vary lost", w.Header())
				}
				if !accepted && (w.Body.Len() != 0 || w.Header().Get("Content-Length") != "0" || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Encoding") != "") {
					t.Fatal("rejection sent body or was cacheable", w.Header())
				}
			})
		}
	}
	for _, method := range []string{"POST", "PATCH", "DELETE", "OPTIONS"} {
		r := httptest.NewRequest(method, "https://example.test/", nil)
		r.Header.Set("Accept-Encoding", "gzip;q=2")
		w := httptest.NewRecorder()
		if !RequireCompressedRead(w, r) || w.Code != 200 {
			t.Fatal("non-read affected", method)
		}
	}
}
