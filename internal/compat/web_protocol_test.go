// HTTP世代の拒否と専ブラ例外の境界を検査する。
package compat

import (
	"fmt"
	"io"
	"net/http/httptest"
	"testing"
)

// unreadProtocolBody は拒否中に要求本文を読み始めた場合に試験を失敗させる。
type unreadProtocolBody struct{ t *testing.T }

func (b unreadProtocolBody) Read([]byte) (int, error) {
	b.t.Fatal("protocol rejection read request body")
	return 0, io.EOF
}
func (unreadProtocolBody) Close() error { return nil }

func TestRequireModernHTTP(t *testing.T) {
	for _, major := range []int{1, 2, 3} {
		for _, method := range []string{"GET", "HEAD", "POST", "PATCH", "OPTIONS"} {
			t.Run(fmt.Sprintf("%d/%s", major, method), func(t *testing.T) {
				r := httptest.NewRequest(method, "https://bbs.example/", nil)
				r.ProtoMajor, r.ContentLength, r.Body = major, 65536, unreadProtocolBody{t}
				w := httptest.NewRecorder()
				w.Header().Set("Content-Encoding", "gzip")
				w.Header().Set("ETag", `"old"`)
				if accepted := RequireModernHTTP(w, r); accepted != (major != 1) {
					t.Fatal("wrong admission", accepted)
				}
				if major == 1 && (w.Code != 505 || w.Body.Len() != 0 || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Length") != "0" || w.Header().Get("ETag") != "" || w.Header().Get("Content-Encoding") != "") {
					t.Fatal("unsafe protocol rejection", w.Code, w.Header(), w.Body.String())
				}
				if major != 1 && w.Header().Get("ETag") != `"old"` {
					t.Fatal("accepted response changed")
				}
			})
		}
	}
}

func TestLegacyClientPath(t *testing.T) {
	for _, path := range []string{"/bbsmenu.html", "/bbsmenu.json", "/test/bbs.cgi", "/oimo/subject.txt", "/oimo/SETTING.TXT", "/oimo/head.txt", "/oimo/dat/123.dat"} {
		if !LegacyClientPath(path) {
			t.Fatal("legacy path denied", path)
		}
	}
	for _, path := range []string{"/", "/web/post", "/search", "/bbsmenu.json/", "/x/y/subject.txt", "/oimo/dat/123.dat/more", "/oimo/dat/123.datx", "/oimo/setting.txt", "/test/bbs.cgi/more"} {
		if LegacyClientPath(path) {
			t.Fatal("Web path exempted", path)
		}
	}
}
