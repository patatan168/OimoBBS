// 任意の要求ターゲットで検査がpanicせず、本文を消費しない境界を検証する。
package waf

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func FuzzInspect(f *testing.F) {
	for _, target := range []string{"/", "/news/subject.txt", "/search?q=日本語", "/x/%252e%252e/", "/x?x=%3Cscript%3E"} {
		f.Add(target, "Mozilla/5.0")
	}
	f.Fuzz(func(t *testing.T, target, agent string) {
		parsed, err := url.ParseRequestURI(target)
		if err != nil {
			return
		}
		request := &http.Request{Method: http.MethodGet, URL: parsed, Header: http.Header{"User-Agent": {agent}}, Body: io.NopCloser(strings.NewReader("unchanged"))}
		_ = Inspect(request)
		body, err := io.ReadAll(request.Body)
		if err != nil || string(body) != "unchanged" {
			t.Fatal("body changed", err)
		}
	})
}
